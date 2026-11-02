"""SentinelDesk: security incident and vulnerability management API."""
from datetime import date, timedelta
from pathlib import Path

from flask import g, jsonify, request

from .core import Resource, audit, db, err, make_app, now, require, tx, validate

ROOT = Path(__file__).resolve().parent.parent
ROLES = ("admin", "analyst", "auditor")
DEFAULT_ROLE = "auditor"  # least privilege: read-only
STAFF = ("admin", "analyst")
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}
TRANSITIONS = {"new": ["triaged"], "triaged": ["contained"], "contained": ["resolved"], "resolved": ["closed", "triaged"], "closed": []}
SEVERITIES = ["info", "low", "medium", "high", "critical"]


def severity_for(cvss):
    """CVSS v3 qualitative rating."""
    return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low" if cvss > 0 else "info"


def due_for(severity, start=None):
    return ((start or date.today()) + timedelta(days=SLA_DAYS[severity])).isoformat()


def create_app(config=None):
    app = make_app(ROOT, roles=ROLES, default_role=DEFAULT_ROLE, audit_roles=("admin", "auditor"), config=config)

    # ----- assets -----
    Resource("assets", "assets", {
        "name": {"required": True, "max": 120},
        "type": {"type": "enum", "choices": ["server", "workstation", "application", "network", "cloud"], "required": True},
        "criticality": {"type": "enum", "choices": ["low", "medium", "high", "critical"], "required": True},
        "owner": {"max": 120}}, write=STAFF, delete=("admin",), search=("t.name", "t.owner"), filters=("type", "criticality"),
        sortable={"name": "t.name", "criticality": "t.criticality", "created_at": "t.id"},
        select="t.*, (SELECT COUNT(*) FROM vulnerabilities v WHERE v.asset_id=t.id AND v.status IN ('open','in_progress')) AS open_vulns").register(app)

    # ----- vulnerabilities -----
    def vuln_create(clean):
        clean["severity"] = severity_for(clean["cvss"])
        clean["status"] = clean.get("status") or "open"
        clean["due_date"] = due_for(clean["severity"])

    def vuln_update(clean, existing):
        if clean.get("status") is None and "status" in clean:
            del clean["status"]
        if "cvss" in clean:
            clean["severity"] = severity_for(clean["cvss"])
            clean["due_date"] = due_for(clean["severity"], date.fromisoformat(existing["created_at"][:10]))
        clean["updated_at"] = now()

    Resource("vulnerabilities", "vulnerabilities", {
        "cve": {"max": 20, "pattern": r"CVE-\d{4}-\d{4,7}", "pattern_msg": "Use the form CVE-YYYY-NNNN"},
        "title": {"required": True, "max": 200}, "description": {"max": 4000},
        "cvss": {"type": "float", "required": True, "min": 0, "max": 10},
        "status": {"type": "enum", "choices": ["open", "in_progress", "mitigated", "accepted", "closed"]},
        "asset_id": {"type": "int", "required": True, "fk": "assets"}, "assignee_id": {"type": "int", "fk": "users"}},
        write=STAFF, delete=("admin",), hook_create=vuln_create, hook_update=vuln_update,
        search=("t.title", "t.cve", "a.name"), filters=("status", "severity", "asset_id"),
        sortable={"cvss": "t.cvss", "due_date": "t.due_date", "title": "t.title", "created_at": "t.id"},
        select="t.*, a.name AS asset_name, u.name AS assignee_name, "
               "CASE WHEN t.status IN ('open','in_progress') AND t.due_date < date('now') THEN 1 ELSE 0 END AS overdue",
        joins="JOIN assets a ON a.id=t.asset_id LEFT JOIN users u ON u.id=t.assignee_id").register(app)

    # ----- incidents -----
    def inc_create(clean):
        clean["reporter_id"], clean["status"] = g.user["id"], "new"

    inc = Resource("incidents", "incidents", {
        "title": {"required": True, "max": 200}, "description": {"max": 4000},
        "severity": {"type": "enum", "choices": ["low", "medium", "high", "critical"], "required": True},
        "asset_id": {"type": "int", "fk": "assets"}, "assignee_id": {"type": "int", "fk": "users"}},
        write=STAFF, delete=("admin",), hook_create=inc_create, hook_update=lambda c, e: c.update(updated_at=now()),
        search=("t.title", "t.description"), filters=("status", "severity"),
        sortable={"created_at": "t.id", "severity": "t.severity", "title": "t.title"},
        select="t.*, a.name AS asset_name, u.name AS assignee_name, r.name AS reporter_name",
        joins="LEFT JOIN assets a ON a.id=t.asset_id LEFT JOIN users u ON u.id=t.assignee_id JOIN users r ON r.id=t.reporter_id")
    inc.register(app)

    @app.post("/api/incidents/<int:iid>/transition")
    @require(*STAFF)
    def transition(iid):
        d = validate({"status": {"type": "enum", "choices": list(TRANSITIONS), "required": True}, "note": {"max": 1000}}, request.get_json(silent=True))
        with tx() as c:
            row = c.execute("SELECT status, resolved_at FROM incidents WHERE id=?", (iid,)).fetchone()
            if not row:
                err(404, "not_found", "Record not found")
            if d["status"] not in TRANSITIONS[row["status"]]:
                err(409, "invalid_transition", f"Cannot move an incident from {row['status']} to {d['status']}")
            resolved = now() if d["status"] == "resolved" else (None if d["status"] in ("triaged", "contained") else row["resolved_at"])
            c.execute("UPDATE incidents SET status=?, updated_at=?, resolved_at=? WHERE id=?", (d["status"], now(), resolved, iid))
            c.execute("INSERT INTO incident_events(incident_id,user_id,from_status,to_status,note) VALUES(?,?,?,?,?)",
                      (iid, g.user["id"], row["status"], d["status"], d.get("note")))
            audit("transition", "incidents", iid, f"{row['status']}->{d['status']}")
        return jsonify(data=inc._one(iid, scoped=False))

    @app.get("/api/incidents/<int:iid>/events")
    @require()
    def events(iid):
        inc._one(iid)
        rows = db().execute("SELECT e.id,e.from_status,e.to_status,e.note,e.created_at,u.name AS user_name FROM incident_events e "
                            "LEFT JOIN users u ON u.id=e.user_id WHERE e.incident_id=? ORDER BY e.id", (iid,)).fetchall()
        return jsonify(data=[dict(r) for r in rows])

    @app.get("/api/stats")
    @require()
    def stats():
        q = lambda sql, *a: db().execute(sql, a).fetchone()[0]
        openv = "status IN ('open','in_progress')"
        sev = {r["severity"]: r["n"] for r in db().execute(f"SELECT severity, COUNT(*) n FROM vulnerabilities WHERE {openv} GROUP BY severity")}
        ist = {r["status"]: r["n"] for r in db().execute("SELECT status, COUNT(*) n FROM incidents GROUP BY status")}
        open_inc = q("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')")
        overdue = q(f"SELECT COUNT(*) FROM vulnerabilities WHERE {openv} AND due_date < date('now')")
        return jsonify(data={
            "cards": [
                {"label": "Open incidents", "value": open_inc, "tone": "red" if open_inc else "green"},
                {"label": "Open vulnerabilities", "value": q(f"SELECT COUNT(*) FROM vulnerabilities WHERE {openv}")},
                {"label": "Critical/high open", "value": sev.get("critical", 0) + sev.get("high", 0), "tone": "red" if sev.get("critical") else ""},
                {"label": "Overdue vs SLA", "value": overdue, "tone": "red" if overdue else "green"},
                {"label": "Assets tracked", "value": q("SELECT COUNT(*) FROM assets")}],
            "breakdowns": [
                {"title": "Open vulnerabilities by severity", "items": [{"label": s, "value": sev.get(s, 0)} for s in reversed(SEVERITIES)]},
                {"title": "Incidents by status", "items": [{"label": s, "value": ist.get(s, 0)} for s in TRANSITIONS]}]})

    return app
