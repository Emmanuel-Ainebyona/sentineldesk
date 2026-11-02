from datetime import date, timedelta

from tests.base import ADMIN, Base

ANALYST, AUDITOR = "analyst@demo.test", "auditor@demo.test"


class AssetVulnTests(Base):
    def asset(self, name="test-host"):
        return self.data(self.post("/api/assets", ANALYST, json={"name": name, "type": "server", "criticality": "high"}), 201)["id"]

    def test_crud_and_validation(self):
        aid = self.asset()
        self.assertEqual(self.post("/api/assets", ANALYST, json={"name": "test-host", "type": "server", "criticality": "high"}).status_code, 409)
        self.assertEqual(self.post("/api/assets", ANALYST, json={"name": "x", "type": "toaster", "criticality": "high"}).status_code, 422)
        self.assertEqual(self.data(self.put(f"/api/assets/{aid}", ANALYST, json={"owner": "SecOps"}), 200)["owner"], "SecOps")
        self.assertEqual(self.get("/api/assets/99999", ANALYST).status_code, 404)

    def test_rbac(self):
        body = {"name": "nope", "type": "server", "criticality": "low"}
        self.assertEqual(self.post("/api/assets", AUDITOR, json=body).status_code, 403)
        self.assertEqual(self.post("/api/assets", json=body).status_code, 401)
        aid = self.asset()
        self.assertEqual(self.delete(f"/api/assets/{aid}", ANALYST).status_code, 403)
        self.assertEqual(self.get("/api/assets", AUDITOR).status_code, 200)
        self.assertEqual(self.delete(f"/api/assets/{aid}", ADMIN).status_code, 200)

    def test_severity_and_sla_computed_server_side(self):
        aid = self.asset()
        v = self.data(self.post("/api/vulnerabilities", ANALYST, json={"title": "t", "cvss": 9.8, "asset_id": aid, "severity": "info", "due_date": "2000-01-01"}), 201)
        self.assertEqual(v["severity"], "critical")
        self.assertEqual(v["due_date"], (date.today() + timedelta(days=7)).isoformat())
        self.assertEqual(v["status"], "open")
        v2 = self.data(self.put(f"/api/vulnerabilities/{v['id']}", ANALYST, json={"cvss": 5.0}), 200)
        self.assertEqual((v2["severity"], v2["due_date"]), ("medium", (date.today() + timedelta(days=90)).isoformat()))

    def test_vulnerability_validation(self):
        aid = self.asset()
        ok = {"title": "t", "cvss": 5, "asset_id": aid}
        for bad in ({**ok, "cvss": 11}, {**ok, "cvss": "abc"}, {**ok, "cve": "CVE-12"}, {**ok, "asset_id": 9999}, {**ok, "title": ""}, {**ok, "status": "weird"}):
            self.assertEqual(self.post("/api/vulnerabilities", ANALYST, json=bad).status_code, 422, bad)
        self.assertEqual(self.post("/api/vulnerabilities", ANALYST, json={**ok, "cve": "CVE-2024-12345"}).status_code, 201)
        self.assertEqual(self.post("/api/vulnerabilities", ANALYST, json={**ok, "cve": "CVE-2024-12345"}).status_code, 409)

    def test_asset_with_vulnerabilities_cannot_be_deleted(self):
        aid = self.asset()
        self.post("/api/vulnerabilities", ANALYST, json={"title": "t", "cvss": 5, "asset_id": aid})
        self.assertEqual(self.delete(f"/api/assets/{aid}", ADMIN).status_code, 409)

    def test_search_filter_sort_overdue(self):
        r = self.get("/api/vulnerabilities?severity=critical&status=open", ANALYST).get_json()
        self.assertTrue(r["data"] and all(v["severity"] == "critical" for v in r["data"]))
        self.assertTrue(any(v["overdue"] for v in r["data"]))  # seeded Spring4Shell/XZ items are past SLA
        hits = self.data(self.get("/api/vulnerabilities?q=log4shell", ANALYST), 200)
        self.assertEqual(len(hits), 1)
        asc = [v["cvss"] for v in self.data(self.get("/api/vulnerabilities?sort=cvss&order=asc&per_page=100", ANALYST), 200)]
        self.assertEqual(asc, sorted(asc))


class IncidentTests(Base):
    def new(self, **kw):
        return self.data(self.post("/api/incidents", ANALYST, json={"title": "Odd logins", "severity": "high", **kw}), 201)

    def test_create_sets_reporter_and_status_ignores_client_values(self):
        i = self.new(status="closed", reporter_id=999)
        self.assertEqual(i["status"], "new")
        self.assertNotEqual(i["reporter_id"], 999)
        self.assertEqual(self.put(f"/api/incidents/{i['id']}", ANALYST, json={"status": "closed"}).get_json()["data"]["status"], "new")

    def test_workflow_and_events(self):
        i = self.new()
        for s in ("triaged", "contained", "resolved"):
            self.assertEqual(self.data(self.post(f"/api/incidents/{i['id']}/transition", ANALYST, json={"status": s, "note": "ok"}), 200)["status"], s)
        inc = self.data(self.get(f"/api/incidents/{i['id']}", AUDITOR), 200)
        self.assertIsNotNone(inc["resolved_at"])
        ev = self.data(self.get(f"/api/incidents/{i['id']}/events", AUDITOR), 200)
        self.assertEqual([e["to_status"] for e in ev], ["triaged", "contained", "resolved"])
        self.assertEqual(self.data(self.post(f"/api/incidents/{i['id']}/transition", ANALYST, json={"status": "triaged"}), 200)["resolved_at"], None)

    def test_invalid_transitions_rejected(self):
        i = self.new()
        for s in ("resolved", "closed", "new"):
            self.assertEqual(self.post(f"/api/incidents/{i['id']}/transition", ANALYST, json={"status": s}).status_code, 409)
        self.assertEqual(self.post(f"/api/incidents/{i['id']}/transition", ANALYST, json={"status": "bogus"}).status_code, 422)
        self.assertEqual(self.post("/api/incidents/9999/transition", ANALYST, json={"status": "triaged"}).status_code, 404)

    def test_auditor_cannot_change_incidents(self):
        i = self.new()
        self.assertEqual(self.post(f"/api/incidents/{i['id']}/transition", AUDITOR, json={"status": "triaged"}).status_code, 403)
        self.assertEqual(self.post("/api/incidents", AUDITOR, json={"title": "x", "severity": "low"}).status_code, 403)

    def test_audit_trail_for_changes(self):
        i = self.new()
        self.post(f"/api/incidents/{i['id']}/transition", ANALYST, json={"status": "triaged"})
        rows = self.data(self.get("/api/audit?entity=incidents&per_page=100", AUDITOR), 200)
        self.assertEqual({r["action"] for r in rows}, {"create", "transition"})
        self.assertEqual(self.get("/api/audit", ANALYST).status_code, 403)


class StatsTests(Base):
    def test_stats_match_database(self):
        s = self.data(self.get("/api/stats", AUDITOR), 200)
        cards = {c["label"]: c["value"] for c in s["cards"]}
        self.assertEqual(cards["Assets tracked"], self.get("/api/assets", AUDITOR).get_json()["meta"]["total"])
        self.assertEqual(cards["Open vulnerabilities"], sum(i["value"] for i in s["breakdowns"][0]["items"]))
        self.assertEqual(cards["Open incidents"], 3)  # new, triaged, contained in seed
        self.assertEqual(self.get("/api/stats").status_code, 401)
