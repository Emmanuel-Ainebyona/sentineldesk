"""Demo seed data (fictional; local development only)."""
from datetime import date, timedelta

from . import ROOT, due_for, severity_for
from .core import connect, migrate, seed_users

USERS = [("admin@demo.test", "Ada Admin", "admin"), ("analyst@demo.test", "Sam Analyst", "analyst"),
         ("analyst2@demo.test", "Priya Responder", "analyst"), ("auditor@demo.test", "Olu Auditor", "auditor")]
ASSETS = [("web-prod-01", "server", "critical", "Platform"), ("db-prod-01", "server", "critical", "Data"), ("vpn-gateway", "network", "high", "IT Ops"),
          ("hr-portal", "application", "high", "HR"), ("laptop-fleet", "workstation", "medium", "IT Ops"), ("s3-backups", "cloud", "high", "Data"),
          ("intranet-wiki", "application", "low", "IT Ops"), ("build-runner-02", "server", "medium", "Engineering")]
VULNS = [("CVE-2024-3094", "XZ Utils backdoor in build image", 10.0, "open", 0, 1, 3), ("CVE-2023-4863", "libwebp heap overflow", 8.8, "in_progress", 3, 1, 12),
         ("CVE-2024-6387", "OpenSSH regreSSHion race condition", 8.1, "open", 0, 2, 40), ("CVE-2023-44487", "HTTP/2 rapid reset DoS", 7.5, "mitigated", 0, 1, 20),
         ("CVE-2022-22965", "Spring4Shell RCE in HR portal", 9.8, "open", 3, 2, 10), ("CVE-2023-38545", "curl SOCKS5 heap overflow", 7.5, "open", 7, 1, 5),
         (None, "S3 bucket allows public listing", 5.3, "in_progress", 5, 2, 15), (None, "Weak TLS ciphers on VPN", 4.3, "open", 2, 1, 30),
         ("CVE-2021-44228", "Log4Shell in legacy reporting jar", 10.0, "closed", 3, 2, 60), (None, "Missing disk encryption on laptops", 5.5, "accepted", 4, None, 45),
         ("CVE-2023-3519", "Citrix ADC unauthenticated RCE", 9.8, "open", 2, 2, 2), (None, "Verbose server banner", 2.1, "open", 6, None, 20)]
INCIDENTS = [("Phishing campaign targeting finance", "Several staff reported credential-harvesting emails.", "high", 3, "triaged"),
             ("Suspicious outbound traffic from build runner", "Large transfers to unknown IP after midnight.", "critical", 7, "contained"),
             ("Lost company laptop", "Unencrypted laptop reported lost at airport.", "medium", 4, "resolved"),
             ("Brute-force attempts on VPN", "Thousands of failed logins from one ASN.", "medium", 2, "closed"),
             ("Malware alert on HR portal host", "EDR flagged webshell-like file.", "critical", 3, "new")]
PATH = {"new": [], "triaged": ["triaged"], "contained": ["triaged", "contained"], "resolved": ["triaged", "contained", "resolved"],
        "closed": ["triaged", "contained", "resolved", "closed"]}


def seed(db_path):
    migrate(db_path, ROOT / "migrations")
    c = connect(db_path)
    c.execute("BEGIN")
    if not seed_users(c, USERS):
        c.execute("ROLLBACK")
        return False
    uid = {r[1]: r[0] for r in c.execute("SELECT id,email FROM users")}
    for a in ASSETS:
        c.execute("INSERT INTO assets(name,type,criticality,owner) VALUES(?,?,?,?)", a)
    aid = [r[0] for r in c.execute("SELECT id FROM assets ORDER BY id")]
    for cve, title, cvss, status, ai, who, age in VULNS:
        sev = severity_for(cvss)
        created = date.today() - timedelta(days=age)
        c.execute("INSERT INTO vulnerabilities(cve,title,cvss,severity,status,asset_id,assignee_id,due_date,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                  (cve, title, cvss, sev, status, aid[ai], uid["analyst@demo.test"] if who == 1 else uid["analyst2@demo.test"] if who == 2 else None,
                   due_for(sev, created), created.isoformat() + " 09:00:00"))
    for title, desc, sev, ai, status in INCIDENTS:
        n = c.execute("INSERT INTO incidents(title,description,severity,status,reporter_id,assignee_id,asset_id) VALUES(?,?,?,?,?,?,?)",
                      (title, desc, sev, status, uid["analyst@demo.test"], uid["analyst2@demo.test"], aid[ai])).lastrowid
        prev = "new"
        for s in PATH[status]:
            c.execute("INSERT INTO incident_events(incident_id,user_id,from_status,to_status,note) VALUES(?,?,?,?,?)", (n, uid["analyst2@demo.test"], prev, s, "Demo workflow step"))
            prev = s
    c.execute("COMMIT")
    c.close()
    return True
