CREATE TABLE assets(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL CHECK (type IN ('server','workstation','application','network','cloud')),
  criticality TEXT NOT NULL CHECK (criticality IN ('low','medium','high','critical')),
  owner TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE vulnerabilities(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve TEXT,
  title TEXT NOT NULL,
  description TEXT,
  cvss REAL NOT NULL CHECK (cvss BETWEEN 0 AND 10),
  severity TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','mitigated','accepted','closed')),
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
  assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  due_date TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT
);
CREATE UNIQUE INDEX uq_vuln_cve_asset ON vulnerabilities(cve, asset_id) WHERE cve IS NOT NULL;
CREATE INDEX idx_vuln_status ON vulnerabilities(status, severity);
CREATE INDEX idx_vuln_asset ON vulnerabilities(asset_id);
CREATE TABLE incidents(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','triaged','contained','resolved','closed')),
  reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT,
  resolved_at TEXT
);
CREATE INDEX idx_inc_status ON incidents(status);
CREATE TABLE incident_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  from_status TEXT, to_status TEXT NOT NULL, note TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_events_incident ON incident_events(incident_id);
