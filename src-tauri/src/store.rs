use rusqlite::{Connection, params};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::model::{
    ActivityDraft, ActivityEvent, DEFAULT_BYPASS_HOSTS, FindingView, ServiceEvent, ServiceSighting,
};
use crate::pii::{PiiType, Rules, TypeRule};
use crate::platform::SavedProxy;

const SESSION_KEY: &str = "proxy_session";
const BYPASS_SEED_KEY: &str = "default_bypass_seed_v1";

pub fn open(path: &std::path::Path) -> Result<Connection, String> {
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    connection
        .execute_batch(
            "
            CREATE TABLE IF NOT EXISTS rules (
                pii_type TEXT PRIMARY KEY,
                mask INTEGER NOT NULL,
                alert INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bypass_hosts (
                host TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                process_name TEXT NOT NULL,
                method TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                action TEXT NOT NULL,
                alert INTEGER NOT NULL,
                seen INTEGER NOT NULL,
                detail TEXT,
                findings_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS services (
                host TEXT NOT NULL,
                process_name TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                connect_count INTEGER NOT NULL DEFAULT 0,
                scanned_count INTEGER NOT NULL DEFAULT 0,
                pii_count INTEGER NOT NULL DEFAULT 0,
                last_mode TEXT NOT NULL,
                PRIMARY KEY (host, process_name)
            );
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            ",
        )
        .map_err(|error| error.to_string())?;
    seed_rules(&connection)?;
    seed_default_bypass(&connection)?;
    Ok(connection)
}

fn seed_default_bypass(connection: &Connection) -> Result<(), String> {
    let seeded: Option<String> = connection
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![BYPASS_SEED_KEY],
            |row| row.get(0),
        )
        .ok();
    if seeded.is_some() {
        return Ok(());
    }
    for host in DEFAULT_BYPASS_HOSTS {
        connection
            .execute(
                "INSERT OR IGNORE INTO bypass_hosts (host) VALUES (?1)",
                params![*host],
            )
            .map_err(|error| error.to_string())?;
    }
    connection
        .execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![BYPASS_SEED_KEY, "1"],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn seed_rules(connection: &Connection) -> Result<(), String> {
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM rules", [], |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if count > 0 {
        return Ok(());
    }
    let defaults = Rules::default();
    for kind in PiiType::ALL {
        let rule = defaults.rule(kind);
        connection
            .execute(
                "INSERT INTO rules (pii_type, mask, alert) VALUES (?1, ?2, ?3)",
                params![kind.as_str(), rule.mask as i64, rule.alert as i64],
            )
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub fn load_rules(connection: &Connection) -> Result<Rules, String> {
    let mut rules = Rules::default();
    let mut statement = connection
        .prepare("SELECT pii_type, mask, alert FROM rules")
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    for row in rows {
        let (name, mask, alert) = row.map_err(|error| error.to_string())?;
        if let Some(kind) = PiiType::parse(&name) {
            rules.set(
                kind,
                TypeRule {
                    mask: mask != 0,
                    alert: alert != 0,
                },
            );
        }
    }
    Ok(rules)
}

pub fn save_rule(connection: &Connection, kind: PiiType, rule: TypeRule) -> Result<(), String> {
    connection
        .execute(
            "INSERT INTO rules (pii_type, mask, alert) VALUES (?1, ?2, ?3)
             ON CONFLICT(pii_type) DO UPDATE SET mask = excluded.mask, alert = excluded.alert",
            params![kind.as_str(), rule.mask as i64, rule.alert as i64],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub fn load_bypass(connection: &Connection) -> Result<Vec<String>, String> {
    let mut statement = connection
        .prepare("SELECT host FROM bypass_hosts ORDER BY host")
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

pub fn add_bypass(connection: &Connection, host: &str) -> Result<(), String> {
    connection
        .execute(
            "INSERT OR IGNORE INTO bypass_hosts (host) VALUES (?1)",
            params![host],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub fn remove_bypass(connection: &Connection, host: &str) -> Result<(), String> {
    connection
        .execute("DELETE FROM bypass_hosts WHERE host = ?1", params![host])
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub fn insert_event(
    connection: &Connection,
    draft: &ActivityDraft,
) -> Result<ActivityEvent, String> {
    let event = ActivityEvent {
        id: Uuid::new_v4().to_string(),
        timestamp: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string()),
        process_name: draft.process_name.clone(),
        method: draft.method.clone(),
        host: draft.host.clone(),
        path: draft.path.clone(),
        action: draft.action.clone(),
        alert: draft.alert,
        seen: false,
        detail: draft.detail.clone(),
        findings: draft.findings.clone(),
    };
    let findings_json =
        serde_json::to_string(&event.findings).map_err(|error| error.to_string())?;
    connection
        .execute(
            "INSERT INTO events (
                id, timestamp, process_name, method, host, path, action, alert, seen, detail, findings_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10)",
            params![
                event.id,
                event.timestamp,
                event.process_name,
                event.method,
                event.host,
                event.path,
                event.action,
                event.alert as i64,
                event.detail,
                findings_json,
            ],
        )
        .map_err(|error| error.to_string())?;
    let pii = !draft.findings.is_empty()
        && matches!(draft.action.as_str(), "masked" | "allowed");
    let scanned = matches!(
        draft.action.as_str(),
        "masked" | "allowed" | "clean" | "skipped"
    );
    touch_service(
        connection,
        &ServiceSighting {
            process_name: draft.process_name.clone(),
            host: draft.host.clone(),
            mode: "inspected".to_string(),
            scanned,
            pii,
        },
    )?;
    Ok(event)
}

pub fn touch_service(
    connection: &Connection,
    sighting: &ServiceSighting,
) -> Result<ServiceEvent, String> {
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string());
    let connect_inc = if sighting.scanned { 0 } else { 1 };
    let scanned_inc = i64::from(sighting.scanned);
    let pii_inc = i64::from(sighting.pii);
    connection
        .execute(
            "INSERT INTO services (
                host, process_name, first_seen, last_seen, connect_count, scanned_count, pii_count, last_mode
             ) VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(host, process_name) DO UPDATE SET
                last_seen = excluded.last_seen,
                connect_count = services.connect_count + excluded.connect_count,
                scanned_count = services.scanned_count + excluded.scanned_count,
                pii_count = services.pii_count + excluded.pii_count,
                last_mode = excluded.last_mode",
            params![
                sighting.host,
                sighting.process_name,
                now,
                connect_inc,
                scanned_inc,
                pii_inc,
                sighting.mode,
            ],
        )
        .map_err(|error| error.to_string())?;
    connection
        .query_row(
            "SELECT host, process_name, first_seen, last_seen, connect_count, scanned_count, pii_count, last_mode
             FROM services WHERE host = ?1 AND process_name = ?2",
            params![sighting.host, sighting.process_name],
            |row| {
                Ok(ServiceEvent {
                    host: row.get(0)?,
                    process_name: row.get(1)?,
                    first_seen: row.get(2)?,
                    last_seen: row.get(3)?,
                    connect_count: row.get(4)?,
                    scanned_count: row.get(5)?,
                    pii_count: row.get(6)?,
                    last_mode: row.get(7)?,
                })
            },
        )
        .map_err(|error| error.to_string())
}

pub fn list_services(connection: &Connection) -> Result<Vec<ServiceEvent>, String> {
    let mut statement = connection
        .prepare(
            "SELECT host, process_name, first_seen, last_seen, connect_count, scanned_count, pii_count, last_mode
             FROM services
             ORDER BY
                CASE WHEN pii_count > 0 THEN 0 ELSE 1 END,
                last_seen DESC
             LIMIT 200",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok(ServiceEvent {
                host: row.get(0)?,
                process_name: row.get(1)?,
                first_seen: row.get(2)?,
                last_seen: row.get(3)?,
                connect_count: row.get(4)?,
                scanned_count: row.get(5)?,
                pii_count: row.get(6)?,
                last_mode: row.get(7)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

pub fn list_events(connection: &Connection) -> Result<Vec<ActivityEvent>, String> {
    let mut statement = connection
        .prepare(
            "SELECT id, timestamp, process_name, method, host, path, action, alert, seen, detail, findings_json
             FROM events ORDER BY timestamp DESC LIMIT 200",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            let findings_json: String = row.get(10)?;
            let findings: Vec<FindingView> =
                serde_json::from_str(&findings_json).unwrap_or_default();
            Ok(ActivityEvent {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                process_name: row.get(2)?,
                method: row.get(3)?,
                host: row.get(4)?,
                path: row.get(5)?,
                action: row.get(6)?,
                alert: row.get::<_, i64>(7)? != 0,
                seen: row.get::<_, i64>(8)? != 0,
                detail: row.get(9)?,
                findings,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

pub fn mark_seen(connection: &Connection, id: &str) -> Result<(), String> {
    connection
        .execute("UPDATE events SET seen = 1 WHERE id = ?1", params![id])
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub fn mark_all_seen(connection: &Connection) -> Result<(), String> {
    connection
        .execute("UPDATE events SET seen = 1 WHERE seen = 0", [])
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub fn save_session(connection: &Connection, session: &Option<SavedProxy>) -> Result<(), String> {
    match session {
        Some(session) => {
            let value = serde_json::to_string(session).map_err(|error| error.to_string())?;
            connection
                .execute(
                    "INSERT INTO meta (key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![SESSION_KEY, value],
                )
                .map_err(|error| error.to_string())?;
        }
        None => {
            connection
                .execute("DELETE FROM meta WHERE key = ?1", params![SESSION_KEY])
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

pub fn load_session(connection: &Connection) -> Result<Option<SavedProxy>, String> {
    let mut statement = connection
        .prepare("SELECT value FROM meta WHERE key = ?1")
        .map_err(|error| error.to_string())?;
    let mut rows = statement
        .query(params![SESSION_KEY])
        .map_err(|error| error.to_string())?;
    let Some(row) = rows.next().map_err(|error| error.to_string())? else {
        return Ok(None);
    };
    let value: String = row.get(0).map_err(|error| error.to_string())?;
    let session = serde_json::from_str(&value).map_err(|error| error.to_string())?;
    Ok(Some(session))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DEFAULT_BYPASS_HOSTS;

    #[test]
    fn seeds_default_bypass_and_tracks_scanned_services() {
        let dir = std::env::temp_dir().join(format!("pii-store-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("sniffer.sqlite");
        let connection = open(&path).expect("open");

        let bypass = load_bypass(&connection).expect("bypass");
        for host in DEFAULT_BYPASS_HOSTS {
            assert!(
                bypass.iter().any(|item| item == host),
                "missing default bypass {host}"
            );
        }

        touch_service(
            &connection,
            &ServiceSighting {
                process_name: "curl".into(),
                host: "api.example.com".into(),
                mode: "inspected".into(),
                scanned: false,
                pii: false,
            },
        )
        .expect("connect sighting");
        insert_event(
            &connection,
            &ActivityDraft {
                process_name: "curl".into(),
                method: "POST".into(),
                host: "api.example.com".into(),
                path: "/upload".into(),
                action: "masked".into(),
                alert: true,
                detail: None,
                findings: vec![FindingView {
                    pii_type: "email".into(),
                    field_path: "$.email".into(),
                    action: "masked".into(),
                    token: "[redacted-email]".into(),
                }],
            },
        )
        .expect("event");

        let services = list_services(&connection).expect("services");
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].host, "api.example.com");
        assert!(services[0].scanned_count >= 1);
        assert!(services[0].pii_count >= 1);
        assert!(services[0].connect_count >= 1);

        let _ = std::fs::remove_dir_all(dir);
        let _ = connection;
    }
}
