use rusqlite::{Connection, params};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::model::{ActivityDraft, ActivityEvent, FindingView};
use crate::pii::{PiiType, Rules, TypeRule};
use crate::platform::SavedProxy;

const SESSION_KEY: &str = "proxy_session";

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
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            ",
        )
        .map_err(|error| error.to_string())?;
    seed_rules(&connection)?;
    Ok(connection)
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
    Ok(event)
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
