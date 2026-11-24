//! Alerts the services raise themselves. A deployment forwards every log
//! entry with an `alert` field, and alerts when the heartbeat stops; what is
//! worth alerting on is decided here, in the code, and tested with it.
//!
//! Needs an `alerts` table in the service's database (see its migrations).

use sqlx::PgPool;

/// Opens alert `key` with `message`, or resolves it when `message` is `None`.
/// Logs only when that changes, so a condition checked every tick alerts once
/// and resolves once. Failures are logged, not returned: alerting must never
/// stop the work it reports on.
pub async fn set(db: &PgPool, key: &str, message: Option<String>) {
    if let Err(err) = try_set(db, key, message).await {
        tracing::warn!(alert_key = key, "update alert: {err}");
    }
}

async fn try_set(db: &PgPool, key: &str, message: Option<String>) -> Result<(), sqlx::Error> {
    match message {
        Some(message) => {
            let opened = sqlx::query(
                "INSERT INTO alerts (key, message) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING",
            )
            .bind(key)
            .bind(&message)
            .execute(db)
            .await?
            .rows_affected()
                == 1;
            if opened {
                tracing::error!(alert = "open", alert_key = key, "{message}");
            }
        }
        None => {
            let resolved = sqlx::query("DELETE FROM alerts WHERE key = $1")
                .bind(key)
                .execute(db)
                .await?
                .rows_affected()
                == 1;
            if resolved {
                tracing::info!(alert = "resolved", alert_key = key, "resolved: {key}");
            }
        }
    }
    Ok(())
}

/// Logged after every successful tick. Deployments alert when it stops.
pub fn heartbeat() {
    tracing::info!(heartbeat = true, "tick done");
}
