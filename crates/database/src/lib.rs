use std::{marker::PhantomData, path::Path, time::Duration};

use security_monitor_core::{
    Advisory, AiProvider, AiRun, Asset, AuditEvent, Component, ComponentInstance, Deployment,
    Finding, FindingEvidence, NotificationChannel, Project, Remediation, ScanRun, Service,
};
use serde::{Serialize, de::DeserializeOwned};
use sqlx::{
    Row, SqlitePool,
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use thiserror::Error;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
const CREDENTIAL_REF_PREFIX: &str = "secmon-keyring:v1:";

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Opens a file-backed database and applies all forward migrations before returning.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        Self::from_pool(pool).await
    }

    /// Creates a single-connection in-memory database for deterministic tests and ephemeral use.
    pub async fn in_memory() -> Result<Self, DatabaseError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        Self::from_pool(pool).await
    }

    async fn from_pool(pool: SqlitePool) -> Result<Self, DatabaseError> {
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    pub fn repository<T: Entity>(&self) -> Repository<T> {
        Repository {
            pool: self.pool.clone(),
            marker: PhantomData,
        }
    }

    pub async fn schema_version(&self) -> Result<i64, DatabaseError> {
        Ok(
            sqlx::query_scalar("SELECT schema_version FROM app_metadata WHERE singleton = 1")
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

pub struct Repository<T> {
    pool: SqlitePool,
    marker: PhantomData<fn() -> T>,
}

impl<T: Entity> Repository<T> {
    pub async fn create(&self, entity: &T) -> Result<(), DatabaseError> {
        let json = serde_json::to_string(entity)?;
        validate_record(T::TABLE, &json)?;
        let columns = T::COLUMNS
            .iter()
            .map(|(column, _)| quote_identifier(column))
            .collect::<Vec<_>>();
        let values = T::COLUMNS
            .iter()
            .map(|(_, path)| format!("json_extract(?1, '{path}')"))
            .collect::<Vec<_>>();
        let sql = format!(
            "INSERT INTO {} ({}, record_json) SELECT {}, ?1",
            quote_identifier(T::TABLE),
            columns.join(", "),
            values.join(", ")
        );
        sqlx::query(&sql).bind(json).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<Option<T>, DatabaseError> {
        let sql = format!(
            "SELECT record_json FROM {} WHERE {} = ?1",
            quote_identifier(T::TABLE),
            quote_identifier(T::KEY_COLUMN)
        );
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| decode_record(row.try_get::<String, _>(0)?))
            .transpose()
    }

    pub async fn list(&self) -> Result<Vec<T>, DatabaseError> {
        let sql = format!(
            "SELECT record_json FROM {} ORDER BY {}",
            quote_identifier(T::TABLE),
            quote_identifier(T::KEY_COLUMN)
        );
        let rows = sqlx::query(&sql).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| decode_record(row.try_get::<String, _>(0)?))
            .collect()
    }

    pub async fn update(&self, entity: &T) -> Result<bool, DatabaseError> {
        let json = serde_json::to_string(entity)?;
        validate_record(T::TABLE, &json)?;
        let assignments = T::COLUMNS
            .iter()
            .map(|(column, path)| {
                format!("{} = json_extract(?1, '{path}')", quote_identifier(column))
            })
            .chain(std::iter::once("record_json = ?1".to_owned()))
            .collect::<Vec<_>>();
        let sql = format!(
            "UPDATE {} SET {} WHERE {} = ?2",
            quote_identifier(T::TABLE),
            assignments.join(", "),
            quote_identifier(T::KEY_COLUMN)
        );
        let result = sqlx::query(&sql)
            .bind(json)
            .bind(T::key(entity))
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete(&self, id: &str) -> Result<bool, DatabaseError> {
        let sql = format!(
            "DELETE FROM {} WHERE {} = ?1",
            quote_identifier(T::TABLE),
            quote_identifier(T::KEY_COLUMN)
        );
        let result = sqlx::query(&sql).bind(id).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("database operation failed")]
    Sql(#[source] sqlx::Error),
    #[error("database migration failed")]
    Migration(#[source] sqlx::migrate::MigrateError),
    #[error("database record serialization failed")]
    Serialization(#[source] serde_json::Error),
    #[error("database record contains a credential-bearing URL")]
    CredentialInUrl,
    #[error("database record contains an invalid credential reference")]
    InvalidCredentialReference,
}

impl From<sqlx::Error> for DatabaseError {
    fn from(error: sqlx::Error) -> Self {
        Self::Sql(error)
    }
}

impl From<sqlx::migrate::MigrateError> for DatabaseError {
    fn from(error: sqlx::migrate::MigrateError) -> Self {
        Self::Migration(error)
    }
}

impl From<serde_json::Error> for DatabaseError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Defines the fixed SQL mapping for one of the supported domain records.
/// Implementations are sealed so runtime input can never supply identifiers.
pub trait Entity: sealed::Sealed + Serialize + DeserializeOwned + Send + Sync + 'static {
    const TABLE: &'static str;
    const KEY_COLUMN: &'static str;
    const COLUMNS: &'static [(&'static str, &'static str)];

    fn key(&self) -> &str;
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{identifier}\"")
}

fn decode_record<T: DeserializeOwned>(json: String) -> Result<T, DatabaseError> {
    Ok(serde_json::from_str(&json)?)
}

fn validate_record(table: &str, json: &str) -> Result<(), DatabaseError> {
    let record: serde_json::Value = serde_json::from_str(json)?;
    let credential_ref = match table {
        "ai_providers" => record.get("keychain_ref"),
        "notification_channels" => record.get("config_ref"),
        _ => None,
    }
    .and_then(serde_json::Value::as_str);

    if credential_ref.is_some_and(|value| !is_credential_reference(value)) {
        return Err(DatabaseError::InvalidCredentialReference);
    }

    let url = match table {
        "projects" => record.get("git_remote"),
        "ai_providers" => record.get("base_url"),
        _ => None,
    }
    .and_then(serde_json::Value::as_str);

    if let Some(value) = url {
        if let Ok(parsed) = url::Url::parse(value) {
            let has_userinfo = !parsed.username().is_empty() || parsed.password().is_some();
            let has_query = parsed.query().is_some();
            if has_query || parsed.fragment().is_some() || (has_userinfo && table == "ai_providers")
            {
                return Err(DatabaseError::CredentialInUrl);
            }
            if table == "projects"
                && (parsed.password().is_some()
                    || (parsed.username() != "" && parsed.username() != "git"))
            {
                return Err(DatabaseError::CredentialInUrl);
            }
        } else if table == "ai_providers" {
            return Err(DatabaseError::CredentialInUrl);
        }
    }

    Ok(())
}

fn is_credential_reference(value: &str) -> bool {
    let Some(identifier) = value.strip_prefix(CREDENTIAL_REF_PREFIX) else {
        return false;
    };
    let bytes = identifier.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

macro_rules! entity {
    ($type:ty, $key:ident, $table:literal, $key_column:literal, [$(($column:literal, $path:literal)),+ $(,)?]) => {
        impl sealed::Sealed for $type {}

        impl Entity for $type {
            const TABLE: &'static str = $table;
            const KEY_COLUMN: &'static str = $key_column;
            const COLUMNS: &'static [(&'static str, &'static str)] = &[$(($column, $path)),+];

            fn key(&self) -> &str {
                self.$key.as_str()
            }
        }
    };
}

entity!(
    Project,
    id,
    "projects",
    "id",
    [
        ("id", "$.id"),
        ("name", "$.name"),
        ("root_path", "$.root_path"),
        ("git_remote", "$.git_remote"),
        ("reference_branch", "$.reference_branch"),
        ("allowed_ai_providers", "$.allowed_ai_providers"),
        ("last_scan_at", "$.last_scan_at"),
        ("created_at", "$.created_at"),
        ("updated_at", "$.updated_at"),
    ]
);
entity!(
    Asset,
    id,
    "assets",
    "id",
    [
        ("id", "$.id"),
        ("type", "$.asset_type"),
        ("hostname_alias", "$.hostname_alias"),
        ("environment", "$.environment"),
        ("ssh_target_ref", "$.ssh_target_ref"),
        ("host_key_fingerprint", "$.host_key_fingerprint"),
        ("last_seen_at", "$.last_seen_at"),
        ("last_success_at", "$.last_success_at"),
        ("created_at", "$.created_at"),
        ("updated_at", "$.updated_at"),
    ]
);
entity!(
    Service,
    id,
    "services",
    "id",
    [
        ("id", "$.id"),
        ("asset_id", "$.asset_id"),
        ("service_name", "$.service_name"),
        ("runtime_binary", "$.runtime_binary"),
        ("runtime_version", "$.runtime_version"),
        ("internet_facing", "$.internet_facing"),
        ("created_at", "$.created_at"),
        ("updated_at", "$.updated_at"),
    ]
);
entity!(
    Deployment,
    id,
    "deployments",
    "id",
    [
        ("id", "$.id"),
        ("service_id", "$.service_id"),
        ("commit_sha", "$.commit_sha"),
        ("image_digest", "$.image_digest"),
        ("release_id", "$.release_id"),
        ("id_source", "$.id_source"),
        ("observed_at", "$.observed_at"),
    ]
);
entity!(
    Component,
    id,
    "components",
    "id",
    [
        ("id", "$.id"),
        ("purl", "$.purl"),
        ("ecosystem", "$.ecosystem"),
        ("name", "$.name"),
        ("version", "$.version"),
        ("source_type", "$.source_type"),
        ("created_at", "$.created_at"),
    ]
);
entity!(
    ComponentInstance,
    id,
    "component_instances",
    "id",
    [
        ("id", "$.id"),
        ("component_id", "$.component_id"),
        ("project_id", "$.project_id"),
        ("asset_id", "$.asset_id"),
        ("service_id", "$.service_id"),
        ("deployment_id", "$.deployment_id"),
        ("evidence", "$.evidence"),
        ("created_at", "$.created_at"),
    ]
);
entity!(
    Advisory,
    canonical_id,
    "advisories",
    "canonical_id",
    [
        ("canonical_id", "$.canonical_id"),
        ("title", "$.title"),
        ("summary", "$.summary"),
        ("summary_model", "$.summary_model"),
        ("description", "$.description"),
        ("source_attributions", "$.source_attributions"),
        ("aliases", "$.aliases"),
        ("affected_ranges", "$.affected_ranges"),
        ("fixed_versions", "$.fixed_versions"),
        ("cvss", "$.cvss"),
        ("severity", "$.severity"),
        ("kev", "$.kev"),
        ("epss", "$.epss"),
        ("epss_date", "$.epss_date"),
        ("source_urls", "$.source_urls"),
        ("source_updated_at", "$.source_updated_at"),
        ("created_at", "$.created_at"),
        ("updated_at", "$.updated_at"),
    ]
);
entity!(
    Finding,
    id,
    "findings",
    "id",
    [
        ("id", "$.id"),
        ("advisory_id", "$.advisory_id"),
        ("component_instance_id", "$.component_instance_id"),
        ("status", "$.status"),
        ("severity", "$.severity"),
        ("priority_score", "$.priority_score"),
        ("priority_reasons", "$.priority_reasons"),
        ("fingerprint", "$.fingerprint"),
        ("repo_status", "$.repo_status"),
        ("production_status", "$.production_status"),
        ("risk_expires_at", "$.risk_expires_at"),
        ("fix_version", "$.fix_version"),
        ("created_at", "$.created_at"),
        ("updated_at", "$.updated_at"),
    ]
);
entity!(
    FindingEvidence,
    id,
    "finding_evidence",
    "id",
    [
        ("id", "$.id"),
        ("finding_id", "$.finding_id"),
        ("evidence_type", "$.evidence_type"),
        ("file_path_redacted", "$.file_path_redacted"),
        ("reference", "$.reference"),
        ("confidence", "$.confidence"),
        ("created_at", "$.created_at"),
    ]
);
entity!(
    ScanRun,
    id,
    "scan_runs",
    "id",
    [
        ("id", "$.id"),
        ("scope", "$.scope"),
        ("scanner", "$.scanner"),
        ("scanner_version", "$.scanner_version"),
        ("started_at", "$.started_at"),
        ("finished_at", "$.finished_at"),
        ("outcome", "$.outcome"),
        ("error", "$.error"),
    ]
);
entity!(
    Remediation,
    id,
    "remediations",
    "id",
    [
        ("id", "$.id"),
        ("finding_id", "$.finding_id"),
        ("worktree_path", "$.worktree_path"),
        ("branch", "$.branch"),
        ("diff_hash", "$.diff_hash"),
        ("tests", "$.tests"),
        ("approval_state", "$.approval_state"),
        ("created_at", "$.created_at"),
        ("updated_at", "$.updated_at"),
    ]
);
entity!(
    AiProvider,
    id,
    "ai_providers",
    "id",
    [
        ("id", "$.id"),
        ("kind", "$.kind"),
        ("display_name", "$.display_name"),
        ("base_url", "$.base_url"),
        ("model", "$.model"),
        ("capabilities", "$.capabilities"),
        ("price_in", "$.price_in"),
        ("price_out", "$.price_out"),
        ("data_region", "$.data_region"),
        ("keychain_ref", "$.keychain_ref"),
        ("created_at", "$.created_at"),
        ("updated_at", "$.updated_at"),
    ]
);
entity!(
    AiRun,
    id,
    "ai_runs",
    "id",
    [
        ("id", "$.id"),
        ("provider_id", "$.provider_id"),
        ("tier", "$.tier"),
        ("finding_id", "$.finding_id"),
        ("tokens_in", "$.tokens_in"),
        ("tokens_out", "$.tokens_out"),
        ("cost", "$.cost"),
        ("files_sent", "$.files_sent"),
        ("started_at", "$.started_at"),
        ("outcome", "$.outcome"),
    ]
);
entity!(
    NotificationChannel,
    id,
    "notification_channels",
    "id",
    [
        ("id", "$.id"),
        ("kind", "$.kind"),
        ("config_ref", "$.config_ref"),
        ("min_priority", "$.min_priority"),
        ("enabled", "$.enabled"),
        ("created_at", "$.created_at"),
        ("updated_at", "$.updated_at"),
    ]
);
entity!(
    AuditEvent,
    id,
    "audit_events",
    "id",
    [
        ("id", "$.id"),
        ("timestamp", "$.timestamp"),
        ("actor", "$.actor"),
        ("action", "$.action"),
        ("scope_json", "$.scope"),
        ("result", "$.result"),
    ]
);

#[cfg(test)]
mod tests;
