use std::{marker::PhantomData, path::Path, time::Duration};

use security_monitor_core::{
    Advisory, AiDataTransferApproval, AiProvider, AiRun, Asset, AuditEvent, Component,
    ComponentInstance, Deployment, Finding, FindingEvidence, Memory, NewsSignal,
    NotificationChannel, NotificationDeliveryState, ProductionStatus, Project,
    ProjectScanCheckpoint, ProjectServerLink, Remediation, ScanRun, Service,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sqlx::{
    Row, Sqlite, SqlitePool, Transaction,
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

    /// Opens an already initialized database without applying migrations or allowing writes.
    pub async fn open_read_only(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .read_only(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(3)
            .connect_with(options)
            .await?;
        Ok(Self { pool })
    }

    /// Opens an existing database for constrained local MCP memory operations without migrating it.
    pub async fn open_existing_read_write(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(false)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(3)
            .connect_with(options)
            .await?;
        let database = Self { pool };
        if database.schema_version().await? < 9 {
            database.close().await;
            return Err(DatabaseError::MemorySchemaUnavailable);
        }
        Ok(database)
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

    /// Returns non-expired memories ordered with pinned and newer notes first.
    pub async fn search_memories(
        &self,
        query: &str,
        now: chrono::DateTime<chrono::Utc>,
        limit: u32,
    ) -> Result<Vec<Memory>, DatabaseError> {
        let rows = sqlx::query_scalar::<_, String>(
            "SELECT record_json FROM memories \
             WHERE (expires_at IS NULL OR julianday(expires_at) > julianday(?1)) \
               AND (?2 = '' OR instr(lower(content), lower(?2)) > 0) \
             ORDER BY pinned DESC, created_at DESC LIMIT ?3",
        )
        .bind(timestamp(now))
        .bind(query)
        .bind(i64::from(limit.clamp(1, 10_000)))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(decode_record).collect()
    }

    pub async fn delete_expired_memories(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, DatabaseError> {
        let result =
            sqlx::query("DELETE FROM memories WHERE expires_at IS NOT NULL AND julianday(expires_at) <= julianday(?1)")
                .bind(timestamp(now))
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected())
    }

    /// Deletes a note only while it is still authored by the requesting agent.
    pub async fn delete_memory_authored_by(
        &self,
        id: &str,
        author: &str,
    ) -> Result<bool, DatabaseError> {
        let result = sqlx::query("DELETE FROM memories WHERE id = ?1 AND author = ?2")
            .bind(id)
            .bind(author)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete_all_memories(&self) -> Result<u64, DatabaseError> {
        let result = sqlx::query("DELETE FROM memories")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Checks the current AI run ledger and inserts a cost reservation under a SQLite write lock.
    /// The callback is evaluated while other database connections are blocked from reserving.
    pub async fn reserve_ai_run<F>(
        &self,
        run: &AiRun,
        check_budget: F,
    ) -> Result<Result<(), String>, DatabaseError>
    where
        F: FnOnce(&[AiRun]) -> Result<(), String>,
    {
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let records =
            sqlx::query_scalar::<_, String>("SELECT record_json FROM ai_runs ORDER BY id")
                .fetch_all(&mut *transaction)
                .await?;
        let runs = records
            .into_iter()
            .map(decode_record)
            .collect::<Result<Vec<AiRun>, _>>()?;
        if let Err(reason) = check_budget(&runs) {
            transaction.rollback().await?;
            return Ok(Err(reason));
        }

        run.validate()?;
        let json = serde_json::to_string(run)?;
        validate_record(AiRun::TABLE, &json)?;
        let columns = AiRun::COLUMNS
            .iter()
            .map(|(column, _)| quote_identifier(column))
            .collect::<Vec<_>>();
        let values = AiRun::COLUMNS
            .iter()
            .map(|(_, path)| format!("json_extract(?1, '{path}')"))
            .collect::<Vec<_>>();
        let sql = format!(
            "INSERT INTO {} ({}, record_json) SELECT {}, ?1",
            quote_identifier(AiRun::TABLE),
            columns.join(", "),
            values.join(", ")
        );
        sqlx::query(&sql)
            .bind(json)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(Ok(()))
    }

    /// Repoints persisted findings to an already stored canonical advisory and removes the old
    /// identifier within one transaction.
    pub async fn rekey_advisory_findings(
        &self,
        old_id: &str,
        canonical_id: &str,
    ) -> Result<(), DatabaseError> {
        if old_id == canonical_id {
            return Ok(());
        }
        let mut transaction = self.pool.begin().await?;
        let target_exists =
            sqlx::query_scalar::<_, i64>("SELECT 1 FROM advisories WHERE canonical_id = ?1")
                .bind(canonical_id)
                .fetch_optional(&mut *transaction)
                .await?
                .is_some();
        if !target_exists {
            return Err(DatabaseError::MissingAdvisoryTarget);
        }
        sqlx::query(
            "UPDATE findings SET advisory_id = ?1, \
             record_json = json_set(record_json, '$.advisory_id', ?1) \
             WHERE advisory_id = ?2",
        )
        .bind(canonical_id)
        .bind(old_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM advisories WHERE canonical_id = ?1")
            .bind(old_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

pub struct Repository<T> {
    pool: SqlitePool,
    marker: PhantomData<fn() -> T>,
}

pub struct RepositoryPage<T> {
    pub items: Vec<T>,
    pub total_count: u64,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUnpairRecord {
    pub ssh_target_ref: Option<String>,
    pub linked_project_ids: Vec<String>,
    pub history_deleted: bool,
}

#[derive(Default)]
pub struct FindingPageFilter<'a> {
    pub status: Option<&'a str>,
    pub severity: Option<&'a str>,
    pub project_id: Option<&'a str>,
    pub search: &'a str,
}

impl<T: Entity> Repository<T> {
    pub async fn create(&self, entity: &T) -> Result<(), DatabaseError> {
        entity.validate()?;
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

    pub async fn list_page(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<RepositoryPage<T>, DatabaseError> {
        let limit = limit.clamp(1, 250);
        let count_sql = format!("SELECT COUNT(*) FROM {}", quote_identifier(T::TABLE));
        let total_count = sqlx::query_scalar::<_, i64>(&count_sql)
            .fetch_one(&self.pool)
            .await? as u64;
        let sql = format!(
            "SELECT record_json FROM {} ORDER BY {} LIMIT ?1 OFFSET ?2",
            quote_identifier(T::TABLE),
            quote_identifier(T::KEY_COLUMN)
        );
        let rows = sqlx::query(&sql)
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(&self.pool)
            .await?;
        let items = rows
            .into_iter()
            .map(|row| decode_record(row.try_get::<String, _>(0)?))
            .collect::<Result<Vec<T>, DatabaseError>>()?;
        Ok(RepositoryPage {
            items,
            total_count,
            offset,
            limit,
        })
    }

    pub async fn update(&self, entity: &T) -> Result<bool, DatabaseError> {
        entity.validate()?;
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

impl Repository<Asset> {
    /// Removes a server's project links and invalidates production evidence in one transaction.
    /// Kept history is represented by an asset tombstone without its pinned host key or credential.
    pub async fn unpair_server(
        &self,
        server_id: &str,
        delete_history: bool,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<ServerUnpairRecord>, DatabaseError> {
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let asset_json =
            sqlx::query_scalar::<_, String>("SELECT record_json FROM assets WHERE id = ?1")
                .bind(server_id)
                .fetch_optional(&mut *transaction)
                .await?;
        let Some(asset_json) = asset_json else {
            transaction.rollback().await?;
            return Ok(None);
        };
        let mut asset: Asset = decode_record(asset_json)?;
        let linked_project_ids = sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT project_id FROM project_server_links WHERE asset_id = ?1 ORDER BY project_id",
        )
        .bind(server_id)
        .fetch_all(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM project_server_links WHERE asset_id = ?1")
            .bind(server_id)
            .execute(&mut *transaction)
            .await?;

        for project_id in &linked_project_ids {
            let findings = sqlx::query_scalar::<_, String>(
                "SELECT f.record_json FROM findings f \
                 INNER JOIN component_instances ci ON ci.id = f.component_instance_id \
                 WHERE ci.project_id = ?1 ORDER BY f.id",
            )
            .bind(project_id)
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .map(decode_record::<Finding>)
            .collect::<Result<Vec<_>, _>>()?;
            for mut finding in findings {
                if finding.production_status == ProductionStatus::Unknown {
                    continue;
                }
                finding.production_status = ProductionStatus::Unknown;
                if matches!(
                    finding.status,
                    security_monitor_core::FindingStatus::FixedInProduction
                ) {
                    finding.status = security_monitor_core::FindingStatus::NeedsReview;
                }
                finding.updated_at = now;
                update_in_transaction(&mut transaction, &finding).await?;
            }
        }

        let ssh_target_ref = asset.ssh_target_ref.take();
        asset.host_key_fingerprint = None;
        if delete_history {
            sqlx::query(
                "DELETE FROM audit_events WHERE action = 'server_inventory_collection_approved' \
                 AND json_extract(scope_json, '$.resource_id') = ?1",
            )
            .bind(server_id)
            .execute(&mut *transaction)
            .await?;
            sqlx::query("DELETE FROM assets WHERE id = ?1")
                .bind(server_id)
                .execute(&mut *transaction)
                .await?;
        } else {
            asset.removed_at = Some(now);
            asset.updated_at = now;
            update_in_transaction(&mut transaction, &asset).await?;
        }

        let event = AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: now,
            actor: "user".to_owned(),
            action: "server_unpaired".to_owned(),
            scope: security_monitor_core::AuditScope {
                resource_type: "asset".to_owned(),
                resource_id: Some(server_id.to_owned()),
            },
            result: security_monitor_core::AuditResult::Succeeded,
        };
        insert_in_transaction(&mut transaction, &event).await?;
        transaction.commit().await?;

        Ok(Some(ServerUnpairRecord {
            ssh_target_ref,
            linked_project_ids,
            history_deleted: delete_history,
        }))
    }
}

impl Repository<Finding> {
    pub async fn list_filtered_page(
        &self,
        offset: u32,
        limit: u32,
        filter: &FindingPageFilter<'_>,
    ) -> Result<RepositoryPage<Finding>, DatabaseError> {
        let limit = limit.clamp(1, 100);
        let status = filter.status.unwrap_or_default();
        let severity = filter.severity.unwrap_or_default();
        let project_id = filter.project_id.unwrap_or_default();
        let search = filter.search.trim().chars().take(200).collect::<String>();
        let count_sql = format!("SELECT COUNT(*) {FINDING_FILTER_FROM_WHERE}");
        let total_count = sqlx::query_scalar::<_, i64>(&count_sql)
            .bind(status)
            .bind(severity)
            .bind(project_id)
            .bind(search.as_str())
            .fetch_one(&self.pool)
            .await? as u64;
        let sql = format!(
            "SELECT f.record_json {FINDING_FILTER_FROM_WHERE} \
             ORDER BY json_extract(f.record_json, '$.priority_score') DESC, \
             json_extract(f.record_json, '$.updated_at') DESC, f.id LIMIT ?5 OFFSET ?6"
        );
        let rows = sqlx::query(&sql)
            .bind(status)
            .bind(severity)
            .bind(project_id)
            .bind(search.as_str())
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(&self.pool)
            .await?;
        let items = rows
            .into_iter()
            .map(|row| decode_record(row.try_get::<String, _>(0)?))
            .collect::<Result<Vec<Finding>, DatabaseError>>()?;
        Ok(RepositoryPage {
            items,
            total_count,
            offset,
            limit,
        })
    }
}

const FINDING_FILTER_FROM_WHERE: &str = "FROM findings f \
    LEFT JOIN component_instances i ON i.id = json_extract(f.record_json, '$.component_instance_id') \
    LEFT JOIN components c ON c.id = i.component_id \
    LEFT JOIN advisories a ON a.canonical_id = json_extract(f.record_json, '$.advisory_id') \
    LEFT JOIN projects p ON p.id = i.project_id \
    WHERE (?1 = '' OR json_extract(f.record_json, '$.status') = ?1) \
      AND (?2 = '' OR json_extract(f.record_json, '$.severity') = ?2) \
      AND (?3 = '' OR i.project_id = ?3) \
      AND (?4 = '' OR instr(lower( \
        coalesce(a.canonical_id, json_extract(f.record_json, '$.advisory_id')) || ' ' || \
        coalesce(a.title, '') || ' ' || coalesce(c.name, '') || ' ' || \
        coalesce(c.version, '') || ' ' || coalesce(p.name, '') \
      ), lower(?4)) > 0)";

impl Repository<NotificationDeliveryState> {
    /// Reserves a delivery atomically. A successfully delivered fingerprint is never claimed
    /// again; snoozes and active delivery leases are also respected.
    pub async fn claim_delivery(
        &self,
        channel_id: &str,
        event_fingerprint: &str,
        now: chrono::DateTime<chrono::Utc>,
        lease_duration: chrono::Duration,
    ) -> Result<Option<String>, DatabaseError> {
        let id = notification_state_id(channel_id, event_fingerprint);
        let now_text = timestamp(now);
        let lease_until = timestamp(now + lease_duration);
        let state = NotificationDeliveryState {
            id: id.clone(),
            channel_id: channel_id.to_owned(),
            event_fingerprint: event_fingerprint.to_owned(),
            last_delivered_at: None,
            snoozed_until: None,
            lease_expires_at: Some(now + lease_duration),
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_string(&state)?;
        let claimed = sqlx::query_scalar::<_, String>(
            "INSERT INTO notification_delivery_states \
             (id, channel_id, event_fingerprint, last_delivered_at, snoozed_until, \
              lease_expires_at, created_at, updated_at, record_json) \
             VALUES (?1, ?2, ?3, NULL, NULL, ?4, ?5, ?5, ?6) \
             ON CONFLICT(channel_id, event_fingerprint) DO UPDATE SET \
               lease_expires_at = excluded.lease_expires_at, \
               updated_at = excluded.updated_at, \
               record_json = json_set(notification_delivery_states.record_json, \
                 '$.lease_expires_at', excluded.lease_expires_at, \
                 '$.updated_at', excluded.updated_at) \
             WHERE (notification_delivery_states.snoozed_until IS NULL OR \
                    notification_delivery_states.snoozed_until <= excluded.updated_at) \
               AND (notification_delivery_states.lease_expires_at IS NULL OR \
                    notification_delivery_states.lease_expires_at <= excluded.updated_at) \
               AND notification_delivery_states.last_delivered_at IS NULL \
             RETURNING id",
        )
        .bind(id)
        .bind(channel_id)
        .bind(event_fingerprint)
        .bind(lease_until)
        .bind(now_text)
        .bind(json)
        .fetch_optional(&self.pool)
        .await?;
        Ok(claimed)
    }

    /// Completes or releases a reservation without storing any notification payload.
    pub async fn finish_delivery(
        &self,
        state_id: &str,
        delivered: bool,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, DatabaseError> {
        let now_text = timestamp(now);
        let result = sqlx::query(
            "UPDATE notification_delivery_states SET \
             last_delivered_at = CASE WHEN ?1 = 1 THEN ?2 ELSE last_delivered_at END, \
             lease_expires_at = NULL, updated_at = ?2, \
             record_json = json_set(record_json, '$.last_delivered_at', \
               CASE WHEN ?1 = 1 THEN ?2 ELSE last_delivered_at END, \
               '$.lease_expires_at', NULL, '$.updated_at', ?2) WHERE id = ?3",
        )
        .bind(delivered)
        .bind(now_text)
        .bind(state_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Persists a per-channel, per-event snooze, including before the first delivery.
    pub async fn snooze(
        &self,
        channel_id: &str,
        event_fingerprint: &str,
        until: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DatabaseError> {
        let id = notification_state_id(channel_id, event_fingerprint);
        let state = NotificationDeliveryState {
            id: id.clone(),
            channel_id: channel_id.to_owned(),
            event_fingerprint: event_fingerprint.to_owned(),
            last_delivered_at: None,
            snoozed_until: Some(until),
            lease_expires_at: None,
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_string(&state)?;
        let now_text = timestamp(now);
        let until_text = timestamp(until);
        sqlx::query(
            "INSERT INTO notification_delivery_states \
             (id, channel_id, event_fingerprint, last_delivered_at, snoozed_until, \
              lease_expires_at, created_at, updated_at, record_json) \
             VALUES (?1, ?2, ?3, NULL, ?4, NULL, ?5, ?5, ?6) \
             ON CONFLICT(channel_id, event_fingerprint) DO UPDATE SET \
               snoozed_until = excluded.snoozed_until, updated_at = excluded.updated_at, \
               record_json = json_set(notification_delivery_states.record_json, \
                 '$.snoozed_until', excluded.snoozed_until, '$.updated_at', excluded.updated_at)",
        )
        .bind(id)
        .bind(channel_id)
        .bind(event_fingerprint)
        .bind(until_text)
        .bind(now_text)
        .bind(json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn notification_state_id(channel_id: &str, event_fingerprint: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(channel_id.as_bytes());
    digest.update([0]);
    digest.update(event_fingerprint.as_bytes());
    format!("notification-{}", hex::encode(digest.finalize()))
}

fn timestamp(value: chrono::DateTime<chrono::Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
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
    #[error("finding disposition is incomplete or inconsistent")]
    InvalidFindingDisposition,
    #[error(
        "enabled external notification channel requires recorded approval and a credential reference"
    )]
    NotificationApprovalRequired,
    #[error("notification approval destination must contain only a valid scheme and host")]
    InvalidNotificationDestination,
    #[error("canonical advisory is missing during rekey")]
    MissingAdvisoryTarget,
    #[error("database schema does not support MCP memory writes")]
    MemorySchemaUnavailable,
    #[error("memory record is invalid")]
    InvalidMemory,
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

    fn validate(&self) -> Result<(), DatabaseError> {
        Ok(())
    }
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{identifier}\"")
}

async fn update_in_transaction<T: Entity>(
    transaction: &mut Transaction<'_, Sqlite>,
    entity: &T,
) -> Result<(), DatabaseError> {
    entity.validate()?;
    let json = serde_json::to_string(entity)?;
    validate_record(T::TABLE, &json)?;
    let assignments = T::COLUMNS
        .iter()
        .map(|(column, path)| format!("{} = json_extract(?1, '{path}')", quote_identifier(column)))
        .chain(std::iter::once("record_json = ?1".to_owned()))
        .collect::<Vec<_>>();
    let sql = format!(
        "UPDATE {} SET {} WHERE {} = ?2",
        quote_identifier(T::TABLE),
        assignments.join(", "),
        quote_identifier(T::KEY_COLUMN)
    );
    sqlx::query(&sql)
        .bind(json)
        .bind(T::key(entity))
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn insert_in_transaction<T: Entity>(
    transaction: &mut Transaction<'_, Sqlite>,
    entity: &T,
) -> Result<(), DatabaseError> {
    entity.validate()?;
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
    sqlx::query(&sql)
        .bind(json)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn decode_record<T: DeserializeOwned>(json: String) -> Result<T, DatabaseError> {
    Ok(serde_json::from_str(&json)?)
}

fn validate_record(table: &str, json: &str) -> Result<(), DatabaseError> {
    let record: serde_json::Value = serde_json::from_str(json)?;
    if table == "notification_channels" {
        let kind = record
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let enabled = record
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if let Some(destination) = record
            .get("network_approved_destination")
            .and_then(serde_json::Value::as_str)
        {
            validate_notification_destination(kind, destination)?;
        }
        if enabled && kind != "desktop" {
            let approved_at = record
                .get("network_approved_at")
                .and_then(serde_json::Value::as_str)
                .and_then(parse_timestamp);
            if approved_at.is_none()
                || record
                    .get("network_approved_destination")
                    .is_none_or(serde_json::Value::is_null)
                || record
                    .get("config_ref")
                    .is_none_or(serde_json::Value::is_null)
            {
                return Err(DatabaseError::NotificationApprovalRequired);
            }
        }
    }
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

fn validate_notification_destination(kind: &str, destination: &str) -> Result<(), DatabaseError> {
    let parsed =
        url::Url::parse(destination).map_err(|_| DatabaseError::InvalidNotificationDestination)?;
    let scheme_matches = match kind {
        "webhook" | "slack" | "discord" => parsed.scheme() == "https",
        "smtp" => matches!(parsed.scheme(), "smtp" | "smtps"),
        _ => false,
    };
    if !scheme_matches
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.port_or_known_default().is_none()
    {
        return Err(DatabaseError::InvalidNotificationDestination);
    }
    Ok(())
}

fn parse_timestamp(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
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
    ($type:ty, $key:ident, $table:literal, $key_column:literal, [$(($column:literal, $path:literal)),+ $(,)?], $validator:ident, $error:ident) => {
        impl sealed::Sealed for $type {}

        impl Entity for $type {
            const TABLE: &'static str = $table;
            const KEY_COLUMN: &'static str = $key_column;
            const COLUMNS: &'static [(&'static str, &'static str)] = &[$(($column, $path)),+];

            fn key(&self) -> &str {
                self.$key.as_str()
            }

            fn validate(&self) -> Result<(), DatabaseError> {
                self.$validator().map_err(|_| DatabaseError::$error)
            }
        }
    };
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
        ("removed_at", "$.removed_at"),
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
    NewsSignal,
    id,
    "news_signals",
    "id",
    [
        ("id", "$.id"),
        ("feed_id", "$.feed_id"),
        ("external_id", "$.external_id"),
        ("advisory_id", "$.advisory_id"),
        ("archived_at", "$.archived_at"),
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
        ("disposition", "$.disposition"),
        ("risk_expires_at", "$.risk_expires_at"),
        ("fix_version", "$.fix_version"),
        ("created_at", "$.created_at"),
        ("updated_at", "$.updated_at"),
    ],
    validate,
    InvalidFindingDisposition
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
    ProjectScanCheckpoint,
    id,
    "project_scan_checkpoints",
    "id",
    [
        ("id", "$.id"),
        ("project_id", "$.project_id"),
        ("input_hash", "$.input_hash"),
        ("inventory_json", "$.inventory_json"),
        ("inventory_complete", "$.inventory_complete"),
        ("checked_at", "$.checked_at"),
        ("created_at", "$.created_at"),
        ("updated_at", "$.updated_at"),
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
        ("provider_id", "$.provider_id"),
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
        ("model", "$.model"),
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
    AiDataTransferApproval,
    id,
    "ai_transfer_approvals",
    "id",
    [
        ("id", "$.id"),
        ("project_id", "$.project_id"),
        ("provider_id", "$.provider_id"),
        ("destination_origin", "$.destination_origin"),
        ("data_category", "$.data_category"),
        ("tier", "$.tier"),
        ("content_sha256", "$.content_sha256"),
        ("approved_at", "$.approved_at"),
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
        ("network_approved_at", "$.network_approved_at"),
        (
            "network_approved_destination",
            "$.network_approved_destination"
        ),
        ("created_at", "$.created_at"),
        ("updated_at", "$.updated_at"),
    ]
);
entity!(
    NotificationDeliveryState,
    id,
    "notification_delivery_states",
    "id",
    [
        ("id", "$.id"),
        ("channel_id", "$.channel_id"),
        ("event_fingerprint", "$.event_fingerprint"),
        ("last_delivered_at", "$.last_delivered_at"),
        ("snoozed_until", "$.snoozed_until"),
        ("lease_expires_at", "$.lease_expires_at"),
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
entity!(
    ProjectServerLink,
    id,
    "project_server_links",
    "id",
    [
        ("id", "$.id"),
        ("project_id", "$.project_id"),
        ("asset_id", "$.asset_id"),
        ("confirmed_at", "$.confirmed_at"),
    ]
);
entity!(
    Memory,
    id,
    "memories",
    "id",
    [
        ("id", "$.id"),
        ("scope", "$.scope"),
        ("scope_id", "$.scope_id"),
        ("kind", "$.kind"),
        ("content", "$.content"),
        ("author", "$.author"),
        ("source_run_id", "$.source_run_id"),
        ("created_at", "$.created_at"),
        ("expires_at", "$.expires_at"),
        ("pinned", "$.pinned"),
        ("verified_at", "$.verified_at"),
        ("verified_by", "$.verified_by"),
    ],
    validate,
    InvalidMemory
);

#[cfg(test)]
mod tests;
