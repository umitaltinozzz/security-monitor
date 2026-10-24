use std::{env, path::PathBuf, sync::Arc};

use clap::{Parser, Subcommand};
use security_monitor_ai::AiSettings;
use security_monitor_database::Database;
use security_monitor_mcp_server::{McpServer, WorkspaceTools};

#[derive(Debug, Parser)]
#[command(version, about = "Security Monitor command-line interface")]
struct Arguments {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the local stdio MCP server. Tools come from local AI permissions.
    Mcp {
        /// Use a specific existing Security Monitor database.
        #[arg(long)]
        database: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    let arguments = Arguments::parse();
    if let Some(Command::Mcp { database }) = arguments.command
        && let Err(error) = run_mcp(database).await
    {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run_mcp(database: Option<PathBuf>) -> Result<(), &'static str> {
    let database_path = database
        .unwrap_or_else(default_database_path)
        .canonicalize()
        .map_err(|_| "database_unavailable")?;
    let app_data = database_path.parent().ok_or("database_unavailable")?;
    let settings_path = app_data.join("ai-settings.json");
    let ai_settings = std::fs::read(settings_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<AiSettings>(&bytes).ok())
        .filter(|settings| settings.validate().is_ok())
        .unwrap_or_default();
    let database = Database::open_read_only(database_path)
        .await
        .map_err(|_| "database_unavailable")?;
    let executor = Arc::new(WorkspaceTools::new(database.clone(), None));
    let server = McpServer::new(executor, ai_settings.enabled_tools);
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    server
        .serve_stdio(tokio::io::BufReader::new(stdin), stdout)
        .await
        .map_err(|_| "mcp_transport_failed")?;
    database.close().await;
    Ok(())
}

fn default_database_path() -> PathBuf {
    let directory = if cfg!(target_os = "windows") {
        env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir)
            .join("org.securitymonitor.desktop")
    } else if cfg!(target_os = "macos") {
        env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir)
            .join("Library")
            .join("Application Support")
            .join("org.securitymonitor.desktop")
    } else {
        env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(env::temp_dir)
                    .join(".local")
                    .join("share")
            })
            .join("org.securitymonitor.desktop")
    };
    directory.join("security-monitor.sqlite3")
}
