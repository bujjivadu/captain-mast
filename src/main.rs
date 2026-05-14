mod auth;
mod broker;
mod config;
mod error;
mod inference;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::sync::mpsc;
use tracing::info;

use crate::auth::{AclStore, PasswdStore};
use crate::broker::{BlockList, BrokerEngine};
use crate::config::MastConfig;
use crate::error::{MastError, Result};
use crate::inference::BrokerEvent;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "captain-mast",
    about = "A standalone MQTT broker with Mosquitto-compatible auth and ACL",
    version
)]
struct Cli {
    /// Path to broker configuration file
    #[arg(short, long, default_value = "mast.conf")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage broker user passwords
    Passwd {
        /// Path to password file (overrides config file setting)
        #[arg(short = 'f', long)]
        file: Option<PathBuf>,

        #[command(subcommand)]
        action: PasswdAction,
    },
}

#[derive(Subcommand)]
enum PasswdAction {
    /// Add or update a user (prompts for password, or use --password for scripted use)
    Set {
        username: String,
        /// Set password non-interactively (use in scripts; omit to prompt)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Delete a user
    Delete { username: String },
    /// List all users in the password file
    List,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    // passwd subcommand: handle before full broker init
    if let Some(Commands::Passwd { file, action }) = cli.command {
        return passwd_cmd(action, file, &cli.config);
    }

    // ── Tracing ──────────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("captain_mast=info,rumqttd=warn")),
        )
        .init();

    // ── Config ────────────────────────────────────────────────────────────────
    info!("Loading config from {:?}", cli.config);
    let config = MastConfig::load(&cli.config)?;

    // ── Passwd store ──────────────────────────────────────────────────────────
    let passwd = if let Some(ref path) = config.password_file {
        info!("Loading password file from {:?}", path);
        PasswdStore::load(path)?
    } else {
        if !config.allow_anonymous {
            tracing::warn!(
                "No password_file configured and allow_anonymous=false — \
                 all connections will be rejected"
            );
        }
        PasswdStore::empty()
    };

    // ── ACL store ─────────────────────────────────────────────────────────────
    let acl = if let Some(ref path) = config.acl_file {
        info!("Loading ACL file from {:?}", path);
        AclStore::load(path)?
    } else {
        tracing::debug!("No acl_file configured — open ACL (all topics allowed)");
        AclStore::open()
    };

    // ── Inference ─────────────────────────────────────────────────────────────
    //
    // The BlockList is always created (starts empty). The inference monitor is
    // only started when hf_enabled=true; the block list is checked on every
    // CONNECT regardless so blocks written by the monitor take effect immediately.
    let block_list = Arc::new(BlockList::new());

    let (event_tx, event_rx) = if config.inference.enabled {
        if config.inference.api_key.is_empty() {
            tracing::warn!(
                "hf_enabled=true but hf_api_key is empty — inference monitor will not start"
            );
            (None, None)
        } else {
            // Buffer up to 4096 events; extras are dropped (non-critical for monitoring).
            let (tx, rx) = mpsc::channel::<BrokerEvent>(4096);
            info!(
                model = %config.inference.model,
                "Inference monitor enabled"
            );
            (Some(tx), Some(rx))
        }
    } else {
        (None, None)
    };

    // ── Broker ────────────────────────────────────────────────────────────────
    // Install the logging client-cert verifier (rumqttd fork hook). Must run
    // before BrokerEngine constructs the TLS listener.
    crate::broker::tls::install();

    BrokerEngine::new(config, passwd, acl, block_list, event_tx, event_rx).start()
}

// ── passwd subcommand ─────────────────────────────────────────────────────────

fn passwd_cmd(
    action: PasswdAction,
    file_override: Option<PathBuf>,
    config_path: &PathBuf,
) -> Result<()> {
    let passwd_path = if let Some(f) = file_override {
        f
    } else {
        MastConfig::load(config_path)
            .ok()
            .and_then(|c| c.password_file)
            .unwrap_or_else(|| PathBuf::from("passwd"))
    };

    match action {
        PasswdAction::Set { username, password: pw_flag } => {
            let password = if let Some(p) = pw_flag {
                p
            } else {
                let p = rpassword::prompt_password(format!("Password for {username}: "))
                    .map_err(MastError::Io)?;
                let confirm = rpassword::prompt_password("Confirm password: ").map_err(MastError::Io)?;
                if p != confirm {
                    eprintln!("Error: passwords do not match");
                    std::process::exit(1);
                }
                p
            };

            let mut store = if passwd_path.exists() {
                PasswdStore::load(&passwd_path)?
            } else {
                PasswdStore::empty()
            };

            store.set_password(&username, &password)?;
            store.save(&passwd_path)?;
            println!("Password updated for '{username}'");
        }

        PasswdAction::Delete { username } => {
            let mut store = PasswdStore::load(&passwd_path)?;
            if store.delete(&username) {
                store.save(&passwd_path)?;
                println!("Deleted user '{username}'");
            } else {
                eprintln!("User '{username}' not found");
                std::process::exit(1);
            }
        }

        PasswdAction::List => {
            let store = if passwd_path.exists() {
                PasswdStore::load(&passwd_path)?
            } else {
                PasswdStore::empty()
            };
            let users = store.list();
            if users.is_empty() {
                println!("(no users)");
            } else {
                for u in users {
                    println!("{u}");
                }
            }
        }
    }

    Ok(())
}
