mod auth;
mod broker;
mod config;
mod error;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing::info;

use crate::auth::{AclStore, PasswdStore};
use crate::broker::BrokerEngine;
use crate::config::MastConfig;
use crate::error::{MastError, Result};

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
    /// Add or update a user (prompts for password)
    Set { username: String },
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

    // ── Broker ────────────────────────────────────────────────────────────────
    BrokerEngine::new(config, passwd, acl).start()
}

// ── passwd subcommand ─────────────────────────────────────────────────────────

fn passwd_cmd(
    action: PasswdAction,
    file_override: Option<PathBuf>,
    config_path: &PathBuf,
) -> Result<()> {
    // Resolve which passwd file to use
    let passwd_path = if let Some(f) = file_override {
        f
    } else {
        MastConfig::load(config_path)
            .ok()
            .and_then(|c| c.password_file)
            .unwrap_or_else(|| PathBuf::from("passwd"))
    };

    match action {
        PasswdAction::Set { username } => {
            let password = rpassword::prompt_password(format!("Password for {username}: "))
                .map_err(MastError::Io)?;
            let confirm = rpassword::prompt_password("Confirm password: ").map_err(MastError::Io)?;

            if password != confirm {
                eprintln!("Error: passwords do not match");
                std::process::exit(1);
            }

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
