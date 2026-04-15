use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{MastError, Result};

/// Top-level broker configuration, parsed from a Mosquitto-compatible mast.conf file.
#[derive(Debug, Clone)]
pub struct MastConfig {
    pub listeners: Vec<ListenerConfig>,
    pub password_file: Option<PathBuf>,
    pub acl_file: Option<PathBuf>,
    pub allow_anonymous: bool,
    pub log_level: LogLevel,
    pub log_dest: Vec<LogDest>,
    pub persistence: bool,
    pub persistence_location: Option<PathBuf>,
    /// -1 = unlimited
    pub max_connections: i64,
    pub max_inflight_messages: usize,
    pub max_queued_messages: usize,
}

impl Default for MastConfig {
    fn default() -> Self {
        Self {
            listeners: vec![ListenerConfig {
                port: 1883,
                bind_addr: None,
                tls: None,
                websocket: false,
            }],
            password_file: None,
            acl_file: None,
            allow_anonymous: true,
            log_level: LogLevel::Info,
            log_dest: vec![LogDest::Stdout],
            persistence: false,
            persistence_location: None,
            max_connections: -1,
            max_inflight_messages: 20,
            max_queued_messages: 1000,
        }
    }
}

impl MastConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|e| {
            MastError::Config(format!("Cannot read config file {:?}: {}", path, e))
        })?;
        Self::parse(&content)
    }

    fn parse(content: &str) -> Result<Self> {
        let mut config = MastConfig::default();
        config.listeners.clear();

        let mut current_listener: Option<ListenerConfig> = None;
        let mut log_dest_set = false;

        for (idx, raw_line) in content.lines().enumerate() {
            let line_num = idx + 1;
            let line = raw_line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Split on first whitespace into (key, value)
            let (key, value) = split_kv(line);

            match key {
                "listener" => {
                    if let Some(prev) = current_listener.take() {
                        config.listeners.push(prev);
                    }
                    let mut parts = value.split_whitespace();
                    let port: u16 = parts
                        .next()
                        .and_then(|p| p.parse().ok())
                        .ok_or_else(|| MastError::ConfigParse {
                            line: line_num,
                            message: format!("Invalid port: '{}'", value),
                        })?;
                    current_listener = Some(ListenerConfig {
                        port,
                        bind_addr: parts.next().map(String::from),
                        tls: None,
                        websocket: false,
                    });
                }

                // TLS directives apply to the current listener
                "cafile" => {
                    if let Some(ref mut l) = current_listener {
                        l.tls.get_or_insert_with(TlsListenerConfig::default).cafile =
                            Some(PathBuf::from(value));
                    }
                }
                "certfile" => {
                    if let Some(ref mut l) = current_listener {
                        l.tls.get_or_insert_with(TlsListenerConfig::default).certfile =
                            Some(PathBuf::from(value));
                    }
                }
                "keyfile" => {
                    if let Some(ref mut l) = current_listener {
                        l.tls.get_or_insert_with(TlsListenerConfig::default).keyfile =
                            Some(PathBuf::from(value));
                    }
                }
                "websocket" | "protocol" => {
                    if let Some(ref mut l) = current_listener {
                        l.websocket = value == "true" || value == "websockets";
                    }
                }

                // Global auth/acl
                "password_file" => config.password_file = Some(PathBuf::from(value)),
                "acl_file" => config.acl_file = Some(PathBuf::from(value)),
                "allow_anonymous" => match value {
                    "true" => config.allow_anonymous = true,
                    "false" => config.allow_anonymous = false,
                    _ => {
                        return Err(MastError::ConfigParse {
                            line: line_num,
                            message: format!("Expected true/false for allow_anonymous, got '{}'", value),
                        })
                    }
                },

                // Logging
                "log_type" | "log_level" => {
                    config.log_level = match value {
                        "debug" | "all" => LogLevel::Debug,
                        "information" | "info" => LogLevel::Info,
                        "notice" => LogLevel::Notice,
                        "warning" | "warn" => LogLevel::Warn,
                        "error" => LogLevel::Error,
                        _ => LogLevel::Info,
                    };
                }
                "log_dest" => {
                    if !log_dest_set {
                        config.log_dest.clear();
                        log_dest_set = true;
                    }
                    match value {
                        "stdout" => config.log_dest.push(LogDest::Stdout),
                        "stderr" => config.log_dest.push(LogDest::Stderr),
                        _ if value.starts_with("file ") => {
                            let path = value["file ".len()..].trim();
                            config.log_dest.push(LogDest::File(PathBuf::from(path)));
                        }
                        _ => {
                            tracing::warn!("Unknown log_dest '{}' at line {} (ignored)", value, line_num);
                        }
                    }
                }

                // Persistence
                "persistence" => config.persistence = value == "true",
                "persistence_location" => {
                    config.persistence_location = Some(PathBuf::from(value))
                }

                // Limits
                "max_connections" => config.max_connections = value.parse().unwrap_or(-1),
                "max_inflight_messages" => {
                    config.max_inflight_messages = value.parse().unwrap_or(20)
                }
                "max_queued_messages" => {
                    config.max_queued_messages = value.parse().unwrap_or(1000)
                }

                other => {
                    tracing::debug!("Unknown directive '{}' at line {} — ignored", other, line_num);
                }
            }
        }

        if let Some(listener) = current_listener {
            config.listeners.push(listener);
        }

        // Fall back to default TCP 1883 if nothing was declared
        if config.listeners.is_empty() {
            config.listeners.push(ListenerConfig {
                port: 1883,
                bind_addr: None,
                tls: None,
                websocket: false,
            });
        }

        Ok(config)
    }
}

fn split_kv(line: &str) -> (&str, &str) {
    match line.find(char::is_whitespace) {
        Some(pos) => (&line[..pos], line[pos..].trim()),
        None => (line, ""),
    }
}

// ── Sub-structs ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    pub port: u16,
    pub bind_addr: Option<String>,
    pub tls: Option<TlsListenerConfig>,
    pub websocket: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TlsListenerConfig {
    pub cafile: Option<PathBuf>,
    pub certfile: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogLevel {
    Debug,
    Info,
    Notice,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogDest {
    Stdout,
    Stderr,
    File(PathBuf),
}
