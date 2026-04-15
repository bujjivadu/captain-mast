use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use rumqttd::{Broker, Config, ConnectionSettings, RouterConfig, ServerSettings, TlsConfig};
use tracing::info;

use crate::auth::{AclStore, PasswdStore};
use crate::config::MastConfig;
use crate::error::{MastError, Result};

pub struct BrokerEngine {
    config: MastConfig,
    passwd: Arc<PasswdStore>,
    /// Stored for future ACL enforcement once rumqttd exposes pub/sub hooks.
    _acl: Arc<AclStore>,
}

impl BrokerEngine {
    pub fn new(config: MastConfig, passwd: PasswdStore, acl: AclStore) -> Self {
        Self {
            config,
            passwd: Arc::new(passwd),
            _acl: Arc::new(acl),
        }
    }

    pub fn start(self) -> Result<()> {
        let allow_anonymous = self.config.allow_anonymous;
        let max_connections = if self.config.max_connections < 0 {
            // rumqttd uses usize; saturate to a practical max instead of usize::MAX
            // to avoid overflow in internal allocations
            100_000_usize
        } else {
            self.config.max_connections as usize
        };

        let passwd = Arc::clone(&self.passwd);

        let mut rumqttd_config = build_rumqttd_config(&self.config, max_connections);

        // Wire bcrypt auth handler into every TCP/TLS listener (v4)
        if let Some(ref mut v4) = rumqttd_config.v4 {
            wire_auth(v4, Arc::clone(&passwd), allow_anonymous);
        }
        // Wire into WebSocket listeners too
        if let Some(ref mut ws) = rumqttd_config.ws {
            wire_auth(ws, Arc::clone(&passwd), allow_anonymous);
        }

        // Log what we're about to start
        for l in &self.config.listeners {
            let proto = match (l.websocket, l.tls.is_some()) {
                (true, true) => "WSS",
                (true, false) => "WS",
                (false, true) => "TLS",
                (false, false) => "TCP",
            };
            let bind = l.bind_addr.as_deref().unwrap_or("0.0.0.0");
            info!("  listener {}:{} [{}]", bind, l.port, proto);
        }
        if allow_anonymous {
            info!("  allow_anonymous = true");
        } else {
            info!("  allow_anonymous = false  (bcrypt auth required)");
        }

        info!("captain-mast broker starting");
        let mut broker = Broker::new(rumqttd_config);
        broker
            .start()
            .map_err(|e| MastError::Broker(e.to_string()))
    }
}

// ── Auth wiring ───────────────────────────────────────────────────────────────

fn wire_auth(
    servers: &mut HashMap<String, ServerSettings>,
    passwd: Arc<PasswdStore>,
    allow_anonymous: bool,
) {
    for (_, server) in servers.iter_mut() {
        let passwd = Arc::clone(&passwd);
        server.set_auth_handler(
            move |client_id: String, username: String, password: String| {
                let passwd = Arc::clone(&passwd);
                async move {
                    if username.is_empty() {
                        if allow_anonymous {
                            tracing::debug!(client_id, "anonymous connect accepted");
                            return true;
                        } else {
                            tracing::warn!(client_id, "anonymous connect rejected (allow_anonymous=false)");
                            return false;
                        }
                    }
                    let ok = passwd.verify(&username, &password);
                    if ok {
                        tracing::info!(client_id, username, "auth accepted");
                    } else {
                        tracing::warn!(client_id, username, "auth rejected — bad credentials");
                    }
                    ok
                }
            },
        );
    }
}

// ── Config builder ────────────────────────────────────────────────────────────

fn build_rumqttd_config(config: &MastConfig, max_connections: usize) -> Config {
    let router = RouterConfig {
        max_connections,
        max_outgoing_packet_count: config.max_queued_messages as u64,
        max_segment_size: 104_857_600, // 100 MB commit log per topic
        max_segment_count: 10,
        initialized_filters: None,
        custom_segment: None,
        shared_subscriptions_strategy: Default::default(),
    };

    let mut v4: HashMap<String, ServerSettings> = HashMap::new();
    let mut ws: HashMap<String, ServerSettings> = HashMap::new();

    for (idx, listener) in config.listeners.iter().enumerate() {
        let addr: SocketAddr = format!(
            "{}:{}",
            listener.bind_addr.as_deref().unwrap_or("0.0.0.0"),
            listener.port
        )
        .parse()
        .unwrap_or_else(|_| {
            format!("0.0.0.0:{}", listener.port).parse().unwrap()
        });

        let tls = listener.tls.as_ref().and_then(|t| {
            // Both certfile and keyfile must be present to enable TLS
            let cert = t.certfile.as_ref()?.to_string_lossy().into_owned();
            let key = t.keyfile.as_ref()?.to_string_lossy().into_owned();
            let ca = t.cafile.as_ref().map(|p| p.to_string_lossy().into_owned());
            Some(TlsConfig::Rustls {
                capath: ca,
                certpath: cert,
                keypath: key,
            })
        });

        let connections = ConnectionSettings {
            connection_timeout_ms: 5000,
            max_payload_size: 1_048_576, // 1 MB
            max_inflight_count: config.max_inflight_messages,
            auth: None,         // auth handled via external_auth (set_auth_handler)
            external_auth: None, // populated by wire_auth() after this fn returns
            dynamic_filters: true,
        };

        let server = ServerSettings {
            name: format!("listener-{}", idx),
            listen: addr,
            tls,
            next_connection_delay_ms: 1,
            connections,
        };

        if listener.websocket {
            ws.insert(idx.to_string(), server);
        } else {
            v4.insert(idx.to_string(), server);
        }
    }

    Config {
        id: 0,
        router,
        v4: if v4.is_empty() { None } else { Some(v4) },
        v5: None,
        ws: if ws.is_empty() { None } else { Some(ws) },
        cluster: None,
        console: None,
        bridge: None,
        prometheus: None,
        metrics: None,
    }
}
