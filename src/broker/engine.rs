use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use rumqttd::{Broker, Config, ConnectionSettings, RouterConfig, ServerSettings, TlsConfig};
use tokio::sync::mpsc;
use tracing::info;

use crate::auth::{AclStore, PasswdStore};
use crate::broker::BlockList;
use crate::config::MastConfig;
use crate::error::{MastError, Result};
use crate::inference::{BrokerEvent, Monitor};

pub struct BrokerEngine {
    config: MastConfig,
    passwd: Arc<PasswdStore>,
    /// Stored for future ACL enforcement once rumqttd exposes pub/sub hooks.
    _acl: Arc<AclStore>,
    block_list: Arc<BlockList>,
    /// Sender half of the inference event channel (None when inference is disabled).
    event_tx: Option<mpsc::Sender<BrokerEvent>>,
    /// Receiver half — consumed by the monitor thread inside start().
    event_rx: Option<mpsc::Receiver<BrokerEvent>>,
}

impl BrokerEngine {
    pub fn new(
        config: MastConfig,
        passwd: PasswdStore,
        acl: AclStore,
        block_list: Arc<BlockList>,
        event_tx: Option<mpsc::Sender<BrokerEvent>>,
        event_rx: Option<mpsc::Receiver<BrokerEvent>>,
    ) -> Self {
        Self {
            config,
            passwd: Arc::new(passwd),
            _acl: Arc::new(acl),
            block_list,
            event_tx,
            event_rx,
        }
    }

    pub fn start(mut self) -> Result<()> {
        let allow_anonymous = self.config.allow_anonymous;
        let max_connections = if self.config.max_connections < 0 {
            100_000_usize
        } else {
            self.config.max_connections as usize
        };

        // Validate mTLS config before touching rumqttd.
        for l in &self.config.listeners {
            if let Some(tls) = &l.tls {
                if tls.require_certificate {
                    if tls.cafile.is_none() {
                        return Err(MastError::Config(format!(
                            "Listener on port {} has require_certificate=true but no cafile",
                            l.port
                        )));
                    }
                    if tls.certfile.is_none() || tls.keyfile.is_none() {
                        return Err(MastError::Config(format!(
                            "Listener on port {} has require_certificate=true but missing certfile/keyfile",
                            l.port
                        )));
                    }
                }
            }
        }

        let passwd = Arc::clone(&self.passwd);
        let block_list = Arc::clone(&self.block_list);

        let mut rumqttd_config = build_rumqttd_config(&self.config, max_connections);

        // Wire bcrypt auth + inference event emission into every listener.
        if let Some(ref mut v4) = rumqttd_config.v4 {
            wire_auth(v4, Arc::clone(&passwd), allow_anonymous, self.event_tx.clone(), Arc::clone(&block_list));
        }
        if let Some(ref mut ws) = rumqttd_config.ws {
            wire_auth(ws, Arc::clone(&passwd), allow_anonymous, self.event_tx.clone(), Arc::clone(&block_list));
        }

        // Log listeners
        for l in &self.config.listeners {
            let tls_tag = match &l.tls {
                Some(t) if t.require_certificate => "mTLS",
                Some(_) => "TLS",
                None => if l.websocket { "WS" } else { "TCP" },
            };
            let proto = if l.websocket && l.tls.is_some() { "WSS/mTLS" } else { tls_tag };
            let bind = l.bind_addr.as_deref().unwrap_or("0.0.0.0");
            info!("  listener {}:{} [{}]", bind, l.port, proto);
        }
        if allow_anonymous {
            info!("  allow_anonymous = true");
        } else {
            info!("  allow_anonymous = false  (bcrypt auth required)");
        }

        // ── Broker ───────────────────────────────────────────────────────────
        //
        // Broker::new() spawns the router thread immediately inside new().
        // This means broker.link() can be called right away — the router is
        // already running before start() begins.
        let mut broker = Broker::new(rumqttd_config);

        // ── Inference monitor ────────────────────────────────────────────────
        if self.config.inference.enabled {
            if let Some(event_rx) = self.event_rx.take() {
                match broker.link("_captain_monitor") {
                    Ok((mut link_tx, link_rx)) => {
                        // Subscribe to every topic so the monitor sees all publishes.
                        match link_tx.subscribe("#") {
                            Ok(_) => info!("Inference monitor subscribed to all topics"),
                            Err(e) => tracing::warn!("Monitor subscribe failed: {} — topic monitoring unavailable", e),
                        }

                        let inference_cfg = self.config.inference.clone();
                        let bl = Arc::clone(&self.block_list);

                        // Run the monitor in a dedicated thread with its own tokio
                        // runtime — rumqttd runs its own runtimes internally too,
                        // so we keep them fully isolated.
                        std::thread::Builder::new()
                            .name("captain-monitor".into())
                            .spawn(move || {
                                let rt = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()
                                    .expect("monitor runtime");
                                rt.block_on(async move {
                                    Monitor::new(event_rx, link_tx, link_rx, &inference_cfg, bl)
                                        .run()
                                        .await;
                                });
                            })
                            .map_err(|e| MastError::Broker(format!("Cannot spawn monitor thread: {}", e)))?;

                        info!(
                            model = %self.config.inference.model,
                            interval_secs = self.config.inference.analysis_interval_secs,
                            "Inference-based threat monitor active"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Cannot create internal broker link for monitor: {} \
                             — topic monitoring disabled; auth-event monitoring still active",
                            e
                        );
                    }
                }
            }
        } else {
            info!("Inference monitor disabled (set hf_enabled=true to activate)");
        }

        info!("captain-mast broker starting");
        broker.start().map_err(|e| MastError::Broker(e.to_string()))
    }
}

// ── Auth wiring ───────────────────────────────────────────────────────────────

fn wire_auth(
    servers: &mut HashMap<String, ServerSettings>,
    passwd: Arc<PasswdStore>,
    allow_anonymous: bool,
    event_tx: Option<mpsc::Sender<BrokerEvent>>,
    block_list: Arc<BlockList>,
) {
    // When fully anonymous (no passwords configured + allow_anonymous=true) skip
    // the external_auth handler entirely.  rumqttd's native "no auth = allow all"
    // path accepts CONNECT packets that carry no username/password field, which is
    // what unauthenticated MQTT clients send.  Installing a handler forces rumqttd
    // to require a login field even when the handler would accept empty credentials.
    if allow_anonymous && passwd.is_empty() {
        return;
    }

    for (_, server) in servers.iter_mut() {
        let passwd = Arc::clone(&passwd);
        let tx = event_tx.clone();
        let bl = Arc::clone(&block_list);

        server.set_auth_handler(
            move |client_id: String, username: String, password: String| {
                let passwd = Arc::clone(&passwd);
                let tx = tx.clone();
                let bl = Arc::clone(&bl);

                async move {
                    // BlockList check — inference engine may have blocked this client
                    if bl.is_blocked(&username, &client_id) {
                        tracing::warn!(client_id, username, "connect rejected — blocked by inference engine");
                        emit(&tx, BrokerEvent::connect(client_id, username, false, "blocked"));
                        return false;
                    }

                    // Anonymous connect
                    if username.is_empty() {
                        if allow_anonymous {
                            tracing::debug!(client_id, "anonymous connect accepted");
                            emit(&tx, BrokerEvent::connect(client_id, String::new(), true, "anonymous"));
                            true
                        } else {
                            tracing::warn!(client_id, "anonymous connect rejected");
                            emit(&tx, BrokerEvent::connect(client_id, String::new(), false, "anon_denied"));
                            false
                        }
                    } else {
                        // Bcrypt credential check
                        let ok = passwd.verify(&username, &password);
                        if ok {
                            tracing::info!(client_id, username, "auth accepted");
                            emit(&tx, BrokerEvent::connect(client_id, username, true, "ok"));
                        } else {
                            tracing::warn!(client_id, username, "auth rejected — bad credentials");
                            emit(&tx, BrokerEvent::connect(client_id, username, false, "bad_credentials"));
                        }
                        ok
                    }
                }
            },
        );
    }
}

/// Non-blocking event emission. Drops the event if the channel is full rather
/// than blocking the auth handler.
fn emit(tx: &Option<mpsc::Sender<BrokerEvent>>, event: BrokerEvent) {
    if let Some(tx) = tx {
        let _ = tx.try_send(event);
    }
}

// ── Config builder ────────────────────────────────────────────────────────────

fn build_rumqttd_config(config: &MastConfig, max_connections: usize) -> Config {
    let router = RouterConfig {
        max_connections,
        max_outgoing_packet_count: config.max_queued_messages as u64,
        max_segment_size: 104_857_600,
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
        .unwrap_or_else(|_| format!("0.0.0.0:{}", listener.port).parse().unwrap());

        let tls = listener.tls.as_ref().and_then(|t| {
            let cert = t.certfile.as_ref()?.to_string_lossy().into_owned();
            let key = t.keyfile.as_ref()?.to_string_lossy().into_owned();
            let ca = if t.require_certificate {
                t.cafile.as_ref().map(|p| p.to_string_lossy().into_owned())
            } else {
                None
            };
            Some(TlsConfig::Rustls { capath: ca, certpath: cert, keypath: key })
        });

        let connections = ConnectionSettings {
            connection_timeout_ms: 5000,
            max_payload_size: 1_048_576,
            max_inflight_count: config.max_inflight_messages,
            auth: None,
            external_auth: None,
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
