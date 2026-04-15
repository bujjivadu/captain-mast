use std::sync::Arc;
use std::time::Duration;

use rumqttd::local::{LinkRx, LinkTx};
use rumqttd::{Forward, Notification};
use tokio::sync::mpsc::Receiver;
use tokio::time::interval;
use tracing::{info, warn};

use super::client::HfClient;
use super::event::{BrokerEvent, EventWindow};
use crate::broker::BlockList;
use crate::config::InferenceConfig;

// ── Monitor ───────────────────────────────────────────────────────────────────

pub struct Monitor {
    /// Auth/connect events from the broker auth handler.
    auth_rx: Receiver<BrokerEvent>,
    /// Keep alive: dropping LinkTx disconnects the internal link.
    _link_tx: LinkTx,
    /// Internal broker link — receives all published messages.
    link_rx: LinkRx,
    hf: HfClient,
    window: EventWindow,
    block_list: Arc<BlockList>,
    analysis_interval: Duration,
    threshold: f32,
    window_secs: u64,
}

impl Monitor {
    pub fn new(
        auth_rx: Receiver<BrokerEvent>,
        link_tx: LinkTx,
        link_rx: LinkRx,
        cfg: &InferenceConfig,
        block_list: Arc<BlockList>,
    ) -> Self {
        let endpoint = cfg.endpoint.clone().unwrap_or_else(|| {
            format!(
                "https://api-inference.huggingface.co/models/{}",
                cfg.model
            )
        });

        Self {
            auth_rx,
            _link_tx: link_tx,
            link_rx,
            hf: HfClient::new(cfg.api_key.clone(), endpoint),
            window: EventWindow::new(2000),
            block_list,
            analysis_interval: Duration::from_secs(cfg.analysis_interval_secs),
            threshold: cfg.threat_threshold,
            window_secs: cfg.analysis_interval_secs,
        }
    }

    pub async fn run(mut self) {
        info!(
            endpoint = %self.hf.endpoint,
            interval_secs = self.window_secs,
            threshold = self.threshold,
            "Inference monitor started"
        );

        // Signal the router that the internal link is ready to receive.
        let _ = self.link_rx.ready();

        let mut tick = interval(self.analysis_interval);
        let mut should_analyze = false;

        loop {
            tokio::select! {
                // Auth/connect event from broker auth handler
                event = self.auth_rx.recv() => {
                    match event {
                        Some(e) => {
                            let is_fail = matches!(&e, BrokerEvent::Connect { allowed: false, .. });
                            self.window.push(e);
                            // Trigger immediate analysis on auth failure burst (≥5 in 60s)
                            if is_fail && self.window.auth_fail_count(60) >= 5 {
                                warn!("Auth failure burst detected — triggering immediate inference");
                                should_analyze = true;
                            }
                        }
                        None => {
                            // Auth channel closed — broker is shutting down
                            info!("Auth event channel closed, monitor stopping");
                            return;
                        }
                    }
                }

                // Published message from internal broker link
                notification = self.link_rx.next() => {
                    match notification {
                        Ok(Some(Notification::Forward(Forward { publish, .. }))) => {
                            let topic = String::from_utf8_lossy(&publish.topic).into_owned();
                            self.window.push(BrokerEvent::publish(
                                topic,
                                publish.payload.len(),
                            ));
                            // Signal readiness for next batch
                            let _ = self.link_rx.ready();
                        }
                        Ok(Some(_)) => {
                            // Other notification types (DeviceAck, etc.) — ignored
                            let _ = self.link_rx.ready();
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!("Internal broker link error: {} — topic monitoring paused", e);
                            // Don't kill the whole monitor over a link error; auth events
                            // continue flowing. The link will reconnect on next broker restart.
                            return;
                        }
                    }
                }

                // Periodic full analysis
                _ = tick.tick() => {
                    if !self.window.is_empty() {
                        should_analyze = true;
                    }
                }
            }

            if should_analyze {
                should_analyze = false;
                self.analyze().await;
            }
        }
    }

    async fn analyze(&mut self) {
        let prompt = self.window.to_prompt(self.window_secs);
        tracing::debug!(chars = prompt.len(), "Sending event window to HF model");

        match self.hf.analyze(&prompt).await {
            Ok(result) => {
                let scores: Vec<String> = result.all.iter()
                    .map(|(l, s)| format!("{}: {:.0}%", l, s * 100.0))
                    .collect();
                tracing::debug!("HF scores: [{}]", scores.join(" | "));

                let is_threat = result.label != "normal activity"
                    && result.score >= self.threshold;

                if is_threat {
                    warn!(
                        label = %result.label,
                        confidence = format!("{:.0}%", result.score * 100.0),
                        "Threat detected — applying corrective action"
                    );
                    self.enforce(&result.label);
                } else {
                    info!(
                        label = %result.label,
                        confidence = format!("{:.0}%", result.score * 100.0),
                        "Inference: normal activity"
                    );
                }
            }
            Err(e) => {
                warn!("HF inference failed: {} — no action taken", e);
            }
        }
    }

    /// Block clients responsible for repeated failures.
    fn enforce(&self, threat_label: &str) {
        let fails = self.window.fail_summary(self.window_secs);
        let mut acted = false;

        for (client_id, username, count) in &fails {
            if *count >= 3 {
                warn!(
                    %client_id,
                    %username,
                    failures = count,
                    threat = threat_label,
                    "Blocking client due to repeated auth failures"
                );
                if !username.is_empty() {
                    self.block_list.block_username(username);
                }
                self.block_list.block_client(client_id);
                acted = true;
            }
        }

        if !acted {
            warn!(
                threat = threat_label,
                "Threat classified but no specific offender found — logged only"
            );
        }
    }
}
