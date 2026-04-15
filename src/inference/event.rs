use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

/// An event emitted by the broker that the inference engine observes.
#[derive(Debug, Clone)]
pub enum BrokerEvent {
    /// MQTT CONNECT processed (auth accepted or rejected).
    Connect {
        client_id: String,
        username: String,
        allowed: bool,
        #[allow(dead_code)]
        reason: &'static str,
        ts: SystemTime,
    },
    /// Message published to a topic (seen via internal broker link).
    Publish {
        topic: String,
        #[allow(dead_code)]
        payload_len: usize,
        ts: SystemTime,
    },
}

impl BrokerEvent {
    pub fn connect(
        client_id: String,
        username: String,
        allowed: bool,
        reason: &'static str,
    ) -> Self {
        Self::Connect { client_id, username, allowed, reason, ts: SystemTime::now() }
    }

    pub fn publish(topic: String, payload_len: usize) -> Self {
        Self::Publish { topic, payload_len, ts: SystemTime::now() }
    }

    #[allow(dead_code)]
    pub fn ts(&self) -> SystemTime {
        match self {
            Self::Connect { ts, .. } | Self::Publish { ts, .. } => *ts,
        }
    }
}

// ── Event window ──────────────────────────────────────────────────────────────

/// Bounded rolling window of recent broker events fed to the HF model.
pub struct EventWindow {
    events: Vec<BrokerEvent>,
    max_size: usize,
}

impl EventWindow {
    pub fn new(max_size: usize) -> Self {
        Self { events: Vec::with_capacity(max_size), max_size }
    }

    pub fn push(&mut self, event: BrokerEvent) {
        if self.events.len() >= self.max_size {
            self.events.remove(0);
        }
        self.events.push(event);
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Number of auth failures in the last `window_secs` seconds.
    pub fn auth_fail_count(&self, window_secs: u64) -> usize {
        let cutoff = cutoff(window_secs);
        self.events.iter().filter(|e| {
            matches!(e, BrokerEvent::Connect { allowed: false, ts, .. } if *ts >= cutoff)
        }).count()
    }

    /// Per (client_id, username) failure counts within the window.
    pub fn fail_summary(&self, window_secs: u64) -> Vec<(String, String, usize)> {
        let cutoff = cutoff(window_secs);
        let mut counts: HashMap<(String, String), usize> = HashMap::new();
        for e in &self.events {
            if let BrokerEvent::Connect { client_id, username, allowed: false, ts, .. } = e {
                if *ts >= cutoff {
                    *counts.entry((client_id.clone(), username.clone())).or_default() += 1;
                }
            }
        }
        counts.into_iter().map(|((c, u), n)| (c, u, n)).collect()
    }

    /// Top 10 topics by publish count within the window.
    pub fn topic_summary(&self, window_secs: u64) -> Vec<(String, usize)> {
        let cutoff = cutoff(window_secs);
        let mut counts: HashMap<String, usize> = HashMap::new();
        for e in &self.events {
            if let BrokerEvent::Publish { topic, ts, .. } = e {
                if *ts >= cutoff {
                    *counts.entry(topic.clone()).or_default() += 1;
                }
            }
        }
        let mut v: Vec<_> = counts.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(10);
        v
    }

    /// Build a natural-language prompt for HF zero-shot classification.
    pub fn to_prompt(&self, window_secs: u64) -> String {
        let cutoff = cutoff(window_secs);

        let connects: Vec<_> = self.events.iter().filter(|e| {
            matches!(e, BrokerEvent::Connect { ts, .. } if *ts >= cutoff)
        }).collect();
        let ok_count = connects.iter().filter(|e| {
            matches!(e, BrokerEvent::Connect { allowed: true, .. })
        }).count();
        let fail_count = connects.len() - ok_count;

        let unique_clients: HashSet<&str> = connects.iter().filter_map(|e| {
            if let BrokerEvent::Connect { client_id, .. } = e { Some(client_id.as_str()) } else { None }
        }).collect();

        let fails = self.fail_summary(window_secs);
        let topics = self.topic_summary(window_secs);

        let mut parts = vec![format!(
            "MQTT broker activity (last {}s): {} connection attempts ({} accepted, {} rejected), {} unique client IDs.",
            window_secs,
            connects.len(),
            ok_count,
            fail_count,
            unique_clients.len(),
        )];

        if !fails.is_empty() {
            parts.push("Authentication failures:".into());
            for (cid, usr, cnt) in &fails {
                parts.push(format!("  client='{}' user='{}' failed {} times.", cid, usr, cnt));
            }
        }

        if !topics.is_empty() {
            let ts: Vec<String> = topics.iter()
                .map(|(t, c)| format!("{}({}x)", t, c))
                .collect();
            parts.push(format!("Active topics: {}.", ts.join(", ")));
        }

        parts.join(" ")
    }
}

fn cutoff(window_secs: u64) -> SystemTime {
    SystemTime::now()
        .checked_sub(Duration::from_secs(window_secs))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}
