use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::error::{MastError, Result};

// ── HF Inference API client ───────────────────────────────────────────────────

pub struct HfClient {
    http: Client,
    api_key: String,
    pub endpoint: String,
}

#[derive(Serialize)]
struct ZeroShotRequest<'a> {
    inputs: &'a str,
    parameters: ZeroShotParams,
}

#[derive(Serialize)]
struct ZeroShotParams {
    candidate_labels: Vec<String>,
    multi_label: bool,
}

#[derive(Deserialize, Debug)]
struct ZeroShotResponse {
    labels: Vec<String>,
    scores: Vec<f32>,
}

/// Result of one HF inference call.
pub struct AnalysisResult {
    /// Highest-confidence label.
    pub label: String,
    /// Confidence score (0.0–1.0) for the top label.
    pub score: f32,
    /// All labels + scores for logging.
    pub all: Vec<(String, f32)>,
}

/// Candidate labels for MQTT threat classification.
const LABELS: &[&str] = &[
    "normal activity",
    "brute force attack",
    "unauthorized device",
    "credential stuffing",
    "anomalous traffic",
];

impl HfClient {
    pub fn new(api_key: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            http: Client::new(),
            api_key: api_key.into(),
            endpoint: endpoint.into(),
        }
    }

    /// Call the HF zero-shot classification endpoint.
    pub async fn analyze(&self, prompt: &str) -> Result<AnalysisResult> {
        let req = ZeroShotRequest {
            inputs: prompt,
            parameters: ZeroShotParams {
                candidate_labels: LABELS.iter().map(|s| s.to_string()).collect(),
                multi_label: false,
            },
        };

        debug!(chars = prompt.len(), endpoint = %self.endpoint, "Calling HF inference");

        let resp = self.http
            .post(&self.endpoint)
            .bearer_auth(&self.api_key)
            .json(&req)
            .send()
            .await
            .map_err(|e| MastError::Inference(format!("HF request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!("HF API {} — {}", status, &body[..body.len().min(300)]);
            return Err(MastError::Inference(format!("HF API returned {}", status)));
        }

        let raw: ZeroShotResponse = resp.json().await
            .map_err(|e| MastError::Inference(format!("HF response parse error: {}", e)))?;

        let top_label = raw.labels.first().cloned().unwrap_or_default();
        let top_score = raw.scores.first().copied().unwrap_or(0.0);
        let all = raw.labels.into_iter().zip(raw.scores).collect();

        Ok(AnalysisResult { label: top_label, score: top_score, all })
    }
}
