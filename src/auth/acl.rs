use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::error::{MastError, Result};

// ── Access level ─────────────────────────────────────────────────────────────

// ACL check methods are scaffolded for v2 enforcement once rumqttd exposes
// publish/subscribe hooks.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum AclAccess {
    Read,
    Write,
    ReadWrite,
    Deny,
}

impl AclAccess {
    fn allows_read(&self) -> bool {
        matches!(self, AclAccess::Read | AclAccess::ReadWrite)
    }

    fn allows_write(&self) -> bool {
        matches!(self, AclAccess::Write | AclAccess::ReadWrite)
    }
}

// ── Single rule ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AclRule {
    /// MQTT topic filter; pattern rules use %u / %c before matching.
    filter: String,
    access: AclAccess,
}

// ── Store ─────────────────────────────────────────────────────────────────────

/// Parsed ACL store.
///
/// Mosquitto ACL file format:
/// ```text
/// # Global rules (apply to every authenticated user)
/// topic read $SYS/#
///
/// # Anonymous rules (no-username clients)
/// # (introduced by a bare `user` line with no argument — non-standard extension)
///
/// # Per-user rules
/// user admin
/// topic readwrite #
///
/// # Pattern rules — %u = username, %c = client_id
/// pattern write sensors/%u/#
/// pattern read  commands/%u/#
/// ```
///
/// **v1 note:** rumqttd 0.20 exposes no publish/subscribe hooks, so ACL is
/// parsed and stored but only enforced at the application layer.  The
/// `check_read` / `check_write` methods are ready for use once a hook is
/// available (e.g. via a future rumqttd release or a sidecar proxy).
pub struct AclStore {
    /// Rules with no preceding `user` directive — apply to all authenticated users.
    global: Vec<AclRule>,
    /// Per-user rule sets.
    users: HashMap<String, Vec<AclRule>>,
    /// Pattern rules (contain %u / %c substitution tokens).
    patterns: Vec<AclRule>,
}

impl AclStore {
    /// Open ACL: every topic is readable and writable by everyone.
    /// Used when no acl_file is configured.
    pub fn open() -> Self {
        Self {
            global: vec![AclRule {
                filter: "#".to_string(),
                access: AclAccess::ReadWrite,
            }],
            users: HashMap::new(),
            patterns: vec![],
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|e| MastError::Config(format!("Cannot read ACL file {:?}: {}", path, e)))?;

        let mut store = AclStore {
            global: vec![],
            users: HashMap::new(),
            patterns: vec![],
        };

        // None  → global context
        // Some(name) → user-specific context
        let mut current_user: Option<String> = None;
        let mut in_pattern = false;

        for (idx, raw) in content.lines().enumerate() {
            let line_num = idx + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (kw, rest) = split_kv(line);

            match kw {
                "user" => {
                    in_pattern = false;
                    current_user = Some(rest.to_string());
                }
                "pattern" => {
                    in_pattern = true;
                    current_user = None;
                    if let Some(rule) = parse_topic_line(rest, line_num)? {
                        store.patterns.push(rule);
                    }
                }
                "topic" => {
                    if in_pattern {
                        if let Some(rule) = parse_topic_line(rest, line_num)? {
                            store.patterns.push(rule);
                        }
                    } else {
                        let rule = match parse_topic_line(rest, line_num)? {
                            Some(r) => r,
                            None => continue,
                        };
                        match &current_user {
                            None => store.global.push(rule),
                            Some(u) => store.users.entry(u.clone()).or_default().push(rule),
                        }
                    }
                }
                other => {
                    tracing::debug!(
                        "Unknown ACL directive '{}' at line {} — ignored",
                        other,
                        line_num
                    );
                }
            }
        }

        Ok(store)
    }

    // ── Check helpers ─────────────────────────────────────────────────────────

    #[allow(dead_code)]
    pub fn check_read(&self, username: Option<&str>, client_id: &str, topic: &str) -> bool {
        self.check(username, client_id, topic, AclAccess::allows_read)
    }

    #[allow(dead_code)]
    pub fn check_write(&self, username: Option<&str>, client_id: &str, topic: &str) -> bool {
        self.check(username, client_id, topic, AclAccess::allows_write)
    }

    fn check(
        &self,
        username: Option<&str>,
        client_id: &str,
        topic: &str,
        allows: fn(&AclAccess) -> bool,
    ) -> bool {
        let uname = username.unwrap_or("");

        // Pattern rules have highest priority
        for rule in &self.patterns {
            let resolved = rule.filter.replace("%u", uname).replace("%c", client_id);
            if topic_matches(&resolved, topic) {
                return allows(&rule.access);
            }
        }

        // User-specific rules
        if let Some(user) = username {
            if let Some(rules) = self.users.get(user) {
                for rule in rules {
                    if topic_matches(&rule.filter, topic) {
                        return allows(&rule.access);
                    }
                }
            }
        }

        // Global rules
        for rule in &self.global {
            if topic_matches(&rule.filter, topic) {
                return allows(&rule.access);
            }
        }

        // Default deny
        false
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_topic_line(rest: &str, line_num: usize) -> Result<Option<AclRule>> {
    // rest is either:
    //   "read <filter>"   / "write <filter>" / "readwrite <filter>" / "none <filter>"
    //   or just "<filter>"  (implies readwrite)
    let (first, second) = split_kv(rest);

    let (access, filter) = match first {
        "read" => (AclAccess::Read, second),
        "write" => (AclAccess::Write, second),
        "readwrite" => (AclAccess::ReadWrite, second),
        "none" => (AclAccess::Deny, second),
        // No keyword — whole thing is the filter, access defaults to readwrite
        filter => (AclAccess::ReadWrite, filter),
    };

    if filter.is_empty() {
        tracing::warn!("Empty topic filter at line {} — ignored", line_num);
        return Ok(None);
    }

    Ok(Some(AclRule {
        filter: filter.to_string(),
        access,
    }))
}

fn split_kv(line: &str) -> (&str, &str) {
    match line.find(char::is_whitespace) {
        Some(pos) => (&line[..pos], line[pos..].trim()),
        None => (line, ""),
    }
}

/// MQTT topic filter matching.
/// - `+`  matches exactly one level segment
/// - `#`  matches zero or more remaining levels (must be final segment)
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    fn go(f: &[&str], t: &[&str]) -> bool {
        match (f.first(), t.first()) {
            (Some(&"#"), _) => true,
            (Some(&"+"), Some(_)) => go(&f[1..], &t[1..]),
            (Some(a), Some(b)) if a == b => go(&f[1..], &t[1..]),
            (None, None) => true,
            _ => false,
        }
    }
    let fp: Vec<&str> = filter.split('/').collect();
    let tp: Vec<&str> = topic.split('/').collect();
    go(&fp, &tp)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_hash_matches_any() {
        assert!(topic_matches("#", "a/b/c"));
        assert!(topic_matches("#", "a"));
        assert!(topic_matches("a/#", "a/b/c"));
        assert!(topic_matches("a/#", "a"));
    }

    #[test]
    fn wildcard_plus_matches_single_level() {
        assert!(topic_matches("a/+/c", "a/b/c"));
        assert!(!topic_matches("a/+/c", "a/b/d"));
        assert!(!topic_matches("a/+/c", "a/b/b/c"));
    }

    #[test]
    fn exact_match() {
        assert!(topic_matches("a/b/c", "a/b/c"));
        assert!(!topic_matches("a/b/c", "a/b/d"));
    }

    #[test]
    fn acl_store_open_allows_all() {
        let store = AclStore::open();
        assert!(store.check_read(Some("alice"), "c1", "any/topic"));
        assert!(store.check_write(Some("alice"), "c1", "any/topic"));
        assert!(store.check_read(None, "c1", "any/topic"));
    }
}
