use std::collections::HashSet;
use std::sync::RwLock;

// ── BlockList ─────────────────────────────────────────────────────────────────
//
// Dynamic deny-list written by the inference engine and checked by every
// incoming CONNECT in the auth handler.  Clients on this list are rejected
// immediately regardless of their credentials.

pub struct BlockList {
    usernames: RwLock<HashSet<String>>,
    client_ids: RwLock<HashSet<String>>,
}

impl BlockList {
    pub fn new() -> Self {
        Self {
            usernames: RwLock::new(HashSet::new()),
            client_ids: RwLock::new(HashSet::new()),
        }
    }

    /// Return true if either the username or the client_id is blocked.
    pub fn is_blocked(&self, username: &str, client_id: &str) -> bool {
        let u = self.usernames.read().unwrap();
        let c = self.client_ids.read().unwrap();
        (!username.is_empty() && u.contains(username)) || c.contains(client_id)
    }

    pub fn block_username(&self, username: &str) {
        self.usernames.write().unwrap().insert(username.to_string());
    }

    pub fn block_client(&self, client_id: &str) {
        self.client_ids.write().unwrap().insert(client_id.to_string());
    }

    #[allow(dead_code)]
    pub fn unblock_username(&self, username: &str) {
        self.usernames.write().unwrap().remove(username);
    }

    #[allow(dead_code)]
    pub fn unblock_client(&self, client_id: &str) {
        self.client_ids.write().unwrap().remove(client_id);
    }

    #[allow(dead_code)]
    pub fn blocked_usernames(&self) -> Vec<String> {
        self.usernames.read().unwrap().iter().cloned().collect()
    }

    #[allow(dead_code)]
    pub fn blocked_clients(&self) -> Vec<String> {
        self.client_ids.read().unwrap().iter().cloned().collect()
    }
}
