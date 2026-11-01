use std::collections::HashSet;

/// Context tracker for detecting and breaking cyclic peer dependency relationships.
#[derive(Debug, Clone, Default)]
pub struct PeerContext {
    /// Active peer edges currently undergoing resolution: (dependent, peer)
    active_edges: HashSet<(String, String)>,
}

impl PeerContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if a peer dependency edge forms a cycle with an already active resolution.
    pub fn is_cycle(&self, dependent: &str, peer: &str) -> bool {
        self.active_edges.contains(&(peer.to_string(), dependent.to_string()))
            || self.active_edges.contains(&(dependent.to_string(), peer.to_string()))
    }

    /// Mark a peer edge as actively being resolved.
    pub fn enter(&mut self, dependent: &str, peer: &str) {
        self.active_edges.insert((dependent.to_string(), peer.to_string()));
    }

    /// Mark a peer edge as finished.
    pub fn leave(&mut self, dependent: &str, peer: &str) {
        self.active_edges.remove(&(dependent.to_string(), peer.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_cycle_detection() {
        let mut ctx = PeerContext::new();
        assert!(!ctx.is_cycle("react", "react-dom"));

        ctx.enter("react-dom", "react");
        assert!(ctx.is_cycle("react", "react-dom"));

        ctx.leave("react-dom", "react");
        assert!(!ctx.is_cycle("react", "react-dom"));
    }
}
