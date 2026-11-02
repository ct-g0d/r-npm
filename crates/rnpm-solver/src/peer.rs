use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Context tracker for detecting and breaking cyclic peer dependency relationships of any depth.
#[derive(Debug, Clone, Default)]
pub struct PeerContext {
    /// Active peer edges: dependent_package -> set of peer_packages being resolved
    active_graph: BTreeMap<String, BTreeSet<String>>,
}

impl PeerContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if adding a peer dependency edge from `dependent` to `peer` creates a cycle.
    ///
    /// Detects self-cycles (A -> A), 2-node cycles (A -> B -> A), and multi-node cycles (A -> B -> C -> A).
    pub fn is_cycle(&self, dependent: &str, peer: &str) -> bool {
        if dependent == peer {
            return true;
        }

        // Cycle exists if `dependent` is reachable from `peer` in the active peer graph
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(peer);
        visited.insert(peer);

        while let Some(curr) = queue.pop_front() {
            if curr == dependent {
                return true;
            }
            if let Some(neighbors) = self.active_graph.get(curr) {
                for next in neighbors {
                    if visited.insert(next.as_str()) {
                        queue.push_back(next.as_str());
                    }
                }
            }
        }

        false
    }

    /// Finds the cycle path from `dependent` to `peer` and back to `dependent`, if one exists.
    ///
    /// Returns e.g. `vec!["A", "B", "C", "A"]`.
    pub fn find_cycle_path(&self, dependent: &str, peer: &str) -> Option<Vec<String>> {
        if dependent == peer {
            return Some(vec![dependent.to_string(), dependent.to_string()]);
        }

        // BFS with predecessor map to reconstruct shortest path from `peer` to `dependent`
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        let mut parent_map: BTreeMap<&str, &str> = BTreeMap::new();

        queue.push_back(peer);
        visited.insert(peer);

        let mut found = false;
        while let Some(curr) = queue.pop_front() {
            if curr == dependent {
                found = true;
                break;
            }
            if let Some(neighbors) = self.active_graph.get(curr) {
                for next in neighbors {
                    if visited.insert(next.as_str()) {
                        parent_map.insert(next.as_str(), curr);
                        queue.push_back(next.as_str());
                    }
                }
            }
        }

        if !found {
            return None;
        }

        // Reconstruct path: peer -> ... -> dependent
        let mut path = Vec::new();
        let mut curr = dependent;
        path.push(curr.to_string());
        while curr != peer {
            if let Some(&p) = parent_map.get(curr) {
                path.push(p.to_string());
                curr = p;
            } else {
                break;
            }
        }
        path.reverse();

        // Cycle path starts at `dependent`, goes through `path`, and ends at `dependent`
        let mut full_cycle = Vec::with_capacity(path.len() + 1);
        full_cycle.push(dependent.to_string());
        full_cycle.extend(path);
        Some(full_cycle)
    }

    /// Mark a peer edge as actively being resolved.
    pub fn enter(&mut self, dependent: &str, peer: &str) {
        self.active_graph
            .entry(dependent.to_string())
            .or_default()
            .insert(peer.to_string());
    }

    /// Mark a peer edge as finished.
    pub fn leave(&mut self, dependent: &str, peer: &str) {
        if let Some(set) = self.active_graph.get_mut(dependent) {
            set.remove(peer);
            if set.is_empty() {
                self.active_graph.remove(dependent);
            }
        }
    }

    /// Checks if there are any active peer edges currently tracked.
    pub fn is_empty(&self) -> bool {
        self.active_graph.is_empty()
    }

    /// Clears all active peer edges.
    pub fn clear(&mut self) {
        self.active_graph.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_cycle_detection() {
        let mut ctx = PeerContext::new();
        assert!(!ctx.is_cycle("react", "react-dom"));

        // 2-node cycle: react-dom -> react
        ctx.enter("react-dom", "react");
        assert!(ctx.is_cycle("react", "react-dom"));

        ctx.leave("react-dom", "react");
        assert!(!ctx.is_cycle("react", "react-dom"));

        // Self-cycle: A -> A
        assert!(ctx.is_cycle("a", "a"));
        assert_eq!(ctx.find_cycle_path("a", "a"), Some(vec!["a".to_string(), "a".to_string()]));

        // 3-node cycle: A -> B -> C -> A
        ctx.enter("a", "b");
        ctx.enter("b", "c");
        assert!(!ctx.is_cycle("a", "c")); // A -> C is forward, not cyclic
        assert!(ctx.is_cycle("c", "a"));  // C -> A completes cycle A -> B -> C -> A!
        let cycle_path = ctx.find_cycle_path("c", "a").unwrap();
        assert_eq!(cycle_path, vec!["c", "a", "b", "c"]);

        // Diamond / non-cyclic: A -> B -> D, A -> C -> D
        let mut diamond_ctx = PeerContext::new();
        diamond_ctx.enter("a", "b");
        diamond_ctx.enter("a", "c");
        diamond_ctx.enter("b", "d");
        diamond_ctx.enter("c", "d");
        assert!(!diamond_ctx.is_cycle("a", "d"));
        assert!(!diamond_ctx.is_cycle("b", "c"));
        assert!(diamond_ctx.is_cycle("d", "a"));
    }
}
