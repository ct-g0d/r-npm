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
        self.is_cycle_with_alias(dependent, None, peer, None)
    }

    /// Checks if adding a peer dependency edge creates a cycle, considering optional aliases.
    pub fn is_cycle_with_alias(
        &self,
        dependent: &str,
        dep_alias: Option<&str>,
        peer: &str,
        peer_alias: Option<&str>,
    ) -> bool {
        let dep_matches = |name: &str| -> bool {
            name == dependent || dep_alias.map_or(false, |a| a == name)
        };

        if dep_matches(peer) || peer_alias.map_or(false, |pa| dep_matches(pa)) {
            return true;
        }

        // Cycle exists if `dependent` (or alias) is reachable from `peer` (or alias) in active graph
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(peer);
        visited.insert(peer);
        if let Some(pa) = peer_alias {
            if visited.insert(pa) {
                queue.push_back(pa);
            }
        }

        while let Some(curr) = queue.pop_front() {
            if dep_matches(curr) {
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
        self.find_cycle_path_with_alias(dependent, None, peer, None)
    }

    /// Finds the cycle path from `dependent` to `peer` and back to `dependent`, considering optional aliases.
    pub fn find_cycle_path_with_alias(
        &self,
        dependent: &str,
        dep_alias: Option<&str>,
        peer: &str,
        peer_alias: Option<&str>,
    ) -> Option<Vec<String>> {
        let dep_matches = |name: &str| -> bool {
            name == dependent || dep_alias.map_or(false, |a| a == name)
        };

        if dep_matches(peer) {
            return Some(vec![dependent.to_string(), peer.to_string()]);
        }
        if let Some(pa) = peer_alias {
            if dep_matches(pa) {
                return Some(vec![dependent.to_string(), pa.to_string()]);
            }
        }

        // BFS with predecessor map to reconstruct shortest path from `peer` (or alias) to `dependent`
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        let mut parent_map: BTreeMap<&str, &str> = BTreeMap::new();

        queue.push_back(peer);
        visited.insert(peer);
        if let Some(pa) = peer_alias {
            if visited.insert(pa) {
                queue.push_back(pa);
            }
        }

        let mut matched_target = None;
        while let Some(curr) = queue.pop_front() {
            if dep_matches(curr) {
                matched_target = Some(curr);
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

        let target = matched_target?;

        // Reconstruct path: peer -> ... -> target
        let mut path = Vec::new();
        let mut curr = target;
        path.push(curr.to_string());
        while curr != peer && peer_alias.map_or(true, |pa| curr != pa) {
            if let Some(&p) = parent_map.get(curr) {
                path.push(p.to_string());
                curr = p;
            } else {
                break;
            }
        }
        path.reverse();

        // Cycle path starts at `dependent`, goes through `path`, and ends at `target`
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

    #[test]
    fn test_peer_cycle_detection_with_alias() {
        let mut ctx = PeerContext::new();
        // react-dom peers aliased package "my-react"
        ctx.enter("react-dom", "my-react");
        // Check cycle from "react" (whose alias is "my-react") back to "react-dom"
        assert!(ctx.is_cycle_with_alias("react", Some("my-react"), "react-dom", None));
        let path = ctx
            .find_cycle_path_with_alias("react", Some("my-react"), "react-dom", None)
            .unwrap();
        assert_eq!(path, vec!["react", "react-dom", "my-react"]);
    }
}
