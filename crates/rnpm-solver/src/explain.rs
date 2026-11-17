//! npm's ERESOLVE explanation (lib/utils/explain-eresolve.js and
//! explain-dep.js) rendered from the solver graph, using the shape Arborist's
//! `Node#explain` and `Edge#explain` give it.

use crate::graph::{DependencyGraph, DependencyType};
use rnpm_core::spec::PackageTarget;

/// npm renders the terminal explanation at depth 4 and the report file at
/// depth Infinity.
pub const TERMINAL_DEPTH: usize = 4;
pub const REPORT_DEPTH: usize = usize::MAX;

/// Where an explained edge comes from.
#[derive(Debug, Clone)]
pub enum EdgeFrom {
    /// The project root: "the root project".
    Root,
    /// A node in the graph, explained with its valid incoming edges.
    Node(String),
    /// A node in an Arborist virtual peer-set tree: it sits at
    /// `node_modules/<name>` and its only dependent is the edge that loaded it.
    Virtual {
        name: String,
        version: String,
        incoming: Option<Box<EdgeView>>,
    },
}

#[derive(Debug, Clone)]
pub struct EdgeView {
    pub dep_type: DependencyType,
    pub name: String,
    pub spec: String,
    pub from: EdgeFrom,
}

/// A node to explain: a graph node, or a candidate that is not in the graph.
#[derive(Debug, Clone)]
pub enum Subject {
    Graph(String),
    Candidate {
        name: String,
        version: String,
        location: String,
        dependents: Vec<EdgeView>,
    },
}

/// The pieces of an Arborist ERESOLVE explanation object.
#[derive(Debug, Clone)]
pub struct Explanation {
    /// "could not resolve" (place-dep) or "unable to resolve dependency tree"
    /// (build-ideal-tree's peer set check).
    pub heading: &'static str,
    pub while_resolving: Option<String>,
    pub found: Subject,
    pub edge: EdgeView,
    pub conflict: Option<Subject>,
}

/// An explanation rendered for the terminal and for eresolve-report.txt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eresolve {
    pub heading: &'static str,
    pub explanation: String,
    pub report: String,
    pub strict_peer_deps: bool,
}

impl Explanation {
    pub fn render(&self, graph: &DependencyGraph, strict_peer_deps: bool) -> Eresolve {
        Eresolve {
            heading: self.heading,
            explanation: self.render_at(graph, TERMINAL_DEPTH),
            report: self.render_at(graph, REPORT_DEPTH),
            strict_peer_deps,
        }
    }

    pub fn render_at(&self, graph: &DependencyGraph, depth: usize) -> String {
        let r = Renderer { graph };
        let mut out = Vec::new();
        if let Some(while_resolving) = &self.while_resolving {
            out.push(format!("While resolving: {while_resolving}"));
        }
        out.push(format!("Found: {}", r.subject(&self.found, depth)));
        out.push(format!(
            "\nCould not resolve dependency:\n{}",
            r.edge(&self.edge, depth, &mut Vec::new())
        ));
        if let Some(conflict) = &self.conflict {
            out.push(format!(
                "\nConflicting peer dependency: {}",
                r.subject(conflict, depth)
            ));
        }
        out.join("\n")
    }
}

/// `name@version` of a graph node, as `printNode` shows the source of a
/// virtual tree (no location).
pub fn package_id(graph: &DependencyGraph, location: &str) -> Option<String> {
    graph
        .nodes
        .get(location)
        .map(|node| format!("{}@{}", node.name, node.version))
}

/// The edges Arborist lists as a node's dependents: its incoming edges,
/// skipping invalid ones unless they come from the root.
pub fn graph_dependents(graph: &DependencyGraph, location: &str) -> Vec<EdgeView> {
    let Some(target) = graph.nodes.get(location) else {
        return Vec::new();
    };
    graph
        .edges
        .iter()
        .filter(|edge| edge.to_location == location && edge.from_location != location)
        .filter(|edge| {
            edge.from_location == graph.root_location
                || PackageTarget::parse(&edge.spec)
                    .map_or(true, |t| crate::hoisting::node_satisfies_target(target, &t))
        })
        .map(|edge| {
            graph_edge(
                graph,
                &edge.from_location,
                edge.dep_type,
                &edge.install_name,
                &edge.spec,
            )
        })
        .collect()
}

pub fn graph_edge(
    graph: &DependencyGraph,
    from_location: &str,
    dep_type: DependencyType,
    name: &str,
    spec: &str,
) -> EdgeView {
    EdgeView {
        dep_type,
        name: name.to_string(),
        spec: spec.to_string(),
        from: if from_location == graph.root_location {
            EdgeFrom::Root
        } else {
            EdgeFrom::Node(from_location.to_string())
        },
    }
}

fn type_name(dep_type: DependencyType) -> &'static str {
    match dep_type {
        DependencyType::Prod => "prod",
        DependencyType::Dev => "dev",
        DependencyType::Optional => "optional",
        DependencyType::Peer => "peer",
        DependencyType::PeerOptional => "peerOptional",
    }
}

/// Indents every line after the first by two spaces, as explain-dep's
/// `str.split('\n').join('\n  ')` does.
fn indent(lines: &[String]) -> String {
    let joined = format!("\n{}", lines.join("\n"));
    joined.replace('\n', "\n  ")
}

struct Renderer<'g> {
    graph: &'g DependencyGraph,
}

impl Renderer<'_> {
    fn subject(&self, subject: &Subject, depth: usize) -> String {
        match subject {
            Subject::Graph(location) => self.graph_node(location, depth, &mut Vec::new()),
            Subject::Candidate {
                name,
                version,
                location,
                dependents,
            } => format!(
                "{name}@{version}\n{location}{}",
                self.dependents(dependents, depth, &mut Vec::new())
            ),
        }
    }

    /// explainNode on a graph node. `path` is the chain of nodes being
    /// explained: Node#explain gives a node already on it no location and no
    /// dependents, which is how cycles end.
    fn graph_node(&self, location: &str, depth: usize, path: &mut Vec<String>) -> String {
        let Some(node) = self.graph.nodes.get(location) else {
            return String::new();
        };
        let name = &node.install_name;
        if path.iter().any(|p| p == location) {
            return format!("{name}@{}", node.version);
        }
        path.push(location.to_string());
        let dependents = graph_dependents(self.graph, location);
        let out = format!(
            "{name}@{}\n{location}{}",
            node.version,
            self.dependents(&dependents, depth, path)
        );
        path.pop();
        out
    }

    fn dependents(&self, dependents: &[EdgeView], depth: usize, path: &mut Vec<String>) -> String {
        if dependents.is_empty() || depth == 0 {
            return String::new();
        }
        let max = depth / 2 + depth % 2;
        let mut messages: Vec<String> = dependents
            .iter()
            .take(max)
            .map(|edge| self.edge(edge, depth, path))
            .collect();
        if dependents.len() > max {
            let mut len = 0;
            let mut names = Vec::new();
            for (i, edge) in dependents.iter().enumerate().skip(max) {
                let name = match &edge.from {
                    EdgeFrom::Root => "the root project".to_string(),
                    EdgeFrom::Node(location) => self
                        .graph
                        .nodes
                        .get(location)
                        .map(|n| n.install_name.clone())
                        .unwrap_or_default(),
                    EdgeFrom::Virtual { name, .. } => name.clone(),
                };
                len += name.encode_utf16().count();
                if len >= 50 && i < dependents.len() - 1 {
                    names.push("...".to_string());
                    break;
                }
                names.push(name);
            }
            messages.push(format!(
                "{} more ({})",
                dependents.len() - max,
                names.join(", ")
            ));
        }
        indent(&messages)
    }

    fn edge(&self, edge: &EdgeView, depth: usize, path: &mut Vec<String>) -> String {
        let prefix = if edge.dep_type == DependencyType::Prod {
            String::new()
        } else {
            format!("{} ", type_name(edge.dep_type))
        };
        format!(
            "{prefix}{}@\"{}\" from {}",
            edge.name,
            edge.spec,
            self.from(&edge.from, depth, path)
        )
    }

    fn from(&self, from: &EdgeFrom, depth: usize, path: &mut Vec<String>) -> String {
        let below = depth.saturating_sub(1);
        match from {
            EdgeFrom::Root => "the root project".to_string(),
            EdgeFrom::Node(location) => {
                if path.iter().any(|p| p == location) {
                    return self
                        .graph
                        .nodes
                        .get(location)
                        .map(|n| format!("{}@{}", n.install_name, n.version))
                        .unwrap_or_default();
                }
                self.graph_node(location, below, path)
            }
            EdgeFrom::Virtual {
                name,
                version,
                incoming,
            } => {
                let dependents: Vec<EdgeView> = incoming.iter().map(|e| (**e).clone()).collect();
                format!(
                    "{name}@{version}\nnode_modules/{name}{}",
                    self.dependents(&dependents, below, path)
                )
            }
        }
    }
}

/// npm's fix line, from explain-eresolve's `report`.
pub fn fix_line(strict_peer_deps: bool) -> String {
    let flags: Vec<&str> = [
        strict_peer_deps.then_some("--no-strict-peer-deps"),
        Some("--force"),
        Some("--legacy-peer-deps"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let or = if flags.len() <= 2 {
        flags.join(" or ")
    } else {
        let last = flags.len() - 1;
        flags
            .iter()
            .enumerate()
            .map(|(i, f)| {
                if i == last {
                    format!("or {f}")
                } else {
                    f.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!("Fix the upstream dependency conflict, or retry this command with {or} to accept an incorrect (and potentially broken) dependency resolution.")
}
