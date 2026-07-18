use std::collections::{BTreeMap, HashSet};

use serde::Serialize;

use super::dep_tree::{DependencyGraph, NodeInfo};
use crate::api_types::StringRecordDto;

const DEFAULT_MAX_KEY_STEPS: usize = 200;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisKeyStep {
    pub seq: u32,
    pub end_seq: u32,
    pub operation: String,
    pub expression: String,
    pub transport_count: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisOperationCount {
    pub operation: String,
    pub count: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisStringEvidence {
    pub content: String,
    pub addr: String,
    pub seq: u32,
    pub byte_len: u32,
    pub encoding: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyAnalysisSummary {
    pub root_seq: u32,
    pub dependency_nodes: u32,
    pub input_leaf_count: u32,
    pub truncated: bool,
    pub operations: Vec<AnalysisOperationCount>,
    pub functions: Vec<String>,
    pub modules: Vec<String>,
    pub memory_reads: Vec<String>,
    pub memory_writes: Vec<String>,
    pub key_strings: Vec<AnalysisStringEvidence>,
    pub key_steps: Vec<AnalysisKeyStep>,
}

pub fn summarize_dependency_graph(
    graph: &DependencyGraph,
    strings: &[StringRecordDto],
    max_key_steps: Option<u32>,
) -> DependencyAnalysisSummary {
    let mut operation_counts = BTreeMap::<String, u32>::new();
    for node in &graph.nodes {
        let operation = if node.operation.is_empty() {
            "unknown"
        } else {
            node.operation.as_str()
        };
        *operation_counts.entry(operation.to_string()).or_default() += 1;
    }
    let mut operations: Vec<_> = operation_counts
        .into_iter()
        .map(|(operation, count)| AnalysisOperationCount { operation, count })
        .collect();
    operations.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.operation.cmp(&right.operation))
    });
    operations.truncate(12);

    DependencyAnalysisSummary {
        root_seq: graph.root_seq,
        dependency_nodes: graph.total_reachable,
        input_leaf_count: graph.nodes.iter().filter(|node| node.is_leaf).count() as u32,
        truncated: graph.truncated,
        operations,
        functions: unique_values(
            graph
                .nodes
                .iter()
                .filter_map(|node| node.function_name.as_deref()),
            12,
        ),
        modules: unique_values(
            graph.nodes.iter().filter_map(|node| node.module.as_deref()),
            12,
        ),
        memory_reads: unique_values(
            graph
                .nodes
                .iter()
                .filter(|node| node.mem_rw.as_deref().is_some_and(|rw| rw.contains('R')))
                .filter_map(|node| node.mem_addr.as_deref()),
            16,
        ),
        memory_writes: unique_values(
            graph
                .nodes
                .iter()
                .filter(|node| node.mem_rw.as_deref().is_some_and(|rw| rw.contains('W')))
                .filter_map(|node| node.mem_addr.as_deref()),
            16,
        ),
        key_strings: related_strings(&graph.nodes, strings),
        key_steps: build_key_steps(
            &graph.nodes,
            max_key_steps.unwrap_or(DEFAULT_MAX_KEY_STEPS as u32) as usize,
        ),
    }
}

fn unique_values<'a>(values: impl Iterator<Item = &'a str>, limit: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for value in values {
        if seen.insert(value) {
            output.push(value.to_string());
            if output.len() >= limit {
                break;
            }
        }
    }
    output
}

fn parse_address(value: &str) -> Option<u64> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u64::from_str_radix(value, 16).ok()
}

fn related_strings(nodes: &[NodeInfo], strings: &[StringRecordDto]) -> Vec<AnalysisStringEvidence> {
    let addresses: Vec<u64> = nodes
        .iter()
        .filter_map(|node| node.mem_addr.as_deref())
        .filter_map(parse_address)
        .collect();
    let mut output = Vec::new();
    for record in strings {
        let Some(start) = parse_address(&record.addr) else {
            continue;
        };
        let end = start.saturating_add(record.byte_len as u64);
        if addresses
            .iter()
            .any(|address| *address >= start && *address < end)
        {
            output.push(AnalysisStringEvidence {
                content: record.content.clone(),
                addr: record.addr.clone(),
                seq: record.seq,
                byte_len: record.byte_len,
                encoding: record.encoding.clone(),
            });
            if output.len() >= 12 {
                break;
            }
        }
    }
    output
}

fn build_key_steps(nodes: &[NodeInfo], limit: usize) -> Vec<AnalysisKeyStep> {
    let mut ordered: Vec<_> = nodes.iter().collect();
    ordered.sort_by_key(|node| node.seq);
    let mut steps = Vec::new();
    let mut index = 0;
    while index < ordered.len() && steps.len() < limit {
        let node = ordered[index];
        if !is_transport_operation(&node.operation) {
            steps.push(make_single_step(node));
            index += 1;
            continue;
        }

        let first = node;
        let mut last = node;
        let mut cursor = index + 1;
        while cursor < ordered.len()
            && is_transport_operation(&ordered[cursor].operation)
            && ordered[cursor].seq <= last.seq.saturating_add(2)
        {
            last = ordered[cursor];
            cursor += 1;
        }
        let transport_count = (cursor - index) as u32;
        if transport_count == 1 {
            steps.push(make_single_step(first));
        } else {
            steps.push(AnalysisKeyStep {
                seq: first.seq,
                end_seq: last.seq,
                operation: "Data movement".to_string(),
                expression: format!("{} -> {}", node_expression(first), node_expression(last)),
                transport_count,
            });
        }
        index = cursor;
    }
    steps
}

fn make_single_step(node: &NodeInfo) -> AnalysisKeyStep {
    AnalysisKeyStep {
        seq: node.seq,
        end_seq: node.seq,
        operation: if node.operation.is_empty() {
            "unknown".to_string()
        } else {
            node.operation.clone()
        },
        expression: node_expression(node).to_string(),
        transport_count: u32::from(is_transport_operation(&node.operation)),
    }
}

fn node_expression(node: &NodeInfo) -> &str {
    if node.expression.is_empty() {
        node.asm.as_str()
    } else {
        node.expression.as_str()
    }
}

fn is_transport_operation(operation: &str) -> bool {
    let operation = operation.to_ascii_lowercase();
    [
        "mov", "mvn", "fmov", "ldr", "ldur", "ldp", "str", "stur", "stp", "load", "store",
    ]
    .iter()
    .any(|prefix| operation.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(seq: u32, operation: &str, mem_addr: Option<&str>) -> NodeInfo {
        NodeInfo {
            seq,
            expression: format!("expr-{seq}"),
            asm: format!("asm-{seq}"),
            operation: operation.to_string(),
            is_leaf: seq == 1,
            value: None,
            address: format!("0x{seq:x}"),
            module: Some("libsample.so".to_string()),
            mem_addr: mem_addr.map(str::to_string),
            mem_rw: mem_addr.map(|_| "R".to_string()),
            function_name: Some("sample".to_string()),
            depth: seq,
        }
    }

    #[test]
    fn summarizes_graph_and_collapses_transport_steps() {
        let graph = DependencyGraph {
            nodes: vec![
                node(1, "ldr", Some("0x1001")),
                node(2, "mov", None),
                node(3, "eor", None),
            ],
            edges: vec![[3, 2], [2, 1]],
            root_seq: 3,
            total_reachable: 3,
            truncated: false,
        };
        let strings = vec![StringRecordDto {
            idx: 0,
            addr: "0x1000".to_string(),
            content: "hello".to_string(),
            encoding: "ASCII".to_string(),
            byte_len: 5,
            seq: 1,
            xref_count: 1,
            rw: "R".to_string(),
        }];

        let summary = summarize_dependency_graph(&graph, &strings, None);
        assert_eq!(summary.dependency_nodes, 3);
        assert_eq!(summary.input_leaf_count, 1);
        assert_eq!(summary.key_steps.len(), 2);
        assert_eq!(summary.key_steps[0].operation, "Data movement");
        assert_eq!(summary.key_strings[0].content, "hello");
        assert_eq!(summary.functions, vec!["sample"]);
    }
}
