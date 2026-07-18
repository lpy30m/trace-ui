use std::collections::HashMap;

use serde::Serialize;
use trace_parser::gumtrace::CallAnnotation;

use crate::api_types::TraceLine;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowEndpointClassification {
    pub direction: String,
    pub kind: String,
    pub category: String,
    pub confidence: String,
    pub external: bool,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceValidation {
    pub status: String,
    pub handle: String,
    pub resource_kind: Option<String>,
    pub origin_seq: Option<u32>,
    pub origin_function: Option<String>,
    pub direction: String,
    pub validated_kind: Option<String>,
    pub validated_category: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallResourceContext {
    pub seq: u32,
    pub function_name: String,
    pub raw_args: Vec<String>,
    pub decoded_args: Vec<(String, String)>,
    pub ret_value: Option<String>,
    pub resource_validation: Option<ResourceValidation>,
}

#[derive(Clone, Debug, Default)]
pub struct ResourceFlowIndex {
    contexts: HashMap<u32, CallResourceContext>,
}

impl ResourceFlowIndex {
    pub fn get(&self, seq: u32) -> Option<&CallResourceContext> {
        self.contexts.get(&seq)
    }
}

#[derive(Clone, Debug)]
struct ResourceOrigin {
    kind: String,
    seq: u32,
    function_name: String,
}

pub fn build_resource_flow_index(annotations: &HashMap<u32, CallAnnotation>) -> ResourceFlowIndex {
    let mut ordered = annotations.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|(seq, _)| **seq);
    let mut resources = HashMap::<String, ResourceOrigin>::new();
    let mut contexts = HashMap::new();

    for (&seq, annotation) in ordered {
        let canonical = canonical_function_name(&annotation.func_name);
        let raw_args = raw_call_args(annotation);
        let resource_validation = resource_argument_index(&canonical).and_then(|index| {
            let handle = raw_args
                .get(index)
                .and_then(|value| normalize_handle(value))?;
            let direction = resource_direction(&canonical).unwrap_or("lifecycle");
            let origin = resources.get(&handle);
            let (validated_kind, validated_category) = origin
                .map(|origin| validated_endpoint(&origin.kind, direction))
                .unwrap_or((None, None));
            Some(ResourceValidation {
                status: if origin.is_some() {
                    "verified".to_string()
                } else {
                    "unresolved".to_string()
                },
                handle: handle.clone(),
                resource_kind: origin.map(|origin| origin.kind.clone()),
                origin_seq: origin.map(|origin| origin.seq),
                origin_function: origin.map(|origin| origin.function_name.clone()),
                direction: direction.to_string(),
                validated_kind,
                validated_category,
                evidence: if let Some(origin) = origin {
                    vec![format!(
                        "Handle {handle} was created by {} at seq {}.",
                        origin.function_name, origin.seq
                    )]
                } else {
                    vec![format!(
                        "Handle {handle} was used by {} but its creation was not observed.",
                        annotation.func_name
                    )]
                },
            })
        });

        contexts.insert(
            seq,
            CallResourceContext {
                seq,
                function_name: annotation.func_name.clone(),
                raw_args: raw_args.clone(),
                decoded_args: annotation.args.clone(),
                ret_value: annotation.ret_value.clone(),
                resource_validation,
            },
        );

        if let Some(kind) = created_resource_kind(&canonical) {
            if let Some(handle) = annotation
                .ret_value
                .as_deref()
                .and_then(normalize_handle)
                .filter(|handle| handle != "0xffffffffffffffff")
            {
                let inherited = if matches!(canonical.as_str(), "dup" | "dup2" | "dup3") {
                    raw_args
                        .first()
                        .and_then(|value| normalize_handle(value))
                        .and_then(|source| resources.get(&source))
                        .map(|origin| origin.kind.clone())
                } else {
                    None
                };
                resources.insert(
                    handle,
                    ResourceOrigin {
                        kind: inherited.unwrap_or_else(|| kind.to_string()),
                        seq,
                        function_name: annotation.func_name.clone(),
                    },
                );
            }
        }

        if canonical == "close" || canonical == "fclose" {
            if let Some(handle) = raw_args.first().and_then(|value| normalize_handle(value)) {
                resources.remove(&handle);
            }
        }
    }

    ResourceFlowIndex { contexts }
}

pub fn apply_resource_validation(
    endpoint: &mut FlowEndpointClassification,
    context: &CallResourceContext,
) {
    let Some(validation) = context.resource_validation.as_ref() else {
        return;
    };
    if validation.status != "verified" || validation.direction != endpoint.direction {
        return;
    }
    if let Some(kind) = validation.validated_kind.as_ref() {
        endpoint.kind = kind.clone();
    }
    if let Some(category) = validation.validated_category.as_ref() {
        endpoint.category = category.clone();
    }
    endpoint.confidence = "high".to_string();
    endpoint.external = true;
    endpoint.reason = format!(
        "{} Cross-call resource provenance verified the handle category.",
        endpoint.reason
    );
}

pub fn classify_flow_endpoints(
    line: &TraceLine,
    terminal: bool,
) -> Vec<FlowEndpointClassification> {
    let mut endpoints = Vec::new();
    let stack_access = is_stack_access(&line.disasm);

    if line.mem_rw.as_deref().is_some_and(|rw| rw.contains('R')) {
        endpoints.push(endpoint(
            "source",
            if stack_access {
                "stack_read"
            } else {
                "memory_read"
            },
            if stack_access { "stack" } else { "memory" },
            if stack_access { "low" } else { "medium" },
            false,
            if stack_access {
                "Affected data is joined with a value read from stack memory."
            } else {
                "Affected data is joined with a value read from runtime memory."
            },
        ));
    }
    if line.mem_rw.as_deref().is_some_and(|rw| rw.contains('W')) {
        endpoints.push(endpoint(
            "sink",
            if stack_access {
                "stack_write"
            } else {
                "memory_write"
            },
            if stack_access { "stack" } else { "memory" },
            if stack_access { "low" } else { "medium" },
            false,
            if stack_access {
                "Affected data is written to stack memory and may be temporary transport."
            } else {
                "Affected data is written to a runtime memory buffer."
            },
        ));
    }

    if let Some(call) = line.call_info.as_ref() {
        classify_call(&call.func_name, call.is_jni, &mut endpoints);
    } else {
        let operation = operation_name(line);
        if matches!(operation.as_str(), "bl" | "blr" | "call") {
            endpoints.push(endpoint(
                "sink",
                "unresolved_function_call",
                "function",
                "low",
                true,
                "Affected data reaches a function call without a resolved annotation.",
            ));
        }
    }

    let operation = operation_name(line);
    if matches!(operation.as_str(), "svc" | "syscall") {
        endpoints.push(endpoint(
            "sink",
            "system_call",
            "system",
            "medium",
            true,
            "Affected data reaches a system-call instruction; the syscall number is not yet validated.",
        ));
    }
    if operation == "ret" {
        endpoints.push(endpoint(
            "sink",
            "function_return",
            "function",
            "medium",
            true,
            "Affected data reaches a function return boundary.",
        ));
    }
    if terminal && !endpoints.iter().any(|item| item.direction == "sink") {
        endpoints.push(endpoint(
            "sink",
            "terminal_output",
            "data_flow",
            "low",
            false,
            "No later consumer was observed for this affected instruction in the dynamic trace.",
        ));
    }

    endpoints
}

fn classify_call(
    function_name: &str,
    is_jni: bool,
    endpoints: &mut Vec<FlowEndpointClassification>,
) {
    let canonical = canonical_function_name(function_name);
    let lower_name = function_name.to_ascii_lowercase();

    if is_jni {
        endpoints.push(endpoint(
            "sink",
            "jni_boundary",
            "jni",
            "high",
            true,
            "Affected data reaches an explicitly annotated JNI call.",
        ));
        if lower_name.contains("get") || lower_name.contains("from") {
            endpoints.push(endpoint(
                "source",
                "jni_input",
                "jni",
                "high",
                true,
                "The JNI call name indicates data entering native execution.",
            ));
        }
        return;
    }

    if matches_name(&canonical, &["recv", "recvfrom", "recvmsg"]) {
        endpoints.push(endpoint(
            "source",
            "socket_receive",
            "network",
            "high",
            true,
            "Resolved function name identifies a socket receive operation.",
        ));
    } else if matches_name(&canonical, &["read", "pread", "fread", "fgets", "getline"]) {
        endpoints.push(endpoint(
            "source",
            "file_read",
            "file",
            "medium",
            true,
            "Resolved function name identifies a read-like external input operation.",
        ));
    } else if matches_name(
        &canonical,
        &["getenv", "getprop", "system_property_get", "secure_getenv"],
    ) {
        endpoints.push(endpoint(
            "source",
            "environment_input",
            "environment",
            "high",
            true,
            "Resolved function name identifies environment or system-property input.",
        ));
    } else if matches_name(&canonical, &["getrandom", "arc4random", "random", "rand"]) {
        endpoints.push(endpoint(
            "source",
            "random_input",
            "randomness",
            "high",
            true,
            "Resolved function name identifies a randomness source.",
        ));
    }

    if matches_name(&canonical, &["send", "sendto", "sendmsg", "connect"]) {
        endpoints.push(endpoint(
            "sink",
            "socket_send",
            "network",
            "high",
            true,
            "Resolved function name identifies a network output operation.",
        ));
    } else if matches_name(
        &canonical,
        &["write", "pwrite", "fwrite", "fputs", "fprintf", "fflush"],
    ) {
        endpoints.push(endpoint(
            "sink",
            "file_write",
            "file",
            "medium",
            true,
            "Resolved function name identifies a write-like external output operation.",
        ));
    } else if matches_name(
        &canonical,
        &[
            "printf",
            "puts",
            "putchar",
            "android_log_print",
            "android_log_write",
        ],
    ) {
        endpoints.push(endpoint(
            "sink",
            "log_output",
            "logging",
            "high",
            true,
            "Resolved function name identifies visible logging or console output.",
        ));
    } else if matches_name(&canonical, &["execve", "execv", "execl", "system", "popen"]) {
        endpoints.push(endpoint(
            "sink",
            "process_execution",
            "process",
            "high",
            true,
            "Resolved function name identifies process or command execution.",
        ));
    } else if matches_name(&canonical, &["memcpy", "memmove", "strcpy", "strncpy"]) {
        endpoints.push(endpoint(
            "sink",
            "buffer_transfer",
            "memory",
            "medium",
            false,
            "Resolved function name identifies transfer into another memory buffer.",
        ));
    } else if endpoints.is_empty() {
        endpoints.push(endpoint(
            "sink",
            "external_function_call",
            "function",
            "medium",
            true,
            "Affected data reaches a resolved external function boundary.",
        ));
    }
}

fn endpoint(
    direction: &str,
    kind: &str,
    category: &str,
    confidence: &str,
    external: bool,
    reason: &str,
) -> FlowEndpointClassification {
    FlowEndpointClassification {
        direction: direction.to_string(),
        kind: kind.to_string(),
        category: category.to_string(),
        confidence: confidence.to_string(),
        external,
        reason: reason.to_string(),
    }
}

fn operation_name(line: &TraceLine) -> String {
    line.disasm
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .trim_matches(|character: char| !character.is_ascii_alphanumeric())
        .to_ascii_lowercase()
}

fn is_stack_access(disasm: &str) -> bool {
    let disasm = disasm.to_ascii_lowercase();
    disasm.contains("[sp") || disasm.contains("[x29") || disasm.contains("[fp")
}

fn canonical_function_name(function_name: &str) -> String {
    let lower = function_name.to_ascii_lowercase();
    let without_version = lower.split('@').next().unwrap_or(lower.as_str());
    let token = without_version
        .split(|character: char| matches!(character, '!' | ':' | '/' | '\\' | ' ' | '(' | ')'))
        .filter(|value| !value.is_empty())
        .next_back()
        .unwrap_or(without_version)
        .trim_start_matches('_');
    token
        .strip_suffix("_chk")
        .unwrap_or(token)
        .trim_end_matches("64")
        .to_string()
}

fn matches_name(name: &str, candidates: &[&str]) -> bool {
    candidates.iter().any(|candidate| name == *candidate)
}

fn raw_call_args(annotation: &CallAnnotation) -> Vec<String> {
    let Some(call_line) = annotation.raw_lines.first() else {
        return Vec::new();
    };
    let rest = call_line
        .trim()
        .strip_prefix("call jni func: ")
        .or_else(|| call_line.trim().strip_prefix("call func: "))
        .unwrap_or(call_line.trim());
    if let (Some(start), Some(end)) = (rest.find('('), rest.rfind(')')) {
        if end > start {
            return rest[start + 1..end]
                .split(',')
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect();
        }
    }
    rest.split_once(':')
        .map(|(_, args)| {
            args.split(',')
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn normalize_handle(value: &str) -> Option<String> {
    let token = value
        .split(['=', ' ', '\t'])
        .filter(|part| !part.is_empty())
        .next_back()?
        .trim_matches(|character: char| matches!(character, ',' | ';' | '(' | ')' | '[' | ']'));
    if token.starts_with('-') {
        return None;
    }
    let parsed = if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        token.parse::<u64>().ok()?
    };
    Some(format!("0x{parsed:x}"))
}

fn created_resource_kind(function: &str) -> Option<&'static str> {
    if matches!(function, "open" | "openat" | "creat") {
        Some("file_descriptor")
    } else if matches!(function, "fopen" | "fdopen") {
        Some("file_stream")
    } else if matches!(function, "socket" | "accept" | "accept4") {
        Some("socket")
    } else if matches!(function, "dup" | "dup2" | "dup3") {
        Some("duplicated_handle")
    } else if matches!(function, "malloc" | "calloc" | "realloc" | "mmap") {
        Some("memory_buffer")
    } else {
        None
    }
}

fn resource_argument_index(function: &str) -> Option<usize> {
    if matches!(
        function,
        "read"
            | "pread"
            | "write"
            | "pwrite"
            | "send"
            | "sendto"
            | "sendmsg"
            | "recv"
            | "recvfrom"
            | "recvmsg"
            | "connect"
            | "close"
            | "fclose"
            | "fprintf"
            | "fputs"
            | "fflush"
    ) {
        Some(0)
    } else if matches!(function, "fread" | "fwrite") {
        Some(3)
    } else if function == "fgets" {
        Some(2)
    } else {
        None
    }
}

fn resource_direction(function: &str) -> Option<&'static str> {
    if matches!(
        function,
        "read" | "pread" | "fread" | "fgets" | "recv" | "recvfrom" | "recvmsg"
    ) {
        Some("source")
    } else if matches!(
        function,
        "write"
            | "pwrite"
            | "fwrite"
            | "fprintf"
            | "fputs"
            | "fflush"
            | "send"
            | "sendto"
            | "sendmsg"
            | "connect"
    ) {
        Some("sink")
    } else {
        None
    }
}

fn validated_endpoint(resource_kind: &str, direction: &str) -> (Option<String>, Option<String>) {
    match (resource_kind, direction) {
        ("socket", "source") => (
            Some("socket_receive".to_string()),
            Some("network".to_string()),
        ),
        ("socket", "sink") => (Some("socket_send".to_string()), Some("network".to_string())),
        ("file_descriptor" | "file_stream", "source") => {
            (Some("file_read".to_string()), Some("file".to_string()))
        }
        ("file_descriptor" | "file_stream", "sink") => {
            (Some("file_write".to_string()), Some("file".to_string()))
        }
        _ => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_types::CallInfoDto;
    use std::collections::HashMap;

    fn line(disasm: &str, rw: Option<&str>, function: Option<(&str, bool)>) -> TraceLine {
        TraceLine {
            seq: 10,
            address: "0x1000".to_string(),
            so_offset: "0x10".to_string(),
            so_name: Some("libsample.so".to_string()),
            disasm: disasm.to_string(),
            changes: String::new(),
            reg_before: String::new(),
            mem_rw: rw.map(str::to_string),
            mem_addr: rw.map(|_| "0x2000".to_string()),
            mem_size: Some(8),
            raw: disasm.to_string(),
            call_info: function.map(|(name, is_jni)| CallInfoDto {
                func_name: name.to_string(),
                is_jni,
                args: Vec::new(),
                ret_value: None,
                summary: name.to_string(),
                tooltip: String::new(),
            }),
        }
    }

    #[test]
    fn classifies_network_and_jni_boundaries() {
        let send = classify_flow_endpoints(
            &line("bl 0x2000", None, Some(("libc.so!send@plt", false))),
            false,
        );
        assert!(send
            .iter()
            .any(|item| item.kind == "socket_send" && item.external));

        let jni = classify_flow_endpoints(
            &line("blr x8", None, Some(("GetStringUTFChars", true))),
            false,
        );
        assert!(jni.iter().any(|item| item.kind == "jni_boundary"));
        assert!(jni.iter().any(|item| item.kind == "jni_input"));
    }

    #[test]
    fn distinguishes_stack_and_runtime_memory() {
        let stack = classify_flow_endpoints(&line("str x0, [sp, #8]", Some("W"), None), false);
        assert_eq!(stack[0].kind, "stack_write");

        let memory = classify_flow_endpoints(&line("str x0, [x8]", Some("W"), None), false);
        assert_eq!(memory[0].kind, "memory_write");
        assert_eq!(memory[0].confidence, "medium");
    }

    #[test]
    fn marks_unconsumed_values_as_terminal_outputs() {
        let endpoints = classify_flow_endpoints(&line("eor x0, x1, x2", None, None), true);
        assert_eq!(endpoints[0].kind, "terminal_output");
    }

    #[test]
    fn validates_socket_handle_across_calls() {
        let annotations = HashMap::from([
            (
                10,
                CallAnnotation {
                    func_name: "socket".to_string(),
                    is_jni: false,
                    args: Vec::new(),
                    ret_value: Some("3".to_string()),
                    raw_lines: vec!["call func: socket(2, 1, 0)".to_string()],
                },
            ),
            (
                20,
                CallAnnotation {
                    func_name: "write".to_string(),
                    is_jni: false,
                    args: Vec::new(),
                    ret_value: Some("16".to_string()),
                    raw_lines: vec!["call func: write(3, 0x1000, 16)".to_string()],
                },
            ),
        ]);
        let index = build_resource_flow_index(&annotations);
        let context = index.get(20).unwrap();
        let validation = context.resource_validation.as_ref().unwrap();
        assert_eq!(validation.status, "verified");
        assert_eq!(validation.resource_kind.as_deref(), Some("socket"));

        let mut endpoints =
            classify_flow_endpoints(&line("bl 0x2000", None, Some(("write", false))), false);
        let endpoint = endpoints
            .iter_mut()
            .find(|endpoint| endpoint.direction == "sink")
            .unwrap();
        apply_resource_validation(endpoint, context);
        assert_eq!(endpoint.kind, "socket_send");
        assert_eq!(endpoint.category, "network");
        assert_eq!(endpoint.confidence, "high");
    }
}
