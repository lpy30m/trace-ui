use serde::{Deserialize, Serialize};

use crate::utils::parse_hex_addr;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FridaArgumentKind {
    Integer,
    Pointer,
    Utf8String,
    Utf16String,
    ByteArray,
}

impl Default for FridaArgumentKind {
    fn default() -> Self {
        Self::Pointer
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FridaCaptureDirection {
    Input,
    Output,
    InOut,
}

impl Default for FridaCaptureDirection {
    fn default() -> Self {
        Self::Input
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FridaStalkerMode {
    Off,
    Calls,
    Blocks,
    Instructions,
}

impl Default for FridaStalkerMode {
    fn default() -> Self {
        Self::Off
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaArgumentSpec {
    pub index: u8,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub kind: FridaArgumentKind,
    #[serde(default)]
    pub direction: FridaCaptureDirection,
    #[serde(default)]
    pub length: Option<u32>,
    #[serde(default)]
    pub length_arg: Option<u8>,
    #[serde(default)]
    pub length_pointer_arg: Option<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaHookRequest {
    pub module_name: String,
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(default)]
    pub offset: Option<String>,
    #[serde(default)]
    pub function_name: Option<String>,
    #[serde(default)]
    pub arguments: Vec<FridaArgumentSpec>,
    #[serde(default = "default_true")]
    pub capture_registers: bool,
    #[serde(default = "default_true")]
    pub capture_return: bool,
    #[serde(default)]
    pub capture_backtrace: bool,
    #[serde(default)]
    pub stalker: FridaStalkerMode,
    #[serde(default = "default_stalker_duration")]
    pub stalker_duration_ms: u32,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u32,
}

fn default_true() -> bool {
    true
}

fn default_stalker_duration() -> u32 {
    10_000
}

fn default_max_bytes() -> u32 {
    256
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaHookScript {
    pub hook_id: String,
    pub file_name: String,
    pub target_expression: String,
    pub script: String,
    pub warnings: Vec<String>,
    pub protocol_version: String,
    pub frida_api_version: String,
}

fn sanitize_identifier(value: &str, fallback: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
            output.push(character);
        } else if !output.ends_with('_') {
            output.push('_');
        }
    }
    let output = output.trim_matches('_');
    if output.is_empty() {
        fallback.to_string()
    } else {
        output.to_string()
    }
}

fn validate_request(request: &FridaHookRequest) -> Result<(String, Option<u64>), String> {
    let module_name = request.module_name.trim();
    if module_name.is_empty() || module_name.chars().any(|character| character.is_control()) {
        return Err("module_name must be a non-empty printable name".to_string());
    }
    let symbol = request
        .symbol
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let offset = request
        .offset
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if symbol.is_some() == offset.is_some() {
        return Err("provide exactly one of symbol or offset".to_string());
    }
    let parsed_offset = offset
        .map(|value| parse_hex_addr(value).map_err(|error| error.to_string()))
        .transpose()?;
    if let Some(symbol) = symbol {
        if symbol.chars().any(|character| character.is_control()) {
            return Err("symbol must not contain control characters".to_string());
        }
        if symbol.len() > 512 {
            return Err("symbol is too long".to_string());
        }
    }
    if request.arguments.iter().any(|argument| {
        argument.index > 7
            || argument.length_arg.is_some_and(|index| index > 7)
            || argument.length_pointer_arg.is_some_and(|index| index > 7)
            || argument.length.is_some_and(|length| length > 1_048_576)
    }) {
        return Err(
            "argument indexes must be X0-X7 and capture lengths must be <= 1 MiB".to_string(),
        );
    }
    if request.arguments.iter().any(|argument| {
        usize::from(argument.length.is_some())
            + usize::from(argument.length_arg.is_some())
            + usize::from(argument.length_pointer_arg.is_some())
            > 1
    }) {
        return Err(
            "each capture may use only one length source: length, length_arg, or length_pointer_arg"
                .to_string(),
        );
    }
    if request.arguments.iter().any(|argument| {
        argument.length_pointer_arg.is_some()
            && !matches!(argument.direction, FridaCaptureDirection::Output)
    }) {
        return Err("length_pointer_arg is supported only for output captures".to_string());
    }
    let max_bytes = request.max_bytes.clamp(1, 1_048_576);
    if max_bytes == 0 {
        return Err("max_bytes must be positive".to_string());
    }
    Ok((module_name.to_string(), parsed_offset))
}

fn argument_kind(kind: &FridaArgumentKind) -> &'static str {
    match kind {
        FridaArgumentKind::Integer => "integer",
        FridaArgumentKind::Pointer => "pointer",
        FridaArgumentKind::Utf8String => "utf8String",
        FridaArgumentKind::Utf16String => "utf16String",
        FridaArgumentKind::ByteArray => "byteArray",
    }
}

fn direction(direction: &FridaCaptureDirection) -> &'static str {
    match direction {
        FridaCaptureDirection::Input => "input",
        FridaCaptureDirection::Output => "output",
        FridaCaptureDirection::InOut => "inOut",
    }
}

fn target_json(request: &FridaHookRequest, parsed_offset: Option<u64>) -> (String, String) {
    let symbol = request.symbol.as_deref().map(str::trim);
    let offset = parsed_offset.map(|value| format!("0x{value:x}"));
    (
        serde_json::to_string(&symbol).unwrap(),
        serde_json::to_string(&offset).unwrap(),
    )
}

fn argument_json(arguments: &[FridaArgumentSpec]) -> String {
    let values: Vec<serde_json::Value> = arguments
        .iter()
        .map(|argument| {
            serde_json::json!({
                "index": argument.index,
                "label": argument.label.clone().unwrap_or_else(|| format!("x{}", argument.index)),
                "kind": argument_kind(&argument.kind),
                "direction": direction(&argument.direction),
                "length": argument.length,
                "lengthArg": argument.length_arg,
                "lengthPointerArg": argument.length_pointer_arg,
            })
        })
        .collect();
    serde_json::to_string_pretty(&values).unwrap()
}

fn stalker_events(mode: &FridaStalkerMode) -> (&'static str, bool) {
    match mode {
        FridaStalkerMode::Off => ("{}", false),
        FridaStalkerMode::Calls => ("{ call: true, ret: true }", true),
        FridaStalkerMode::Blocks => ("{ call: true, ret: true, block: true }", true),
        FridaStalkerMode::Instructions => ("{ call: true, ret: true, exec: true }", true),
    }
}

pub fn generate_frida_hook(request: &FridaHookRequest) -> Result<FridaHookScript, String> {
    let (module_name, parsed_offset) = validate_request(request)?;
    let symbol = request.symbol.as_deref().map(str::trim);
    let function_name = request
        .function_name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(symbol.unwrap_or("offset"));
    let hook_id = sanitize_identifier(function_name, "trace-ui-hook");
    let file_name = format!("{hook_id}-frida-hook.js");
    let target_expression = if let Some(symbol) = symbol {
        format!("{}!{symbol}", module_name)
    } else {
        format!(
            "{}+0x{:x}",
            module_name,
            parsed_offset.expect("validated offset")
        )
    };
    let (symbol_json, offset_json) = target_json(request, parsed_offset);
    let (events, stalker_enabled) = stalker_events(&request.stalker);
    let args_json = argument_json(&request.arguments);
    let module_json = serde_json::to_string(&module_name).unwrap();
    let hook_json = serde_json::to_string(&hook_id).unwrap();
    let function_json = serde_json::to_string(function_name).unwrap();
    let max_bytes = request.max_bytes.clamp(1, 1_048_576);
    let duration = request.stalker_duration_ms.clamp(100, 600_000);

    let template = r##"/* Trace UI Frida hook
 * Frida JavaScript API target: 16.x
 * Generated protocol: trace-ui/frida-hook-v1
 * Target: __TARGET_EXPRESSION__
 * Execute manually with your preferred Frida 16 host or CLI.
 * Example: frida -U -f <package> -l __FILE_NAME__
 */
'use strict';

const TRACE_UI_PROTOCOL = 'trace-ui/frida-hook-v1';
const HOOK_ID = __HOOK_ID__;
const MODULE_NAME = __MODULE_NAME__;
const TARGET_SYMBOL = __TARGET_SYMBOL__;
const TARGET_OFFSET = __TARGET_OFFSET__;
const FUNCTION_NAME = __FUNCTION_NAME__;
const MAX_BYTES = __MAX_BYTES__;
const STALKER_DURATION_MS = __STALKER_DURATION__;
const ARG_SPECS = __ARG_SPECS__;
let nextCallId = 1;
let nextEventId = 1;
let resolvedModuleBase = null;
let resolvedModuleSize = 0;

function sendEvent(event, payload) {
  const record = Object.assign({
    protocol: TRACE_UI_PROTOCOL,
    eventId: HOOK_ID + ':event:' + (nextEventId++),
    hookId: HOOK_ID,
    event: event,
    functionName: FUNCTION_NAME,
    moduleName: MODULE_NAME,
    moduleBase: resolvedModuleBase !== null ? resolvedModuleBase.toString() : null,
    moduleSize: resolvedModuleSize,
    timestampMs: Date.now(),
    threadId: Process.getCurrentThreadId()
  }, payload || {});
  send(record);
  console.log('TRACE_UI_JSON ' + JSON.stringify(record));
}

function bytesToHex(arrayBuffer) {
  if (arrayBuffer === null) return null;
  const bytes = new Uint8Array(arrayBuffer);
  let output = '';
  for (let i = 0; i < bytes.length; i++) output += ('0' + bytes[i].toString(16)).slice(-2);
  return output;
}

function safeRead(pointer, kind, length) {
  try {
    if (pointer === null || pointer.isNull()) return { pointer: pointer ? pointer.toString() : null, value: null };
    if (kind === 'integer' || kind === 'pointer') return { pointer: pointer.toString(), value: pointer.toString() };
    const hasLength = length !== null && length !== undefined;
    if (kind === 'utf8String') return { pointer: pointer.toString(), value: pointer.readUtf8String(hasLength ? length : MAX_BYTES) };
    if (kind === 'utf16String') return { pointer: pointer.toString(), value: pointer.readUtf16String(hasLength ? length : Math.floor(MAX_BYTES / 2)) };
    const bounded = Math.max(0, Math.min(hasLength ? length : MAX_BYTES, MAX_BYTES));
    return { pointer: pointer.toString(), value: bytesToHex(pointer.readByteArray(bounded)), byteLength: bounded };
  } catch (error) {
    return { pointer: pointer ? pointer.toString() : null, value: null, readError: String(error) };
  }
}

function captureArguments(args, phase) {
  return ARG_SPECS.filter(spec => phase === 'enter'
    ? spec.direction === 'input' || spec.direction === 'inOut'
    : spec.direction === 'output' || spec.direction === 'inOut')
    .map(spec => {
      let length = spec.length;
      let lengthSource = length !== null && length !== undefined ? 'fixed' : null;
      let lengthReadError = null;
      try {
        if (phase === 'leave' && spec.lengthPointerArg !== null && spec.lengthPointerArg !== undefined) {
          length = args[spec.lengthPointerArg].readU32();
          lengthSource = '*X' + spec.lengthPointerArg;
        } else if (spec.lengthArg !== null && spec.lengthArg !== undefined) {
          length = args[spec.lengthArg].toUInt32();
          lengthSource = 'X' + spec.lengthArg;
        }
      } catch (error) {
        if (phase === 'leave' && spec.lengthPointerArg !== null && spec.lengthPointerArg !== undefined) {
          length = null;
          lengthSource = '*X' + spec.lengthPointerArg;
          lengthReadError = 'length pointer read failed from X' + spec.lengthPointerArg + ': ' + String(error);
        }
      }
      if (length !== null && length !== undefined) length = Math.min(length, MAX_BYTES);
      const value = lengthReadError === null
        ? safeRead(args[spec.index], spec.kind, length)
        : {
            pointer: args[spec.index] ? args[spec.index].toString() : null,
            value: null,
            readError: lengthReadError
          };
      return Object.assign({
        index: spec.index,
        label: spec.label,
        kind: spec.kind,
        direction: spec.direction,
        phase: phase,
        requestedLength: length,
        lengthSource: lengthSource
      }, value);
    });
}

function captureRegisters(context) {
  const registers = {};
  for (let i = 0; i < 8; i++) {
    try { registers['x' + i] = context['x' + i].toString(); } catch (_) { registers['x' + i] = null; }
  }
  for (const name of ['sp', 'lr', 'pc']) {
    try { registers[name] = context[name].toString(); } catch (_) { registers[name] = null; }
  }
  return registers;
}

function copyArguments(args) {
  const values = [];
  for (let i = 0; i < 8; i++) values.push(args[i]);
  return values;
}

function captureBacktrace(context) {
  try {
    return Thread.backtrace(context, Backtracer.ACCURATE)
      .map(address => DebugSymbol.fromAddress(address).toString());
  } catch (error) {
    return ['backtrace error: ' + String(error)];
  }
}

function stopStalker(state) {
  if (!state || state.stalkerTid === null || state.stalkerTid === undefined) return;
  try {
    Stalker.unfollow(state.stalkerTid);
    Stalker.flush();
    Stalker.garbageCollect();
  } catch (error) {
    sendEvent('stalker-error', { callId: state.callId, error: String(error) });
  }
  state.stalkerTid = null;
}

function startStalker(state) {
  if (!__STALKER_ENABLED__) return;
  state.stalkerTid = Process.getCurrentThreadId();
  try {
    Stalker.follow(state.stalkerTid, {
      events: __STALKER_EVENTS__,
      onReceive: function (rawEvents) {
        try {
          const events = Stalker.parse(rawEvents, { annotate: false, stringify: true });
          sendEvent('stalker-events', { callId: state.callId, mode: __STALKER_MODE__, events: events });
        } catch (error) {
          sendEvent('stalker-error', { callId: state.callId, error: String(error) });
        }
      }
    });
    state.stalkerTimer = setTimeout(function () { stopStalker(state); }, STALKER_DURATION_MS);
  } catch (error) {
    sendEvent('stalker-error', { callId: state.callId, error: String(error) });
    state.stalkerTid = null;
  }
}

function resolveTarget() {
  if (TARGET_SYMBOL !== null) {
    return Module.getExportByName(MODULE_NAME, TARGET_SYMBOL);
  }
  const moduleBase = resolvedModuleBase !== null ? resolvedModuleBase : Module.getBaseAddress(MODULE_NAME);
  if (moduleBase === null) throw new Error('module not loaded: ' + MODULE_NAME);
  return moduleBase.add(ptr(TARGET_OFFSET));
}

function install() {
  let target;
  try {
    resolvedModuleBase = Module.getBaseAddress(MODULE_NAME);
    if (resolvedModuleBase === null) throw new Error('module not loaded: ' + MODULE_NAME);
    try { resolvedModuleSize = Process.getModuleByName(MODULE_NAME).size; } catch (_) { resolvedModuleSize = 0; }
    target = resolveTarget();
  } catch (error) {
    sendEvent('hook-error', { error: 'target resolution failed: ' + String(error) });
    return;
  }
  sendEvent('hook-ready', { target: target.toString(), module: MODULE_NAME });
  Interceptor.attach(target, {
    onEnter: function (args) {
      const callId = HOOK_ID + ':' + Process.getCurrentThreadId() + ':' + (nextCallId++);
      this.__traceUiState = { args: copyArguments(args), callId: callId, stalkerTid: null, stalkerTimer: null };
      sendEvent('hook-enter', {
        callId: callId,
        target: target.toString(),
        registers: __CAPTURE_REGISTERS__ ? captureRegisters(this.context) : null,
        backtrace: __CAPTURE_BACKTRACE__ ? captureBacktrace(this.context) : null,
        captures: captureArguments(args, 'enter')
      });
      startStalker(this.__traceUiState);
    },
    onLeave: function (retval) {
      const state = this.__traceUiState;
      stopStalker(state);
      if (state && state.stalkerTimer !== null) clearTimeout(state.stalkerTimer);
      sendEvent('hook-leave', {
        callId: state ? state.callId : null,
        returnValue: __CAPTURE_RETURN__ ? retval.toString() : null,
        captures: state ? captureArguments(state.args, 'leave') : [],
        registers: __CAPTURE_REGISTERS__ ? captureRegisters(this.context) : null
      });
    }
  });
  sendEvent('hook-installed', { target: target.toString() });
}

setImmediate(install);
"##;

    let script = template
        .replace("__TARGET_EXPRESSION__", &target_expression)
        .replace("__FILE_NAME__", &file_name)
        .replace("__HOOK_ID__", &hook_json)
        .replace("__MODULE_NAME__", &module_json)
        .replace("__TARGET_SYMBOL__", &symbol_json)
        .replace("__TARGET_OFFSET__", &offset_json)
        .replace("__FUNCTION_NAME__", &function_json)
        .replace("__MAX_BYTES__", &max_bytes.to_string())
        .replace("__STALKER_DURATION__", &duration.to_string())
        .replace("__ARG_SPECS__", &args_json)
        .replace(
            "__STALKER_ENABLED__",
            if stalker_enabled { "true" } else { "false" },
        )
        .replace("__STALKER_EVENTS__", events)
        .replace(
            "__STALKER_MODE__",
            &serde_json::to_string(match request.stalker {
                FridaStalkerMode::Off => "off",
                FridaStalkerMode::Calls => "calls",
                FridaStalkerMode::Blocks => "blocks",
                FridaStalkerMode::Instructions => "instructions",
            })
            .unwrap(),
        )
        .replace(
            "__CAPTURE_REGISTERS__",
            if request.capture_registers {
                "true"
            } else {
                "false"
            },
        )
        .replace(
            "__CAPTURE_BACKTRACE__",
            if request.capture_backtrace {
                "true"
            } else {
                "false"
            },
        )
        .replace(
            "__CAPTURE_RETURN__",
            if request.capture_return {
                "true"
            } else {
                "false"
            },
        );

    let mut warnings = vec![
        "This script targets the Frida 16.x JavaScript API. Trace UI only generates and saves it; attaching, spawning, and loading remain under user control.".to_string(),
        "The generated agent emits trace-ui/frida-hook-v1 send() messages for the user's Frida host or CLI session.".to_string(),
        "Each event is also printed as a TRACE_UI_JSON-prefixed strict JSON line so redirected Frida CLI output can be imported manually; eventId prevents duplicate send/log records.".to_string(),
        "Pointer reads are best-effort and bounded by max_bytes; unreadable memory is reported as readError rather than guessed.".to_string(),
        "Output length-pointer captures are dereferenced only on function leave and remain bounded by max_bytes.".to_string(),
        "An offset is relative to the loaded module base and must match the target SO/dylib build.".to_string(),
    ];
    match request.stalker {
        FridaStalkerMode::Instructions => warnings.push(
            "Instruction exec events are high volume; use calls/blocks first and bound capture duration."
                .to_string(),
        ),
        FridaStalkerMode::Off => {}
        _ => warnings.push(
            "Stalker follows the hooked thread only and stops on return or after the configured duration."
                .to_string(),
        ),
    }
    Ok(FridaHookScript {
        hook_id,
        file_name,
        target_expression,
        script,
        warnings,
        protocol_version: "trace-ui/frida-hook-v1".to_string(),
        frida_api_version: "16.x".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> FridaHookRequest {
        FridaHookRequest {
            module_name: "libcrypto.so".to_string(),
            symbol: Some("EVP_DigestUpdate".to_string()),
            offset: None,
            function_name: Some("digest-update".to_string()),
            arguments: vec![FridaArgumentSpec {
                index: 1,
                label: Some("data".to_string()),
                kind: FridaArgumentKind::ByteArray,
                direction: FridaCaptureDirection::Input,
                length: None,
                length_arg: Some(2),
                length_pointer_arg: None,
            }],
            capture_registers: true,
            capture_return: true,
            capture_backtrace: true,
            stalker: FridaStalkerMode::Calls,
            stalker_duration_ms: 5000,
            max_bytes: 512,
        }
    }

    #[test]
    fn generates_symbol_hook_with_registers_capture_and_stalker() {
        let script = generate_frida_hook(&base_request()).unwrap();
        assert_eq!(script.target_expression, "libcrypto.so!EVP_DigestUpdate");
        assert!(script
            .script
            .contains("Module.getExportByName(MODULE_NAME, TARGET_SYMBOL)"));
        assert_eq!(script.frida_api_version, "16.x");
        assert!(script.script.contains("EVP_DigestUpdate"));
        assert!(script.script.contains("stalker-events"));
        assert!(script.script.contains("lengthArg"));
        assert!(script.script.contains("lengthPointerArg"));
        assert!(script.script.contains("captureRegisters(this.context)"));
        assert!(script.script.contains("callId: callId"));
        assert!(script.script.contains("TRACE_UI_JSON"));
        assert!(script.script.contains("eventId:"));
        assert!(script.script.contains("moduleBase: resolvedModuleBase"));
        assert!(script
            .script
            .contains("Process.getModuleByName(MODULE_NAME).size"));
        assert!(script.script.contains("Backtracer.ACCURATE"));
        assert!(script
            .warnings
            .iter()
            .any(|warning| warning.contains("Stalker")));
    }

    #[test]
    fn generated_hook_has_valid_javascript_syntax_when_node_is_available() {
        let node = ["node", "nodejs"].into_iter().find(|candidate| {
            std::process::Command::new(candidate)
                .arg("--version")
                .output()
                .is_ok_and(|output| output.status.success())
        });
        let Some(node) = node else {
            eprintln!("skipping generated JavaScript syntax check: Node.js is unavailable");
            return;
        };
        let generated = generate_frida_hook(&base_request()).unwrap();
        let directory =
            std::env::temp_dir().join(format!("trace-ui-frida-syntax-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let script_path = directory.join("generated.js");
        std::fs::write(&script_path, generated.script).unwrap();
        let output = std::process::Command::new(node)
            .arg("--check")
            .arg(&script_path)
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&directory);
        assert!(
            output.status.success(),
            "generated JavaScript failed syntax check: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn generates_offset_hook_and_escapes_target_names() {
        let mut request = base_request();
        request.module_name = "libfoo\".so".to_string();
        request.symbol = None;
        request.offset = Some("0x1a20".to_string());
        request.stalker = FridaStalkerMode::Off;
        let script = generate_frida_hook(&request).unwrap();
        assert_eq!(script.target_expression, "libfoo\".so+0x1a20");
        assert!(script.script.contains("libfoo\\\".so"));
        assert!(script
            .script
            .contains("return moduleBase.add(ptr(TARGET_OFFSET))"));
        assert!(script.script.contains("Module.getBaseAddress(MODULE_NAME)"));
        assert!(script.script.contains("if (!false) return;"));
    }

    #[test]
    fn rejects_ambiguous_or_unsafe_targets() {
        let mut request = base_request();
        request.offset = Some("0x100".to_string());
        assert!(generate_frida_hook(&request).is_err());
        request.symbol = None;
        request.offset = Some("not-an-offset".to_string());
        assert!(generate_frida_hook(&request).is_err());
        request.module_name = "bad\nname".to_string();
        assert!(generate_frida_hook(&request).is_err());
        request.module_name = "libcrypto.so".to_string();
        request.arguments[0].length = Some(32);
        assert!(generate_frida_hook(&request).is_err());
        request.arguments[0].length = None;
        request.arguments[0].length_arg = None;
        request.arguments[0].length_pointer_arg = Some(2);
        assert!(generate_frida_hook(&request).is_err());
    }

    #[test]
    fn generates_leave_time_output_length_pointer_capture() {
        let mut request = base_request();
        request.symbol = Some("EVP_DigestFinal_ex".to_string());
        request.arguments = vec![FridaArgumentSpec {
            index: 1,
            label: Some("digest".to_string()),
            kind: FridaArgumentKind::ByteArray,
            direction: FridaCaptureDirection::Output,
            length: None,
            length_arg: None,
            length_pointer_arg: Some(2),
        }];
        let generated = generate_frida_hook(&request).unwrap();
        assert!(generated
            .script
            .contains("args[spec.lengthPointerArg].readU32()"));
        assert!(generated.script.contains("phase === 'leave'"));
        assert!(generated.script.contains("lengthSource: lengthSource"));
        assert!(generated
            .script
            .contains("length pointer read failed from X"));
        assert!(generated.script.contains("lengthReadError === null"));
        assert!(generated.script.contains("hasLength ? length : MAX_BYTES"));
        assert!(!generated.script.contains("length || MAX_BYTES"));
    }
}
