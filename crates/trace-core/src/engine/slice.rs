use std::collections::{HashMap, HashSet};
use std::io::Write;

use super::TraceEngine;
use crate::api_types::{ExportConfig, SliceMissingRange, SliceOptions, SliceResult, SliceWarning};
use crate::error::{Result, TraceError};
use crate::flat::line_index::LineIndexView;
use crate::flat::mem_last_def::MemLastDefView;
use crate::query::slice::bfs_slice_with_extra_deps;
use crate::scanner::{mem_access_width, RegLastDef, PAIR_HALF2_BIT, PAIR_SHARED_BIT};
use crate::session::SliceOrigin;
use trace_parser::gumtrace as gumtrace_parser;
use trace_parser::insn_class::InsnClass;
use trace_parser::types::{parse_reg, RegId, TraceFormat};
use trace_parser::{def_use, insn_class, parser};

const MAX_RESOLVE_SCAN: u32 = 50000;
const MAX_TAINT_MEMORY_SIZE: u32 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceAt {
    Last,
    Line(u32),
    Seq(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TaintSourceSpec {
    Register {
        name: String,
        reg: RegId,
        at: SourceAt,
    },
    Memory {
        addr: u64,
        size: u32,
        at: SourceAt,
    },
}

impl TaintSourceSpec {
    fn parse(spec: &str) -> std::result::Result<Self, String> {
        let (kind_and_value, suffix) = spec
            .rsplit_once('@')
            .ok_or_else(|| format!("缺少 @ 分隔符: {spec}"))?;
        let at = parse_source_at(suffix)?;

        if let Some(name) = kind_and_value.strip_prefix("reg:") {
            let name = name.trim().to_string();
            let reg =
                parse_reg(&name.to_lowercase()).ok_or_else(|| format!("未知寄存器: {name}"))?;
            return Ok(Self::Register { name, reg, at });
        }

        if let Some(value) = kind_and_value.strip_prefix("mem:") {
            let (addr_text, size) = match value.rsplit_once(':') {
                Some((addr, size)) => {
                    let size = size
                        .parse::<u32>()
                        .map_err(|_| format!("无效内存长度: {size}"))?;
                    (addr, size)
                }
                None => (value, 1),
            };
            if size == 0 {
                return Err("内存污点长度必须至少为 1 字节".to_string());
            }
            if size > MAX_TAINT_MEMORY_SIZE {
                return Err(format!("内存污点长度不能超过 {MAX_TAINT_MEMORY_SIZE} 字节"));
            }

            let addr_text = addr_text.trim();
            let addr_hex = addr_text
                .strip_prefix("0x")
                .or_else(|| addr_text.strip_prefix("0X"))
                .unwrap_or(addr_text);
            let addr = u64::from_str_radix(addr_hex, 16)
                .map_err(|_| format!("无效十六进制地址: {addr_text}"))?;
            addr.checked_add(size as u64 - 1)
                .ok_or_else(|| format!("内存范围从 0x{addr:x} 开始时发生地址溢出"))?;

            return Ok(Self::Memory { addr, size, at });
        }

        Err(format!(
            "不支持的 spec 格式: {spec} (需要 reg:NAME@... 或 mem:ADDR:SIZE@...)"
        ))
    }

    fn normalized(&self) -> String {
        match self {
            Self::Register { name, at, .. } => format!("reg:{name}@{}", format_at(*at)),
            Self::Memory { addr, size, at } => {
                format!("mem:0x{addr:x}:{size}@{}", format_at(*at))
            }
        }
    }
}

fn parse_source_at(suffix: &str) -> std::result::Result<SourceAt, String> {
    if suffix.eq_ignore_ascii_case("last") {
        return Ok(SourceAt::Last);
    }
    if let Some(seq) = suffix.strip_prefix("seq:") {
        return seq
            .parse::<u32>()
            .map(SourceAt::Seq)
            .map_err(|_| format!("invalid sequence number: {seq}"));
    }
    let suffix = suffix.strip_prefix("line:").unwrap_or(suffix);
    let line = suffix
        .parse::<u32>()
        .map_err(|_| format!("无效行号: {suffix}"))?
        .checked_sub(1)
        .ok_or_else(|| "行号必须 >= 1".to_string())?;
    Ok(SourceAt::Line(line))
}

fn format_at(at: SourceAt) -> String {
    match at {
        SourceAt::Last => "last".to_string(),
        SourceAt::Line(line) => format!("line:{}", line + 1),
        SourceAt::Seq(seq) => format!("seq:{seq}"),
    }
}

fn source_seq(at: SourceAt) -> Option<u32> {
    match at {
        SourceAt::Last => None,
        SourceAt::Line(line) | SourceAt::Seq(line) => Some(line),
    }
}

fn parse_call_hex(value: &str) -> Option<u64> {
    u64::from_str_radix(
        value
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X"),
        16,
    )
    .ok()
}

fn call_arg(annotation: &trace_parser::gumtrace::CallAnnotation, name: &str) -> Option<u64> {
    annotation
        .args
        .iter()
        .find(|(index, _)| index == name)
        .and_then(|(_, value)| parse_call_hex(value))
}

fn printf_vararg_count(annotation: &trace_parser::gumtrace::CallAnnotation) -> usize {
    let Some(format) = annotation
        .args
        .iter()
        .rev()
        .find(|(index, _)| index == "1")
        .map(|(_, value)| value.as_str())
    else {
        return 1;
    };
    let bytes = format.as_bytes();
    let mut count = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        i += 1;
        if i < bytes.len() && bytes[i] == b'%' {
            i += 1;
            continue;
        }
        count += 1;
        i += 1;
    }
    count.min(6)
}

pub(crate) fn call_effect_dependencies_in_range(
    state: &crate::session::SessionState,
    line_index: &LineIndexView<'_>,
    min_seq: u32,
    max_seq: u32,
) -> HashMap<u32, Vec<u32>> {
    #[derive(Clone)]
    struct Effect {
        seq: u32,
        inputs: Vec<(u64, u64)>,
        outputs: Vec<(u64, u64)>,
    }
    fn decoded_len(
        annotation: &trace_parser::gumtrace::CallAnnotation,
        index: &str,
    ) -> Option<u64> {
        annotation
            .args
            .iter()
            .find(|(i, _)| i == index)
            .map(|(_, value)| value.as_bytes().len() as u64)
    }
    fn overlaps(left: (u64, u64), right: (u64, u64)) -> bool {
        left.0 < right.0.saturating_add(right.1) && right.0 < left.0.saturating_add(left.1)
    }
    let mut result = HashMap::new();
    let mut calls: Vec<_> = state.call_annotations.iter().collect();
    calls.sort_by_key(|(seq, _)| **seq);
    let mut prior_effects: Vec<Effect> = Vec::new();
    for (&call_seq, annotation) in calls {
        if call_seq > max_seq || call_seq < min_seq {
            continue;
        }
        let name = annotation
            .func_name
            .trim_start_matches('_')
            .to_ascii_lowercase();
        let mut deps = Vec::new();
        let mut effect = Effect {
            seq: call_seq,
            inputs: Vec::new(),
            outputs: Vec::new(),
        };
        match name.as_str() {
            "memcpy" | "memmove" => {
                if let (Some(dst), Some(src), Some(len)) = (
                    call_arg(annotation, "x0"),
                    call_arg(annotation, "x1"),
                    call_arg(annotation, "x2"),
                ) {
                    effect.inputs.push((src, len));
                    effect.outputs.push((dst, len));
                }
            }
            "strcpy" => {
                if let (Some(dst), Some(src)) =
                    (call_arg(annotation, "x0"), call_arg(annotation, "x1"))
                {
                    let len = decoded_len(annotation, "1").unwrap_or(255) + 1;
                    effect.inputs.push((src, len));
                    effect.outputs.push((dst, len));
                }
            }
            "strcat" => {
                if let (Some(dst), Some(src)) =
                    (call_arg(annotation, "x0"), call_arg(annotation, "x1"))
                {
                    let old = decoded_len(annotation, "0").unwrap_or(0);
                    let added = decoded_len(annotation, "1").unwrap_or(255);
                    effect.inputs.extend([(dst, old + 1), (src, added + 1)]);
                    effect.outputs.push((dst, old + added + 1));
                }
            }
            "strlen" => {
                if let Some(src) = call_arg(annotation, "x0") {
                    effect
                        .inputs
                        .push((src, decoded_len(annotation, "0").unwrap_or(255) + 1));
                }
            }
            "sprintf" | "snprintf" => {
                if let Some(fmt) = call_arg(annotation, "x1") {
                    effect.inputs.push((fmt, 64));
                }
                if let Some(dst) = call_arg(annotation, "x0") {
                    let len = annotation
                        .ret_value
                        .as_deref()
                        .and_then(parse_call_hex)
                        .unwrap_or(255)
                        + 1;
                    effect.outputs.push((dst, len));
                }
                let registers = [
                    RegId::X2,
                    RegId::X3,
                    RegId::X4,
                    RegId::X5,
                    RegId::X6,
                    RegId::X7,
                ];
                deps.extend(resolve_reg_defs(
                    &registers[..printf_vararg_count(annotation)],
                    call_seq,
                    &state.mmap,
                    line_index,
                    state.trace_format,
                ));
            }
            "memset" => {
                if let Ok(def) = resolve_reg_def(
                    RegId::X1,
                    call_seq,
                    &state.mmap,
                    line_index,
                    state.trace_format,
                ) {
                    deps.push(def);
                }
            }
            _ => {}
        }
        for prior in prior_effects.iter().rev() {
            if effect
                .inputs
                .iter()
                .any(|input| prior.outputs.iter().any(|output| overlaps(*input, *output)))
            {
                deps.push(prior.seq);
            }
        }
        deps.sort_unstable();
        deps.dedup();
        if !deps.is_empty() {
            result.insert(call_seq, deps);
        }
        if !effect.outputs.is_empty() {
            prior_effects.push(effect);
        }
    }
    result
}

fn call_hexdump_source(
    parsed: &TaintSourceSpec,
    annotations: &HashMap<u32, trace_parser::gumtrace::CallAnnotation>,
) -> Option<u32> {
    let TaintSourceSpec::Memory { addr, size, at } = parsed else {
        return None;
    };
    let limit = source_seq(*at).unwrap_or(u32::MAX);
    annotations
        .iter()
        .filter_map(|(&seq, annotation)| {
            annotation
                .hexdump_observations()
                .into_iter()
                .any(|o| {
                    let end = o.base_addr.saturating_add(o.bytes.len() as u64);
                    *addr >= o.base_addr && addr.saturating_add(*size as u64) <= end
                })
                .then_some(seq)
                .filter(|seq| *seq <= limit)
        })
        .max()
}

pub(crate) struct ResolvedTaintSource {
    pub(crate) start_indices: Vec<u32>,
    pub(crate) warning: Option<SliceWarning>,
    pub(crate) normalized_spec: String,
}

/// Parse one public taint-source string and resolve every BFS start it represents.
pub(crate) fn resolve_start_indices(
    spec: &str,
    reg_last_def: &RegLastDef,
    mem_last_def: &MemLastDefView,
    mmap: &[u8],
    line_index: &LineIndexView<'_>,
    format: TraceFormat,
) -> std::result::Result<ResolvedTaintSource, String> {
    let parsed = TaintSourceSpec::parse(spec)?;
    let normalized_spec = parsed.normalized();
    let (start_indices, missing_offsets) = match parsed {
        TaintSourceSpec::Register { name, reg, at } => {
            let index = match at {
                SourceAt::Last => reg_last_def
                    .get(&reg)
                    .copied()
                    .ok_or_else(|| format!("寄存器 {name} 在 trace 中从未被定义"))?,
                SourceAt::Line(line) | SourceAt::Seq(line) => {
                    validate_source_line(line, line_index)?;
                    resolve_reg_def(reg, line, mmap, line_index, format)?
                }
            };
            (vec![index], Vec::new())
        }
        TaintSourceSpec::Memory { addr, size, at } => match at {
            SourceAt::Last => resolve_mem_range_last(addr, size, mem_last_def),
            SourceAt::Line(line) | SourceAt::Seq(line) => {
                validate_source_line(line, line_index)?;
                resolve_mem_range_defs(addr, size, line, mmap, line_index, format)
            }
        },
    };

    if start_indices.is_empty() {
        return Err(format!(
            "内存范围 {} 没有可追踪的写入定义",
            format_memory_range_from_spec(&normalized_spec)
        ));
    }

    let warning = if missing_offsets.is_empty() {
        None
    } else {
        Some(build_missing_memory_warning(
            &normalized_spec,
            &missing_offsets,
        ))
    };

    Ok(ResolvedTaintSource {
        start_indices,
        warning,
        normalized_spec,
    })
}

/// Compatibility helper for single-root consumers such as the dependency tree.
pub(crate) fn resolve_start_index(
    spec: &str,
    reg_last_def: &RegLastDef,
    mem_last_def: &MemLastDefView,
    mmap: &[u8],
    line_index: &LineIndexView<'_>,
    format: TraceFormat,
) -> std::result::Result<u32, String> {
    resolve_start_indices(spec, reg_last_def, mem_last_def, mmap, line_index, format)?
        .start_indices
        .into_iter()
        .next()
        .ok_or_else(|| format!("污点源没有可用定义: {spec}"))
}

fn validate_source_line(
    line: u32,
    line_index: &LineIndexView<'_>,
) -> std::result::Result<(), String> {
    if line >= line_index.total_lines() {
        return Err(format!(
            "源行 {} 超出 trace 范围 (共 {} 行)",
            line + 1,
            line_index.total_lines()
        ));
    }
    Ok(())
}

fn resolve_reg_def(
    target_reg: RegId,
    from_line: u32,
    mmap: &[u8],
    line_index: &LineIndexView<'_>,
    format: TraceFormat,
) -> std::result::Result<u32, String> {
    let scan_start = from_line.saturating_sub(MAX_RESOLVE_SCAN);
    for s in (scan_start..=from_line).rev() {
        if let Some(raw) = line_index.get_line(mmap, s) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                let parsed = match format {
                    TraceFormat::Unidbg => parser::parse_line(line_str),
                    TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
                };
                if let Some(parsed) = parsed {
                    let cls = insn_class::classify_and_refine(&parsed);
                    let (defs, _) = def_use::determine_def_use(cls, &parsed);
                    if defs.iter().any(|r| *r == target_reg) {
                        // For pair instructions, tag the line number with the
                        // correct half bit so BFS follows the right dependencies.
                        // This mirrors the logic in scanner.rs Step 4.
                        if cls == InsnClass::LoadPair {
                            let has_base_wb = parsed.writeback && parsed.base_reg.is_some();
                            let data_defs = if has_base_wb {
                                &defs[..defs.len() - 1]
                            } else {
                                &defs[..]
                            };
                            let mid = data_defs.len() / 2;
                            if data_defs[mid..].iter().any(|r| *r == target_reg) {
                                return Ok(s | PAIR_HALF2_BIT);
                            }
                            if has_base_wb && defs.last() == Some(&target_reg) {
                                return Ok(s | PAIR_SHARED_BIT);
                            }
                        } else if cls == InsnClass::StorePair {
                            return Ok(s | PAIR_SHARED_BIT);
                        }
                        return Ok(s);
                    }
                }
            }
        }
    }
    Err(format!(
        "在 {} 行范围内未找到寄存器 {:?} 的 DEF",
        MAX_RESOLVE_SCAN, target_reg
    ))
}

fn resolve_reg_defs(
    target_regs: &[RegId],
    from_line: u32,
    mmap: &[u8],
    line_index: &LineIndexView<'_>,
    format: TraceFormat,
) -> Vec<u32> {
    if target_regs.is_empty() {
        return Vec::new();
    }
    let mut unresolved: HashSet<RegId> = target_regs.iter().copied().collect();
    let mut result = Vec::with_capacity(unresolved.len());
    let scan_start = from_line.saturating_sub(MAX_RESOLVE_SCAN);
    for s in (scan_start..=from_line).rev() {
        let Some(raw) = line_index.get_line(mmap, s) else {
            continue;
        };
        let Ok(line_str) = std::str::from_utf8(raw) else {
            continue;
        };
        let parsed = match format {
            TraceFormat::Unidbg => parser::parse_line(line_str),
            TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
        };
        let Some(parsed) = parsed else { continue };
        let cls = insn_class::classify_and_refine(&parsed);
        let (defs, _) = def_use::determine_def_use(cls, &parsed);
        let found: Vec<_> = unresolved
            .iter()
            .copied()
            .filter(|reg| defs.contains(reg))
            .collect();
        for reg in found {
            unresolved.remove(&reg);
            let tagged = if cls == InsnClass::LoadPair {
                let has_base_wb = parsed.writeback && parsed.base_reg.is_some();
                let data_defs = if has_base_wb {
                    &defs[..defs.len() - 1]
                } else {
                    &defs[..]
                };
                let mid = data_defs.len() / 2;
                if data_defs[mid..].contains(&reg) {
                    s | PAIR_HALF2_BIT
                } else if has_base_wb && defs.last() == Some(&reg) {
                    s | PAIR_SHARED_BIT
                } else {
                    s
                }
            } else if cls == InsnClass::StorePair {
                s | PAIR_SHARED_BIT
            } else {
                s
            };
            result.push(tagged);
        }
        if unresolved.is_empty() {
            break;
        }
    }
    result
}

fn resolve_mem_range_last(
    addr: u64,
    size: u32,
    mem_last_def: &MemLastDefView<'_>,
) -> (Vec<u32>, Vec<u32>) {
    let mut starts = Vec::new();
    let mut seen = HashSet::new();
    let mut missing_offsets = Vec::new();

    for offset in 0..size {
        let byte_addr = addr + offset as u64;
        match mem_last_def.get(&byte_addr) {
            Some((line, _)) if seen.insert(line) => starts.push(line),
            Some(_) => {}
            None => missing_offsets.push(offset),
        }
    }
    starts.sort_unstable();
    (starts, missing_offsets)
}

fn resolve_mem_range_defs(
    addr: u64,
    size: u32,
    from_line: u32,
    mmap: &[u8],
    line_index: &LineIndexView<'_>,
    format: TraceFormat,
) -> (Vec<u32>, Vec<u32>) {
    let range_end = addr + size as u64 - 1;
    let mut byte_defs = vec![None; size as usize];
    let mut unresolved = size as usize;
    let scan_start = from_line.saturating_sub(MAX_RESOLVE_SCAN);
    for s in (scan_start..=from_line).rev() {
        if let Some(raw) = line_index.get_line(mmap, s) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                let parsed = match format {
                    TraceFormat::Unidbg => parser::parse_line(line_str),
                    TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
                };
                if let Some(parsed) = parsed {
                    let class = insn_class::classify_and_refine(&parsed);
                    let Some(mem) = parsed.mem_op.as_ref().filter(|mem| mem.is_write) else {
                        continue;
                    };
                    let width = mem_access_width(class, mem.elem_width, &parsed) as u64;
                    if width == 0 {
                        continue;
                    }
                    let mem_end = mem.abs.saturating_add(width - 1);
                    let overlap_start = addr.max(mem.abs);
                    let overlap_end = range_end.min(mem_end);
                    if overlap_start > overlap_end {
                        continue;
                    }

                    for byte_addr in overlap_start..=overlap_end {
                        let offset = (byte_addr - addr) as usize;
                        if byte_defs[offset].is_some() {
                            continue;
                        }
                        let tag = if class == InsnClass::StorePair
                            && byte_addr - mem.abs >= mem.elem_width as u64
                        {
                            PAIR_HALF2_BIT
                        } else {
                            0
                        };
                        byte_defs[offset] = Some(s | tag);
                        unresolved -= 1;
                    }
                    if unresolved == 0 {
                        break;
                    }
                }
            }
        }
    }

    let mut seen = HashSet::new();
    let mut starts = Vec::new();
    let mut missing_offsets = Vec::new();
    for (offset, raw) in byte_defs.into_iter().enumerate() {
        match raw {
            Some(raw) if seen.insert(raw) => starts.push(raw),
            Some(_) => {}
            None => missing_offsets.push(offset as u32),
        }
    }
    starts.sort_unstable();
    (starts, missing_offsets)
}

fn format_memory_range_from_spec(spec: &str) -> String {
    let value = spec.strip_prefix("mem:").unwrap_or(spec);
    value.split('@').next().unwrap_or(value).to_string()
}

fn build_missing_memory_warning(spec: &str, missing_offsets: &[u32]) -> SliceWarning {
    let TaintSourceSpec::Memory { addr, .. } =
        TaintSourceSpec::parse(spec).expect("normalized memory source must parse")
    else {
        unreachable!("missing offsets only apply to memory sources")
    };
    let mut missing_ranges = Vec::new();
    let mut range_start = missing_offsets[0];
    let mut previous = range_start;
    for &offset in &missing_offsets[1..] {
        if offset != previous + 1 {
            missing_ranges.push(make_missing_range(addr, range_start, previous));
            range_start = offset;
        }
        previous = offset;
    }
    missing_ranges.push(make_missing_range(addr, range_start, previous));

    let missing_count: u32 = missing_ranges.iter().map(|range| range.size).sum();
    SliceWarning {
        code: "partial-memory-definition".to_string(),
        message: format!(
            "{missing_count} 个字节在扫描范围内没有写入定义，分析结果只覆盖已找到的字节"
        ),
        source_spec: spec.to_string(),
        missing_ranges,
    }
}

fn make_missing_range(addr: u64, start: u32, end: u32) -> SliceMissingRange {
    SliceMissingRange {
        start_addr: format!("0x{:x}", addr + start as u64),
        end_addr: format!("0x{:x}", addr + end as u64),
        size: end - start + 1,
    }
}

impl TraceEngine {
    pub fn run_slice(
        &self,
        session_id: &str,
        from_specs: &[String],
        options: SliceOptions,
    ) -> Result<SliceResult> {
        if from_specs.is_empty() {
            return Err(TraceError::InvalidArgument(
                "至少需要一个污点源".to_string(),
            ));
        }

        // Phase 1: read lock — resolve specs, run BFS, apply range filter
        let (marked, warnings, normalized_specs) = {
            let handle = self.get_handle(session_id)?;
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;

            let reg_last_def = state
                .reg_last_def
                .as_ref()
                .ok_or(TraceError::IndexNotReady)?;
            let mem_last_def = state.mem_last_def_view().ok_or(TraceError::IndexNotReady)?;
            let scan_view = state.scan_view().ok_or(TraceError::IndexNotReady)?;
            let format = state.trace_format;

            let mut start_indices = Vec::new();
            let mut warnings = Vec::new();
            let mut normalized_specs = Vec::with_capacity(from_specs.len());
            let lidx_view = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
            for spec in from_specs {
                let resolved = resolve_start_indices(
                    spec,
                    reg_last_def,
                    &mem_last_def,
                    &state.mmap,
                    &lidx_view,
                    format,
                )
                .or_else(|original_error| {
                    let parsed = TaintSourceSpec::parse(spec)?;
                    call_hexdump_source(&parsed, &state.call_annotations)
                        .map(|seq| ResolvedTaintSource {
                            start_indices: vec![seq],
                            warning: None,
                            normalized_spec: parsed.normalized(),
                        })
                        .ok_or(original_error)
                })
                .map_err(TraceError::InvalidArgument)?;
                start_indices.extend(resolved.start_indices);
                if let Some(warning) = resolved.warning {
                    warnings.push(warning);
                }
                normalized_specs.push(resolved.normalized_spec);
            }
            start_indices.sort_unstable();
            start_indices.dedup();
            let effect_start = start_indices
                .iter()
                .map(|seq| seq & crate::scanner::LINE_MASK)
                .max()
                .unwrap_or(0);
            let extra_deps = call_effect_dependencies_in_range(
                &state,
                &lidx_view,
                effect_start.saturating_sub(10_000),
                effect_start,
            );

            let mut marked = bfs_slice_with_extra_deps(
                &scan_view,
                &start_indices,
                options.data_only,
                &extra_deps,
            );

            // Apply optional range filter
            if let Some(s) = options.start_seq {
                let end = (s as usize).min(marked.len());
                marked[..end].fill(false);
            }
            if let Some(e) = options.end_seq {
                let start = ((e as usize) + 1).min(marked.len());
                marked[start..].fill(false);
            }

            (marked, warnings, normalized_specs)
        };

        let marked_count = marked.count_ones() as u32;
        let total_lines = marked.len() as u32;
        let percentage = if total_lines > 0 {
            marked_count as f64 / total_lines as f64 * 100.0
        } else {
            0.0
        };

        // Phase 2: write lock — store result + slice_origin
        {
            let handle = self.get_handle(session_id)?;
            let mut state = handle
                .state
                .write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            state.slice_result = Some(marked);
            state.slice_origin = Some(SliceOrigin {
                from_specs: normalized_specs,
                data_only: options.data_only,
                start_seq: options.start_seq,
                end_seq: options.end_seq,
            });
        }

        Ok(SliceResult {
            marked_count,
            total_lines,
            percentage,
            warnings,
        })
    }

    pub fn clear_slice(&self, session_id: &str) -> Result<()> {
        let handle = self.get_handle(session_id)?;
        let mut state = handle
            .state
            .write()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        state.slice_result = None;
        state.slice_origin = None;
        Ok(())
    }

    pub fn get_slice_origin(&self, session_id: &str) -> Result<Option<SliceOrigin>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        Ok(state.slice_origin.clone())
    }

    pub fn get_tainted_seqs(&self, session_id: &str) -> Result<Vec<u32>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        match &state.slice_result {
            Some(marked) => Ok(marked.iter_ones().map(|i| i as u32).collect()),
            None => Ok(vec![]),
        }
    }

    pub fn get_slice_status(
        &self,
        session_id: &str,
        start_seq: u32,
        count: u32,
    ) -> Result<Vec<bool>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        match &state.slice_result {
            Some(marked) => {
                let total = marked.len() as u32;
                let end = (start_seq + count).min(total);
                Ok((start_seq..end).map(|i| marked[i as usize]).collect())
            }
            None => Ok(vec![false; count as usize]),
        }
    }

    pub fn export_taint_results(
        &self,
        session_id: &str,
        output_path: &str,
        format: &str,
        config: ExportConfig,
    ) -> Result<()> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let marked = state
            .slice_result
            .as_ref()
            .ok_or_else(|| TraceError::InvalidArgument("没有活跃的污点分析结果".to_string()))?;
        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;

        // Fallback: if from_specs is empty, use stored slice_origin
        let actual_from_specs = if config.from_specs.is_empty() {
            state
                .slice_origin
                .as_ref()
                .map(|o| o.from_specs.clone())
                .unwrap_or_default()
        } else {
            config.from_specs
        };

        let marked_count = marked.count_ones() as u32;
        let total_lines = marked.len() as u32;

        let file = std::fs::File::create(output_path).map_err(|e| TraceError::Io(e))?;
        let mut writer = std::io::BufWriter::new(file);

        if format == "json" {
            // 收集污点行
            let mut tainted_lines = Vec::with_capacity(marked_count as usize);
            for seq in marked.iter_ones() {
                if let Some(raw) = line_index.get_line(&state.mmap, seq as u32) {
                    let text = String::from_utf8_lossy(raw);
                    tainted_lines.push(serde_json::json!({
                        "seq": seq + 1,
                        "text": text.as_ref(),
                    }));
                }
            }

            let percentage = if total_lines > 0 {
                marked_count as f64 / total_lines as f64 * 100.0
            } else {
                0.0
            };

            let json = serde_json::json!({
                "source": {
                    "file": state.file_path,
                    "totalLines": total_lines,
                },
                "config": {
                    "fromSpecs": actual_from_specs,
                    "startSeq": config.start_seq,
                    "endSeq": config.end_seq,
                },
                "stats": {
                    "markedCount": marked_count,
                    "percentage": percentage,
                },
                "taintedLines": tainted_lines,
            });

            serde_json::to_writer_pretty(&mut writer, &json)
                .map_err(|e| TraceError::Internal(format!("JSON 写入失败: {}", e)))?;
        } else {
            // TXT: 纯污点行原文
            for seq in marked.iter_ones() {
                if let Some(raw) = line_index.get_line(&state.mmap, seq as u32) {
                    writer.write_all(raw).map_err(|e| TraceError::Io(e))?;
                    writer.write_all(b"\n").map_err(|e| TraceError::Io(e))?;
                }
            }
        }

        writer.flush().map_err(|e| TraceError::Io(e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_line(mnemonic: &str, operands: &str, addr: u64) -> String {
        format!(
            "[00:00:00 1][lib.so 0x0] [00000000] 0x40000000: \"{mnemonic} {operands}\" ; mem[WRITE] abs=0x{addr:x} x0=0x1 x1=0x2 x8=0x3 x9=0x4 sp=0x2000 => x0=0x1"
        )
    }

    fn resolve_explicit(
        spec: &str,
        lines: &[String],
    ) -> std::result::Result<ResolvedTaintSource, String> {
        let data = lines.join("\n");
        let sampled_offsets = [0u64];
        let line_index = LineIndexView::from_raw(&sampled_offsets, lines.len() as u32);
        let mem_last_def = MemLastDefView::from_raw(&[], &[], &[]);
        resolve_start_indices(
            spec,
            &RegLastDef::new(),
            &mem_last_def,
            data.as_bytes(),
            &line_index,
            TraceFormat::Unidbg,
        )
    }

    #[test]
    fn parses_and_normalizes_memory_sources() {
        let spec = TaintSourceSpec::parse("mem:0X001000:16@42").unwrap();
        assert_eq!(spec.normalized(), "mem:0x1000:16@line:42");
        assert_eq!(
            TaintSourceSpec::parse("mem:0x1000:16@seq:41")
                .unwrap()
                .normalized(),
            "mem:0x1000:16@seq:41"
        );
        assert_eq!(
            TaintSourceSpec::parse("mem:1000@last")
                .unwrap()
                .normalized(),
            "mem:0x1000:1@last"
        );
    }

    #[test]
    fn rejects_invalid_memory_ranges() {
        assert!(TaintSourceSpec::parse("mem:0x1000:0@last")
            .unwrap_err()
            .contains("至少"));
        assert!(TaintSourceSpec::parse("mem:0x1000:4097@last")
            .unwrap_err()
            .contains("4096"));
        assert!(TaintSourceSpec::parse("mem:0xffffffffffffffff:2@last")
            .unwrap_err()
            .contains("溢出"));
    }

    #[test]
    fn resolves_sixteen_bytes_from_four_stores() {
        let lines = vec![
            store_line("str", "w8, [x0]", 0x1000),
            store_line("str", "w8, [x0]", 0x1004),
            store_line("str", "w8, [x0]", 0x1008),
            store_line("str", "w8, [x0]", 0x100c),
        ];
        let resolved = resolve_explicit("mem:0x1000:16@4", &lines).unwrap();
        assert_eq!(resolved.start_indices, vec![0, 1, 2, 3]);
        assert!(resolved.warning.is_none());
    }

    #[test]
    fn deduplicates_a_single_wide_store() {
        let lines = vec![store_line("str", "q0, [x0]", 0x1000)];
        assert_eq!(
            resolve_explicit("mem:0x1000:16@1", &lines)
                .unwrap()
                .start_indices,
            vec![0]
        );
    }

    #[test]
    fn overlapping_writes_use_latest_definition_per_byte() {
        let lines = vec![
            store_line("str", "x8, [x0]", 0x1000),
            store_line("str", "w9, [x0]", 0x1002),
        ];
        assert_eq!(
            resolve_explicit("mem:0x1000:8@2", &lines)
                .unwrap()
                .start_indices,
            vec![0, 1]
        );

        let fully_overwritten = vec![
            store_line("str", "x8, [x0]", 0x1000),
            store_line("str", "x9, [x0]", 0x1000),
        ];
        assert_eq!(
            resolve_explicit("mem:0x1000:8@2", &fully_overwritten)
                .unwrap()
                .start_indices,
            vec![1]
        );
    }

    #[test]
    fn preserves_store_pair_half_tags() {
        let lines = vec![store_line("stp", "x0, x1, [sp]", 0x1000)];
        assert_eq!(
            resolve_explicit("mem:0x1000:16@1", &lines)
                .unwrap()
                .start_indices,
            vec![0, PAIR_HALF2_BIT]
        );
    }

    #[test]
    fn reports_partial_memory_definitions_as_ranges() {
        let lines = vec![store_line("str", "w8, [x0]", 0x1000)];
        let resolved = resolve_explicit("mem:0x1000:8@1", &lines).unwrap();
        assert_eq!(resolved.start_indices, vec![0]);
        let warning = resolved.warning.unwrap();
        assert_eq!(warning.code, "partial-memory-definition");
        assert_eq!(warning.missing_ranges.len(), 1);
        assert_eq!(warning.missing_ranges[0].start_addr, "0x1004");
        assert_eq!(warning.missing_ranges[0].end_addr, "0x1007");
        assert_eq!(warning.missing_ranges[0].size, 4);
    }

    #[test]
    fn resolves_each_byte_at_last_and_deduplicates_lines() {
        let addrs: Vec<u64> = (0x1000..0x1008).collect();
        let lines = vec![5, 5, 5, 5, 9, 9, 9, 9];
        let values = vec![0; 8];
        let mem_last_def = MemLastDefView::from_raw(&addrs, &lines, &values);
        let line_index = LineIndexView::from_raw(&[0], 0);
        let resolved = resolve_start_indices(
            "mem:0x1000:8@last",
            &RegLastDef::new(),
            &mem_last_def,
            &[],
            &line_index,
            TraceFormat::Unidbg,
        )
        .unwrap();
        assert_eq!(resolved.start_indices, vec![5, 9]);
        assert!(resolved.warning.is_none());
    }

    #[test]
    fn keeps_register_source_compatibility() {
        let lines = vec![
            "[00:00:00 1][lib.so 0x0] [00000000] 0x40000000: \"mov x0, #1\" => x0=0x1".to_string(),
        ];
        let resolved = resolve_explicit("reg:X0@1", &lines).unwrap();
        assert_eq!(resolved.start_indices, vec![0]);
        assert_eq!(resolved.normalized_spec, "reg:X0@line:1");
    }
}
