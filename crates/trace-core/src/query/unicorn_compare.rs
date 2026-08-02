use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::query::unicorn::{UnicornMissingMemory, UnicornOllvmResultBundle, UnicornReplayRun};
use crate::utils::{format_signed_offset_hex, parse_hex_addr, parse_signed_offset};

const UNICORN_ROUND_COMPARISON_SCHEMA: &str = "trace-ui/unicorn-ollvm-round-comparison-v1";
const MAX_ROUNDS: usize = 16;
const MAX_COMPARISON_OFFSET_ENTRIES: usize = 4_000_000;
const MAX_REPORTED_DELTA_OFFSETS: usize = 256;

#[derive(Clone, Copy, Debug)]
pub struct UnicornOllvmRoundInput<'a> {
    pub round_id: &'a str,
    pub source_label: Option<&'a str>,
    pub bundle: &'a UnicornOllvmResultBundle,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornOllvmRoundSummary {
    pub round_index: u32,
    pub round_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_label: Option<String>,
    pub run_count: u32,
    pub seed_offset_count: u32,
    pub total_instruction_count: u64,
    pub unique_executed_offset_count: u64,
    pub unique_block_offset_count: u64,
    pub new_executed_offset_count: u64,
    pub new_executed_offsets: Vec<String>,
    pub new_executed_offsets_truncated: bool,
    pub new_block_offset_count: u64,
    pub new_block_offsets: Vec<String>,
    pub new_block_offsets_truncated: bool,
    pub stop_reason_counts: BTreeMap<String, u64>,
    pub matched_dispatcher_offsets: Vec<String>,
    pub missing_memory_count: u64,
    pub register_relative_missing_count: u64,
    pub recapture_suggestion_count: u64,
    pub carry_forward_window_count: u64,
    pub carry_forward_bytes: u64,
    pub unsupported_seed_region_count: u64,
    pub config_matches_baseline: bool,
    pub execution_data_truncated: bool,
    pub error_run_count: u64,
    pub warning_count: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornOllvmSeedRoundObservation {
    pub round_index: u32,
    pub round_id: String,
    pub present: bool,
    pub source_event_indices: Vec<u64>,
    pub run_count: u32,
    pub stop_reasons: Vec<String>,
    pub total_instruction_count: u64,
    pub max_instruction_count: u64,
    pub terminal_offsets: Vec<String>,
    pub matched_dispatcher_offsets: Vec<String>,
    pub executed_offset_count: u64,
    pub block_offset_count: u64,
    pub missing_memory_count: u64,
    pub register_relative_missing_count: u64,
    pub missing_pc_offsets: Vec<String>,
    pub missing_signatures: Vec<String>,
    pub recapture_suggestion_count: u64,
    pub carry_forward_window_count: u64,
    pub carry_forward_bytes: u64,
    pub unsupported_seed_region_count: u64,
    pub execution_data_truncated: bool,
    pub error_run_count: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornOllvmRoundDelta {
    pub from_round_index: u32,
    pub from_round_id: String,
    pub to_round_index: u32,
    pub to_round_id: String,
    pub status: String,
    pub evidence_level: String,
    pub instruction_delta: i64,
    pub new_executed_offset_count: u64,
    pub new_executed_offsets: Vec<String>,
    pub new_executed_offsets_truncated: bool,
    pub lost_executed_offset_count: u64,
    pub new_block_offset_count: u64,
    pub new_block_offsets: Vec<String>,
    pub new_block_offsets_truncated: bool,
    pub lost_block_offset_count: u64,
    pub stop_reason_changed: bool,
    pub terminal_changed: bool,
    pub missing_memory_changed: bool,
    pub detail: String,
    pub recommendation: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornOllvmSeedRoundComparison {
    pub capture_offset: String,
    pub matched_probe_offsets: Vec<String>,
    pub observations: Vec<UnicornOllvmSeedRoundObservation>,
    pub deltas: Vec<UnicornOllvmRoundDelta>,
    pub latest_status: String,
    pub latest_recommendation: String,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornOllvmRoundComparisonReport {
    pub schema_version: String,
    pub module_name: String,
    pub binary_sha256: String,
    pub round_count: u32,
    pub seed_offset_count: u32,
    pub total_unique_executed_offset_count: u64,
    pub total_unique_block_offset_count: u64,
    pub progressed_seed_count: u32,
    pub stalled_seed_count: u32,
    pub regressed_seed_count: u32,
    pub changed_seed_count: u32,
    pub incomplete_seed_count: u32,
    pub overall_status: String,
    pub overall_recommendation: String,
    pub rounds: Vec<UnicornOllvmRoundSummary>,
    pub seeds: Vec<UnicornOllvmSeedRoundComparison>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct SeedObservationInternal {
    source_event_indices: BTreeSet<u64>,
    matched_probe_offsets: BTreeSet<String>,
    stop_reasons: BTreeSet<String>,
    total_instruction_count: u64,
    max_instruction_count: u64,
    terminal_offsets: BTreeSet<String>,
    matched_dispatcher_offsets: BTreeSet<String>,
    executed_offsets: BTreeSet<String>,
    block_offsets: BTreeSet<String>,
    missing_memory_count: u64,
    register_relative_missing_count: u64,
    missing_pc_offsets: BTreeSet<String>,
    missing_signatures: BTreeSet<String>,
    recapture_suggestion_count: u64,
    carry_forward_window_count: u64,
    carry_forward_bytes: u64,
    unsupported_seed_region_count: u64,
    execution_data_truncated: bool,
    error_run_count: u64,
    run_count: u32,
}

fn normalized_offset(value: &str) -> String {
    parse_hex_addr(value)
        .map(|offset| format!("0x{offset:x}"))
        .unwrap_or_else(|_| value.trim().to_ascii_lowercase())
}

fn sorted_offsets(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort_by_key(|value| parse_hex_addr(value).unwrap_or(u64::MAX));
    values.dedup();
    values
}

fn bounded_offsets(values: &BTreeSet<String>) -> (Vec<String>, bool) {
    let mut values = sorted_offsets(values.iter().cloned());
    let truncated = values.len() > MAX_REPORTED_DELTA_OFFSETS;
    values.truncate(MAX_REPORTED_DELTA_OFFSETS);
    (values, truncated)
}

fn validate_round_id(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(|character| character.is_control())
    {
        return Err("Unicorn comparison round IDs must be 1-128 printable characters".to_string());
    }
    Ok(value.to_string())
}

fn normalized_missing_signature(value: &UnicornMissingMemory) -> String {
    let pc = value
        .pc_offset
        .as_deref()
        .map(normalized_offset)
        .unwrap_or_else(|| "outside".to_string());
    let location = match (
        value.base_register.as_deref(),
        value.displacement.as_deref(),
    ) {
        (Some(register), Some(displacement)) => {
            let register = register.trim().to_ascii_uppercase();
            let displacement = parse_signed_offset(displacement)
                .map(format_signed_offset_hex)
                .unwrap_or_else(|_| displacement.trim().to_ascii_lowercase());
            format!("{register}{displacement}")
        }
        _ => format!("absolute:{}", value.address.trim().to_ascii_lowercase()),
    };
    format!(
        "{pc}|{}|{location}|{}",
        value.access.trim().to_ascii_lowercase(),
        value.size
    )
}

fn add_run(observation: &mut SeedObservationInternal, run: &UnicornReplayRun) {
    observation
        .source_event_indices
        .insert(run.source_event_index);
    observation.stop_reasons.insert(run.stop_reason.clone());
    observation.total_instruction_count = observation
        .total_instruction_count
        .saturating_add(run.instruction_count);
    observation.max_instruction_count =
        observation.max_instruction_count.max(run.instruction_count);
    if let Some(offset) = &run.terminal_offset {
        observation
            .terminal_offsets
            .insert(normalized_offset(offset));
    }
    if let Some(offset) = &run.matched_dispatcher_offset {
        observation
            .matched_dispatcher_offsets
            .insert(normalized_offset(offset));
    }
    observation.executed_offsets.extend(
        run.executed_offsets
            .iter()
            .map(|offset| normalized_offset(offset)),
    );
    observation.block_offsets.extend(
        run.block_offsets
            .iter()
            .map(|offset| normalized_offset(offset)),
    );
    observation.missing_memory_count = observation
        .missing_memory_count
        .saturating_add(run.missing_memory.len() as u64);
    for missing in &run.missing_memory {
        if missing.base_register.is_some() && missing.displacement.is_some() {
            observation.register_relative_missing_count = observation
                .register_relative_missing_count
                .saturating_add(1);
        }
        if let Some(offset) = &missing.pc_offset {
            observation
                .missing_pc_offsets
                .insert(normalized_offset(offset));
        }
        observation
            .missing_signatures
            .insert(normalized_missing_signature(missing));
    }
    observation.execution_data_truncated |= run.executed_offsets_truncated
        || run.block_offsets_truncated
        || run.memory_writes_truncated;
    if run.error.is_some() {
        observation.error_run_count = observation.error_run_count.saturating_add(1);
    }
    observation.run_count = observation.run_count.saturating_add(1);
}

fn build_round_observations(
    bundle: &UnicornOllvmResultBundle,
) -> BTreeMap<String, SeedObservationInternal> {
    let seed_by_event = bundle
        .seeds
        .iter()
        .map(|seed| (seed.source_event_index, seed))
        .collect::<BTreeMap<_, _>>();
    let plan_by_event = bundle
        .seed_recapture_plans
        .iter()
        .map(|plan| (plan.source_event_index, plan))
        .collect::<BTreeMap<_, _>>();
    let mut observations = BTreeMap::<String, SeedObservationInternal>::new();
    for run in &bundle.runs {
        let Some(seed) = seed_by_event.get(&run.source_event_index) else {
            continue;
        };
        let capture_offset = normalized_offset(&seed.capture_offset);
        let observation = observations.entry(capture_offset).or_default();
        observation.matched_probe_offsets.extend(
            seed.matched_probe_offsets
                .iter()
                .map(|offset| normalized_offset(offset)),
        );
        add_run(observation, run);
        if let Some(plan) = plan_by_event.get(&run.source_event_index) {
            observation.carry_forward_window_count = observation
                .carry_forward_window_count
                .saturating_add(plan.windows.len() as u64);
            observation.carry_forward_bytes = observation
                .carry_forward_bytes
                .saturating_add(plan.carry_forward_bytes);
            observation.unsupported_seed_region_count = observation
                .unsupported_seed_region_count
                .saturating_add(plan.unsupported_memory_region_count);
            observation.execution_data_truncated |= plan.windows_truncated;
        }
    }
    for suggestion in &bundle.recapture_suggestions {
        for event_index in &suggestion.source_event_indices {
            if let Some(seed) = seed_by_event.get(event_index) {
                if let Some(observation) =
                    observations.get_mut(&normalized_offset(&seed.capture_offset))
                {
                    observation.recapture_suggestion_count =
                        observation.recapture_suggestion_count.saturating_add(1);
                }
            }
        }
    }
    observations
}

fn public_observation(
    round_index: usize,
    round_id: &str,
    value: Option<&SeedObservationInternal>,
) -> UnicornOllvmSeedRoundObservation {
    let Some(value) = value else {
        return UnicornOllvmSeedRoundObservation {
            round_index: round_index as u32,
            round_id: round_id.to_string(),
            present: false,
            source_event_indices: Vec::new(),
            run_count: 0,
            stop_reasons: Vec::new(),
            total_instruction_count: 0,
            max_instruction_count: 0,
            terminal_offsets: Vec::new(),
            matched_dispatcher_offsets: Vec::new(),
            executed_offset_count: 0,
            block_offset_count: 0,
            missing_memory_count: 0,
            register_relative_missing_count: 0,
            missing_pc_offsets: Vec::new(),
            missing_signatures: Vec::new(),
            recapture_suggestion_count: 0,
            carry_forward_window_count: 0,
            carry_forward_bytes: 0,
            unsupported_seed_region_count: 0,
            execution_data_truncated: false,
            error_run_count: 0,
        };
    };
    UnicornOllvmSeedRoundObservation {
        round_index: round_index as u32,
        round_id: round_id.to_string(),
        present: true,
        source_event_indices: value.source_event_indices.iter().copied().collect(),
        run_count: value.run_count,
        stop_reasons: value.stop_reasons.iter().cloned().collect(),
        total_instruction_count: value.total_instruction_count,
        max_instruction_count: value.max_instruction_count,
        terminal_offsets: sorted_offsets(value.terminal_offsets.iter().cloned()),
        matched_dispatcher_offsets: sorted_offsets(
            value.matched_dispatcher_offsets.iter().cloned(),
        ),
        executed_offset_count: value.executed_offsets.len() as u64,
        block_offset_count: value.block_offsets.len() as u64,
        missing_memory_count: value.missing_memory_count,
        register_relative_missing_count: value.register_relative_missing_count,
        missing_pc_offsets: sorted_offsets(value.missing_pc_offsets.iter().cloned()),
        missing_signatures: value.missing_signatures.iter().cloned().collect(),
        recapture_suggestion_count: value.recapture_suggestion_count,
        carry_forward_window_count: value.carry_forward_window_count,
        carry_forward_bytes: value.carry_forward_bytes,
        unsupported_seed_region_count: value.unsupported_seed_region_count,
        execution_data_truncated: value.execution_data_truncated,
        error_run_count: value.error_run_count,
    }
}

fn difference(left: &BTreeSet<String>, right: &BTreeSet<String>) -> BTreeSet<String> {
    left.difference(right).cloned().collect()
}

fn instruction_delta(current: u64, previous: u64) -> i64 {
    let delta = current as i128 - previous as i128;
    delta.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

fn success_stop(value: &SeedObservationInternal) -> bool {
    value
        .stop_reasons
        .iter()
        .any(|reason| matches!(reason.as_str(), "next-dispatcher" | "return" | "completed"))
}

fn build_delta(
    from_index: usize,
    from_id: &str,
    previous: Option<&SeedObservationInternal>,
    to_index: usize,
    to_id: &str,
    current: Option<&SeedObservationInternal>,
) -> UnicornOllvmRoundDelta {
    let empty = BTreeSet::new();
    let previous_executed = previous
        .map(|value| &value.executed_offsets)
        .unwrap_or(&empty);
    let current_executed = current
        .map(|value| &value.executed_offsets)
        .unwrap_or(&empty);
    let previous_blocks = previous.map(|value| &value.block_offsets).unwrap_or(&empty);
    let current_blocks = current.map(|value| &value.block_offsets).unwrap_or(&empty);
    let new_executed = difference(current_executed, previous_executed);
    let lost_executed = difference(previous_executed, current_executed);
    let new_blocks = difference(current_blocks, previous_blocks);
    let lost_blocks = difference(previous_blocks, current_blocks);
    let (new_executed_offsets, new_executed_offsets_truncated) = bounded_offsets(&new_executed);
    let (new_block_offsets, new_block_offsets_truncated) = bounded_offsets(&new_blocks);

    let previous_instruction_count = previous
        .map(|value| value.max_instruction_count)
        .unwrap_or(0);
    let current_instruction_count = current
        .map(|value| value.max_instruction_count)
        .unwrap_or(0);
    let stop_reason_changed =
        previous.map(|value| &value.stop_reasons) != current.map(|value| &value.stop_reasons);
    let terminal_changed = previous.map(|value| &value.terminal_offsets)
        != current.map(|value| &value.terminal_offsets);
    let missing_memory_changed = previous.map(|value| &value.missing_signatures)
        != current.map(|value| &value.missing_signatures);

    let (status, detail, recommendation) = match (previous, current) {
        (None, Some(_)) => (
            "seed-added",
            "This exact seed offset first appears in the later round; there is no earlier observation to prove progress.",
            "Keep the seed selection aligned across rounds before interpreting coverage changes.",
        ),
        (Some(_), None) => (
            "seed-removed",
            "This exact seed offset is absent from the later round, so the iteration cannot be compared end to end.",
            "Regenerate the later replay with the same exact seed offset if a direct comparison is required.",
        ),
        (None, None) => (
            "not-present",
            "The seed offset is absent from both rounds.",
            "No action is available for this pair of rounds.",
        ),
        (Some(previous), Some(current)) => {
            let new_dispatchers = difference(
                &current.matched_dispatcher_offsets,
                &previous.matched_dispatcher_offsets,
            );
            let prior_stopped_partial = previous.stop_reasons.iter().any(|reason| {
                matches!(
                    reason.as_str(),
                    "missing-memory"
                        | "missing-register"
                        | "instruction-limit"
                        | "timeout"
                        | "loop-detected"
                        | "unsupported-simd-state"
                        | "unsupported-system-state"
                )
            });
            let same_missing = !current.missing_signatures.is_empty()
                && current.missing_signatures == previous.missing_signatures;
            let same_terminal = current.terminal_offsets == previous.terminal_offsets
                && current.stop_reasons == previous.stop_reasons;
            if !new_dispatchers.is_empty() {
                (
                    "reached-new-dispatcher",
                    "The later round reached at least one dispatcher offset not reached by the earlier round. This is execution-specific progress evidence for the captured state.",
                    "Review the new dispatcher transition in IDA/Trace UI and decide whether another exact seed is needed.",
                )
            } else if prior_stopped_partial && success_stop(current) {
                (
                    "resolved-prior-stop",
                    "The later round replaced a prior partial stop with next-dispatcher, return, or completed execution.",
                    "Review the resolved path and reconcile it with dynamic/IDA CFG evidence.",
                )
            } else if same_missing
                && new_executed.is_empty()
                && new_blocks.is_empty()
                && lost_executed.is_empty()
                && lost_blocks.is_empty()
            {
                (
                    "stalled-same-missing-memory",
                    "The later round stopped on the same missing-memory signature without adding recorded instruction or block coverage.",
                    "Capture a closer manual checkpoint or switch to a bounded angr probe; repeating the same seed recapture is unlikely to add state.",
                )
            } else if !current.missing_signatures.is_empty()
                && !previous.missing_signatures.is_empty()
                && current.missing_signatures != previous.missing_signatures
                && (!new_executed.is_empty() || !new_blocks.is_empty())
            {
                (
                    "missing-memory-moved-forward",
                    "The missing-memory stop changed and the later round added recorded coverage. This suggests the cumulative seed advanced, but it does not prove the full path is complete.",
                    "Generate the next bounded recapture Hook for the new register-relative window and continue only while coverage advances.",
                )
            } else if !new_blocks.is_empty() && lost_blocks.is_empty() {
                (
                    "advanced-coverage",
                    "The later round added basic-block coverage without losing earlier recorded blocks.",
                    "Review the newly observed blocks and continue recapture only for remaining explicit missing state.",
                )
            } else if (!new_blocks.is_empty() || !new_executed.is_empty())
                && (!lost_blocks.is_empty() || !lost_executed.is_empty())
            {
                (
                    "diverged-path",
                    "The later round gained and lost recorded offsets relative to the earlier round, indicating a changed concrete path rather than monotonic coverage.",
                    "Check input, thread, capture point, and seed-state differences before treating this as progress.",
                )
            } else if new_blocks.is_empty()
                && new_executed.is_empty()
                && (!lost_blocks.is_empty() || !lost_executed.is_empty())
            {
                (
                    "regressed-coverage",
                    "The later round retained less recorded coverage and did not add new offsets.",
                    "Restore the prior seed context and inspect unsupported or failed recapture windows before another replay.",
                )
            } else if same_terminal {
                (
                    "stalled-same-terminal",
                    "The later round ended with the same stop reason and terminal offset without new recorded coverage.",
                    "Use angr for bounded alternate-path exploration or change the capture point/bounds instead of repeating this replay unchanged.",
                )
            } else if current.max_instruction_count > previous.max_instruction_count
                && new_blocks.is_empty()
                && new_executed.is_empty()
            {
                (
                    "longer-same-coverage",
                    "The later round executed longer but did not add recorded instruction or block offsets, which may indicate a loop or repeated path.",
                    "Inspect loop limits and state transitions; increasing the instruction bound alone is unlikely to recover new CFG evidence.",
                )
            } else if missing_memory_changed || stop_reason_changed || terminal_changed {
                (
                    "changed-not-proven-progress",
                    "The terminal or missing-state outcome changed without monotonic new coverage, so progress is not established.",
                    "Inspect the exact delta and controlled-run inputs before choosing another recapture or angr probe.",
                )
            } else {
                (
                    "unchanged",
                    "No material bounded replay difference was observed for this seed offset.",
                    "Collect a deliberately changed capture or use another analysis bridge if more evidence is required.",
                )
            }
        }
    };

    UnicornOllvmRoundDelta {
        from_round_index: from_index as u32,
        from_round_id: from_id.to_string(),
        to_round_index: to_index as u32,
        to_round_id: to_id.to_string(),
        status: status.to_string(),
        evidence_level: "candidate".to_string(),
        instruction_delta: instruction_delta(current_instruction_count, previous_instruction_count),
        new_executed_offset_count: new_executed.len() as u64,
        new_executed_offsets,
        new_executed_offsets_truncated,
        lost_executed_offset_count: lost_executed.len() as u64,
        new_block_offset_count: new_blocks.len() as u64,
        new_block_offsets,
        new_block_offsets_truncated,
        lost_block_offset_count: lost_blocks.len() as u64,
        stop_reason_changed,
        terminal_changed,
        missing_memory_changed,
        detail: detail.to_string(),
        recommendation: recommendation.to_string(),
    }
}

fn status_bucket(status: &str) -> &'static str {
    match status {
        "reached-new-dispatcher"
        | "resolved-prior-stop"
        | "missing-memory-moved-forward"
        | "advanced-coverage" => "progressed",
        "stalled-same-missing-memory"
        | "stalled-same-terminal"
        | "longer-same-coverage"
        | "unchanged" => "stalled",
        "regressed-coverage" => "regressed",
        "seed-added" | "seed-removed" | "not-present" => "incomplete",
        _ => "changed",
    }
}

pub fn compare_unicorn_ollvm_rounds(
    rounds: &[UnicornOllvmRoundInput<'_>],
) -> Result<UnicornOllvmRoundComparisonReport, String> {
    if !(2..=MAX_ROUNDS).contains(&rounds.len()) {
        return Err("Unicorn round comparison requires between 2 and 16 rounds".to_string());
    }
    let mut round_ids = Vec::with_capacity(rounds.len());
    let mut unique_round_ids = BTreeSet::new();
    for round in rounds {
        let round_id = validate_round_id(round.round_id)?;
        if !unique_round_ids.insert(round_id.clone()) {
            return Err(format!("duplicate Unicorn comparison round ID: {round_id}"));
        }
        round_ids.push(round_id);
    }

    let baseline = rounds[0].bundle;
    let module_name = baseline.module_name.clone();
    let binary_sha256 = baseline.binary_sha256.to_ascii_lowercase();
    let mut total_offset_entries = 0usize;
    for (index, round) in rounds.iter().enumerate() {
        let bundle = round.bundle;
        if bundle.module_name != module_name {
            return Err(format!(
                "Unicorn comparison round {} module {} does not match baseline {}",
                round_ids[index], bundle.module_name, module_name
            ));
        }
        if !bundle.binary_identity_matched
            || !bundle.binary_sha256.eq_ignore_ascii_case(&binary_sha256)
            || !bundle
                .expected_binary_sha256
                .eq_ignore_ascii_case(&binary_sha256)
        {
            return Err(format!(
                "Unicorn comparison round {} does not use the same exact ELF SHA-256",
                round_ids[index]
            ));
        }
        total_offset_entries = total_offset_entries.saturating_add(
            bundle
                .runs
                .iter()
                .map(|run| {
                    run.executed_offsets
                        .len()
                        .saturating_add(run.block_offsets.len())
                })
                .sum::<usize>(),
        );
    }
    if total_offset_entries > MAX_COMPARISON_OFFSET_ENTRIES {
        return Err(format!(
            "Unicorn round comparison contains more than {MAX_COMPARISON_OFFSET_ENTRIES} recorded offset entries"
        ));
    }

    let round_observations = rounds
        .iter()
        .map(|round| build_round_observations(round.bundle))
        .collect::<Vec<_>>();
    let mut seed_offsets = BTreeSet::new();
    for observations in &round_observations {
        seed_offsets.extend(observations.keys().cloned());
    }

    let mut cumulative_executed = BTreeSet::new();
    let mut cumulative_blocks = BTreeSet::new();
    let mut round_summaries = Vec::with_capacity(rounds.len());
    let mut warnings = Vec::new();
    let mut baseline_seed_offsets = None::<BTreeSet<String>>;
    for (round_index, round) in rounds.iter().enumerate() {
        let bundle = round.bundle;
        let observations = &round_observations[round_index];
        let current_seed_offsets = observations.keys().cloned().collect::<BTreeSet<_>>();
        if let Some(baseline_seed_offsets) = &baseline_seed_offsets {
            if baseline_seed_offsets != &current_seed_offsets {
                warnings.push(format!(
                    "Round {} uses a different exact seed-offset set from the baseline; added/removed seeds are reported as incomplete comparisons.",
                    round_ids[round_index]
                ));
            }
        } else {
            baseline_seed_offsets = Some(current_seed_offsets);
        }
        let all_executed = observations
            .values()
            .flat_map(|value| value.executed_offsets.iter().cloned())
            .collect::<BTreeSet<_>>();
        let all_blocks = observations
            .values()
            .flat_map(|value| value.block_offsets.iter().cloned())
            .collect::<BTreeSet<_>>();
        let new_executed = difference(&all_executed, &cumulative_executed);
        let new_blocks = difference(&all_blocks, &cumulative_blocks);
        let (new_executed_offsets, new_executed_offsets_truncated) = bounded_offsets(&new_executed);
        let (new_block_offsets, new_block_offsets_truncated) = bounded_offsets(&new_blocks);
        cumulative_executed.extend(all_executed.iter().cloned());
        cumulative_blocks.extend(all_blocks.iter().cloned());
        let mut stop_reason_counts = BTreeMap::new();
        for run in &bundle.runs {
            *stop_reason_counts
                .entry(run.stop_reason.clone())
                .or_insert(0) += 1;
        }
        let matched_dispatcher_offsets = sorted_offsets(
            observations
                .values()
                .flat_map(|value| value.matched_dispatcher_offsets.iter().cloned()),
        );
        let config_matches_baseline = bundle.config == baseline.config;
        if !config_matches_baseline {
            warnings.push(format!(
                "Round {} changed Unicorn bounds/configuration; instruction-count and stop-reason differences are not directly attributable to recaptured state alone.",
                round_ids[round_index]
            ));
        }
        let execution_data_truncated = observations
            .values()
            .any(|value| value.execution_data_truncated);
        if execution_data_truncated {
            warnings.push(format!(
                "Round {} contains truncated execution or recapture-plan data; absence of new offsets is not proof of no progress.",
                round_ids[round_index]
            ));
        }
        round_summaries.push(UnicornOllvmRoundSummary {
            round_index: round_index as u32,
            round_id: round_ids[round_index].clone(),
            source_label: round.source_label.map(str::to_string),
            run_count: bundle.runs.len() as u32,
            seed_offset_count: observations.len() as u32,
            total_instruction_count: bundle.runs.iter().fold(0u64, |total, run| {
                total.saturating_add(run.instruction_count)
            }),
            unique_executed_offset_count: all_executed.len() as u64,
            unique_block_offset_count: all_blocks.len() as u64,
            new_executed_offset_count: new_executed.len() as u64,
            new_executed_offsets,
            new_executed_offsets_truncated,
            new_block_offset_count: new_blocks.len() as u64,
            new_block_offsets,
            new_block_offsets_truncated,
            stop_reason_counts,
            matched_dispatcher_offsets,
            missing_memory_count: observations
                .values()
                .map(|value| value.missing_memory_count)
                .sum(),
            register_relative_missing_count: observations
                .values()
                .map(|value| value.register_relative_missing_count)
                .sum(),
            recapture_suggestion_count: bundle.recapture_suggestions.len() as u64,
            carry_forward_window_count: bundle
                .seed_recapture_plans
                .iter()
                .map(|plan| plan.windows.len() as u64)
                .sum(),
            carry_forward_bytes: bundle
                .seed_recapture_plans
                .iter()
                .map(|plan| plan.carry_forward_bytes)
                .sum(),
            unsupported_seed_region_count: bundle
                .seed_recapture_plans
                .iter()
                .map(|plan| plan.unsupported_memory_region_count)
                .sum(),
            config_matches_baseline,
            execution_data_truncated,
            error_run_count: bundle.runs.iter().filter(|run| run.error.is_some()).count() as u64,
            warning_count: bundle.warnings.len() as u64
                + bundle
                    .runs
                    .iter()
                    .map(|run| run.warnings.len() as u64)
                    .sum::<u64>(),
        });
    }

    let mut seed_comparisons = Vec::with_capacity(seed_offsets.len());
    let mut progressed_seed_count = 0u32;
    let mut stalled_seed_count = 0u32;
    let mut regressed_seed_count = 0u32;
    let mut changed_seed_count = 0u32;
    let mut incomplete_seed_count = 0u32;
    for capture_offset in sorted_offsets(seed_offsets.into_iter()) {
        let mut observations = Vec::with_capacity(rounds.len());
        let mut matched_probe_offsets = BTreeSet::new();
        let mut deltas = Vec::with_capacity(rounds.len().saturating_sub(1));
        let mut seed_warnings = Vec::new();
        for (round_index, round_id) in round_ids.iter().enumerate() {
            let internal = round_observations[round_index].get(&capture_offset);
            if let Some(internal) = internal {
                matched_probe_offsets.extend(internal.matched_probe_offsets.iter().cloned());
                if internal.run_count > 1 {
                    seed_warnings.push(format!(
                        "Round {round_id} contains {} replay events at {capture_offset}; observations were aggregated by exact seed offset.",
                        internal.run_count
                    ));
                }
                if internal
                    .missing_signatures
                    .iter()
                    .any(|signature| signature.contains("|absolute:"))
                {
                    seed_warnings.push(format!(
                        "Round {round_id} includes absolute-address missing-memory signatures at {capture_offset}; ASLR or heap allocation changes can make equality weaker than register-relative comparison."
                    ));
                }
            }
            observations.push(public_observation(round_index, round_id, internal));
            if round_index > 0 {
                deltas.push(build_delta(
                    round_index - 1,
                    &round_ids[round_index - 1],
                    round_observations[round_index - 1].get(&capture_offset),
                    round_index,
                    round_id,
                    internal,
                ));
            }
        }
        seed_warnings.sort();
        seed_warnings.dedup();
        let latest_status = deltas
            .last()
            .map(|delta| delta.status.clone())
            .unwrap_or_else(|| "not-compared".to_string());
        let latest_recommendation = deltas
            .last()
            .map(|delta| delta.recommendation.clone())
            .unwrap_or_else(|| "Collect at least two aligned rounds.".to_string());
        match status_bucket(&latest_status) {
            "progressed" => progressed_seed_count = progressed_seed_count.saturating_add(1),
            "stalled" => stalled_seed_count = stalled_seed_count.saturating_add(1),
            "regressed" => regressed_seed_count = regressed_seed_count.saturating_add(1),
            "incomplete" => incomplete_seed_count = incomplete_seed_count.saturating_add(1),
            _ => changed_seed_count = changed_seed_count.saturating_add(1),
        }
        seed_comparisons.push(UnicornOllvmSeedRoundComparison {
            capture_offset,
            matched_probe_offsets: sorted_offsets(matched_probe_offsets.into_iter()),
            observations,
            deltas,
            latest_status,
            latest_recommendation,
            warnings: seed_warnings,
        });
    }

    let (overall_status, overall_recommendation) = if regressed_seed_count > 0 {
        (
            "regression-present",
            "At least one seed lost recorded coverage. Restore prior seed memory/context and inspect failed or unsupported recapture windows.",
        )
    } else if stalled_seed_count > 0 {
        (
            "stalled-seeds-present",
            "At least one seed is no longer gaining bounded coverage. Prefer a closer manual checkpoint or bounded angr exploration for those seeds instead of repeating the same recapture unchanged.",
        )
    } else if progressed_seed_count > 0 {
        (
            "candidate-progress-observed",
            "Review newly reached blocks/dispatchers and continue bounded recapture only for explicit remaining missing state.",
        )
    } else if changed_seed_count > 0 {
        (
            "changed-without-proven-progress",
            "Outcomes changed without monotonic bounded coverage. Check controlled inputs, threads, capture points, and configuration before continuing.",
        )
    } else {
        (
            "comparison-incomplete",
            "Align the same exact seed offsets across at least two rounds before drawing a progress conclusion.",
        )
    };

    warnings.sort();
    warnings.dedup();
    Ok(UnicornOllvmRoundComparisonReport {
        schema_version: UNICORN_ROUND_COMPARISON_SCHEMA.to_string(),
        module_name,
        binary_sha256,
        round_count: rounds.len() as u32,
        seed_offset_count: seed_comparisons.len() as u32,
        total_unique_executed_offset_count: cumulative_executed.len() as u64,
        total_unique_block_offset_count: cumulative_blocks.len() as u64,
        progressed_seed_count,
        stalled_seed_count,
        regressed_seed_count,
        changed_seed_count,
        incomplete_seed_count,
        overall_status: overall_status.to_string(),
        overall_recommendation: overall_recommendation.to_string(),
        rounds: round_summaries,
        seeds: seed_comparisons,
        warnings,
        limitations: vec![
            "This report compares bounded exact-seed concrete replays only. New coverage or a new dispatcher is Candidate/Related evidence for the captured states, not a recovered complete CFG.".to_string(),
            "A missing offset in recorded execution can result from truncation, changed concrete input/state, or a different path; it does not prove the offset became unreachable.".to_string(),
            "Trace UI reads validated result files and compares them, but it never executes Unicorn, angr, Frida, or the generated scripts.".to_string(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::angr::AngrOllvmFridaSeedProvenance;
    use crate::query::unicorn::{
        UnicornOllvmConfig, UnicornRecaptureSuggestion, UnicornSeedQuality,
        UnicornSeedRecapturePlan,
    };

    fn bundle(
        sha: &str,
        stop_reason: &str,
        instruction_count: u64,
        executed_offsets: &[&str],
        block_offsets: &[&str],
        missing_pc: Option<&str>,
        dispatcher: Option<&str>,
    ) -> UnicornOllvmResultBundle {
        let missing_memory = missing_pc
            .map(|pc| {
                vec![UnicornMissingMemory {
                    access: "read".to_string(),
                    address: "0x60000020".to_string(),
                    size: 8,
                    pc_offset: Some(pc.to_string()),
                    instruction: Some("ldr x0, [x19, #0x20]".to_string()),
                    base_register: Some("X19".to_string()),
                    displacement: Some("0x20".to_string()),
                }]
            })
            .unwrap_or_default();
        let event = 7;
        UnicornOllvmResultBundle {
            schema: "trace-ui/unicorn-ollvm-v1".to_string(),
            module_name: "libtarget.so".to_string(),
            binary_sha256: sha.to_string(),
            expected_binary_sha256: sha.to_string(),
            binary_identity_matched: true,
            architecture: "AArch64".to_string(),
            unicorn_version: "2.1.4".to_string(),
            capstone_version: "5.0.6".to_string(),
            config: UnicornOllvmConfig::default(),
            seeds: vec![AngrOllvmFridaSeedProvenance {
                source_event_index: event,
                hook_id: "seed".to_string(),
                call_id: None,
                module_name: "libtarget.so".to_string(),
                function_name: "dispatcher".to_string(),
                capture_offset: "0x100".to_string(),
                registers_seeded: vec!["x19".to_string()],
                memory_region_count: 1,
                matched_probe_offsets: vec!["0x100".to_string()],
                matched_branch_offsets: Vec::new(),
                matched_dispatcher_offsets: vec!["0x100".to_string()],
            }],
            seed_qualities: vec![UnicornSeedQuality {
                source_event_index: event,
                capture_offset: "0x100".to_string(),
                status: "ready".to_string(),
                register_count: 1,
                missing_registers: Vec::new(),
                memory_region_count: 1,
                captured_memory_bytes: 8,
                stack_memory_captured: false,
                warnings: Vec::new(),
            }],
            seed_recapture_plans: vec![UnicornSeedRecapturePlan {
                source_event_index: event,
                capture_offset: "0x100".to_string(),
                windows: Vec::new(),
                carry_forward_bytes: 0,
                unsupported_memory_region_count: 0,
                windows_truncated: false,
            }],
            runs: vec![UnicornReplayRun {
                source_event_index: event,
                seed_kind: "frida-capture-exact-dispatcher".to_string(),
                start_offset: "0x100".to_string(),
                mapped_base: "0x40000000".to_string(),
                stop_reason: stop_reason.to_string(),
                instruction_count,
                elapsed_ms: 1,
                terminal_address: "0x40000180".to_string(),
                terminal_offset: missing_pc
                    .map(str::to_string)
                    .or_else(|| dispatcher.map(str::to_string)),
                matched_dispatcher_offset: dispatcher.map(str::to_string),
                source_state_values: Vec::new(),
                target_state_values: Vec::new(),
                executed_offsets: executed_offsets
                    .iter()
                    .map(|value| value.to_string())
                    .collect(),
                executed_offsets_truncated: false,
                block_offsets: block_offsets
                    .iter()
                    .map(|value| value.to_string())
                    .collect(),
                block_offsets_truncated: false,
                register_changes: Vec::new(),
                memory_writes: Vec::new(),
                memory_writes_truncated: false,
                call_boundaries: Vec::new(),
                missing_memory,
                warnings: Vec::new(),
                error: None,
            }],
            transition_matrix: Vec::new(),
            recapture_suggestions: missing_pc
                .map(|pc| {
                    vec![UnicornRecaptureSuggestion {
                        pc_offset: pc.to_string(),
                        base_register: Some("X19".to_string()),
                        displacement: Some("0x20".to_string()),
                        byte_length: 8,
                        reason: "capture X19+0x20".to_string(),
                        source_event_indices: vec![event],
                    }]
                })
                .unwrap_or_default(),
            warnings: Vec::new(),
        }
    }

    fn retarget_single_seed(bundle: &mut UnicornOllvmResultBundle, event: u64, offset: &str) {
        bundle.seeds[0].source_event_index = event;
        bundle.seeds[0].capture_offset = offset.to_string();
        bundle.seeds[0].matched_probe_offsets = vec![offset.to_string()];
        bundle.seeds[0].matched_dispatcher_offsets = vec![offset.to_string()];
        bundle.seed_qualities[0].source_event_index = event;
        bundle.seed_qualities[0].capture_offset = offset.to_string();
        bundle.seed_recapture_plans[0].source_event_index = event;
        bundle.seed_recapture_plans[0].capture_offset = offset.to_string();
        bundle.runs[0].source_event_index = event;
        bundle.runs[0].start_offset = offset.to_string();
        for suggestion in &mut bundle.recapture_suggestions {
            suggestion.source_event_indices = vec![event];
        }
    }

    #[test]
    fn classifies_moved_missing_memory_with_new_coverage_as_progress() {
        let sha = "a".repeat(64);
        let first = bundle(
            &sha,
            "missing-memory",
            4,
            &["0x100", "0x104"],
            &["0x100"],
            Some("0x180"),
            None,
        );
        let second = bundle(
            &sha,
            "missing-memory",
            8,
            &["0x100", "0x104", "0x108"],
            &["0x100", "0x108"],
            Some("0x184"),
            None,
        );
        let report = compare_unicorn_ollvm_rounds(&[
            UnicornOllvmRoundInput {
                round_id: "round-1",
                source_label: None,
                bundle: &first,
            },
            UnicornOllvmRoundInput {
                round_id: "round-2",
                source_label: None,
                bundle: &second,
            },
        ])
        .unwrap();
        assert_eq!(report.progressed_seed_count, 1);
        assert_eq!(
            report.seeds[0].latest_status,
            "missing-memory-moved-forward"
        );
        assert_eq!(report.seeds[0].deltas[0].new_block_offset_count, 1);
        assert_eq!(report.rounds[1].new_executed_offset_count, 1);
    }

    #[test]
    fn detects_repeated_missing_memory_stall() {
        let sha = "b".repeat(64);
        let first = bundle(
            &sha,
            "missing-memory",
            4,
            &["0x100", "0x104"],
            &["0x100"],
            Some("0x180"),
            None,
        );
        let second = first.clone();
        let report = compare_unicorn_ollvm_rounds(&[
            UnicornOllvmRoundInput {
                round_id: "round-1",
                source_label: None,
                bundle: &first,
            },
            UnicornOllvmRoundInput {
                round_id: "round-2",
                source_label: None,
                bundle: &second,
            },
        ])
        .unwrap();
        assert_eq!(report.stalled_seed_count, 1);
        assert_eq!(report.seeds[0].latest_status, "stalled-same-missing-memory");
        assert!(report.seeds[0]
            .latest_recommendation
            .contains("closer manual checkpoint"));
    }

    #[test]
    fn recognizes_new_dispatcher_and_rejects_binary_mismatch() {
        let first_sha = "c".repeat(64);
        let second_sha = "d".repeat(64);
        let first = bundle(
            &first_sha,
            "missing-memory",
            4,
            &["0x100"],
            &["0x100"],
            Some("0x180"),
            None,
        );
        let second = bundle(
            &first_sha,
            "next-dispatcher",
            10,
            &["0x100", "0x108", "0x200"],
            &["0x100", "0x108", "0x200"],
            None,
            Some("0x200"),
        );
        let report = compare_unicorn_ollvm_rounds(&[
            UnicornOllvmRoundInput {
                round_id: "before",
                source_label: None,
                bundle: &first,
            },
            UnicornOllvmRoundInput {
                round_id: "after",
                source_label: None,
                bundle: &second,
            },
        ])
        .unwrap();
        assert_eq!(report.seeds[0].latest_status, "reached-new-dispatcher");

        let mismatched = bundle(
            &second_sha,
            "next-dispatcher",
            10,
            &["0x100", "0x200"],
            &["0x100", "0x200"],
            None,
            Some("0x200"),
        );
        let error = compare_unicorn_ollvm_rounds(&[
            UnicornOllvmRoundInput {
                round_id: "before",
                source_label: None,
                bundle: &first,
            },
            UnicornOllvmRoundInput {
                round_id: "wrong-binary",
                source_label: None,
                bundle: &mismatched,
            },
        ])
        .unwrap_err();
        assert!(error.contains("same exact ELF SHA-256"));
    }

    #[test]
    fn treats_lost_coverage_at_the_same_missing_memory_as_regression() {
        let sha = "e".repeat(64);
        let first = bundle(
            &sha,
            "missing-memory",
            6,
            &["0x100", "0x104", "0x108"],
            &["0x100", "0x108"],
            Some("0x180"),
            None,
        );
        let second = bundle(
            &sha,
            "missing-memory",
            3,
            &["0x100"],
            &["0x100"],
            Some("0x180"),
            None,
        );
        let report = compare_unicorn_ollvm_rounds(&[
            UnicornOllvmRoundInput {
                round_id: "before",
                source_label: None,
                bundle: &first,
            },
            UnicornOllvmRoundInput {
                round_id: "after",
                source_label: None,
                bundle: &second,
            },
        ])
        .unwrap();
        assert_eq!(report.seeds[0].latest_status, "regressed-coverage");
        assert_eq!(report.overall_status, "regression-present");
    }

    #[test]
    fn reports_seed_addition_and_removal_as_incomplete() {
        let sha = "f".repeat(64);
        let first = bundle(&sha, "return", 4, &["0x100"], &["0x100"], None, None);
        let mut second = first.clone();
        retarget_single_seed(&mut second, 8, "0x200");
        let report = compare_unicorn_ollvm_rounds(&[
            UnicornOllvmRoundInput {
                round_id: "round-1",
                source_label: None,
                bundle: &first,
            },
            UnicornOllvmRoundInput {
                round_id: "round-2",
                source_label: None,
                bundle: &second,
            },
        ])
        .unwrap();
        assert_eq!(report.incomplete_seed_count, 2);
        assert_eq!(report.seeds[0].latest_status, "seed-removed");
        assert_eq!(report.seeds[1].latest_status, "seed-added");
    }

    #[test]
    fn warns_for_config_drift_truncation_duplicate_seed_and_absolute_missing_memory() {
        let sha = "1".repeat(64);
        let mut first = bundle(
            &sha,
            "missing-memory",
            4,
            &["0x100", "0x104"],
            &["0x100"],
            Some("0x180"),
            None,
        );
        first.runs[0].missing_memory[0].base_register = None;
        first.runs[0].missing_memory[0].displacement = None;

        let mut second = first.clone();
        second.config.max_instructions += 1;
        second.runs[0].executed_offsets_truncated = true;
        let mut duplicate_seed = second.seeds[0].clone();
        duplicate_seed.source_event_index = 8;
        duplicate_seed.hook_id = "duplicate-seed".to_string();
        second.seeds.push(duplicate_seed);
        let mut duplicate_quality = second.seed_qualities[0].clone();
        duplicate_quality.source_event_index = 8;
        second.seed_qualities.push(duplicate_quality);
        let mut duplicate_plan = second.seed_recapture_plans[0].clone();
        duplicate_plan.source_event_index = 8;
        second.seed_recapture_plans.push(duplicate_plan);
        let mut duplicate_run = second.runs[0].clone();
        duplicate_run.source_event_index = 8;
        second.runs.push(duplicate_run);

        let report = compare_unicorn_ollvm_rounds(&[
            UnicornOllvmRoundInput {
                round_id: "baseline",
                source_label: None,
                bundle: &first,
            },
            UnicornOllvmRoundInput {
                round_id: "changed",
                source_label: None,
                bundle: &second,
            },
        ])
        .unwrap();
        assert!(!report.rounds[1].config_matches_baseline);
        assert!(report.rounds[1].execution_data_truncated);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("changed Unicorn bounds/configuration")));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("truncated execution")));
        assert!(report.seeds[0]
            .warnings
            .iter()
            .any(|warning| warning.contains("observations were aggregated")));
        assert!(report.seeds[0]
            .warnings
            .iter()
            .any(|warning| warning.contains("absolute-address missing-memory")));
    }

    #[test]
    fn enforces_round_id_and_round_count_boundaries() {
        let sha = "2".repeat(64);
        let base = bundle(&sha, "return", 4, &["0x100"], &["0x100"], None, None);
        let duplicate_id_error = compare_unicorn_ollvm_rounds(&[
            UnicornOllvmRoundInput {
                round_id: "same",
                source_label: None,
                bundle: &base,
            },
            UnicornOllvmRoundInput {
                round_id: "same",
                source_label: None,
                bundle: &base,
            },
        ])
        .unwrap_err();
        assert!(duplicate_id_error.contains("duplicate Unicorn comparison round ID"));

        let one_round = [UnicornOllvmRoundInput {
            round_id: "only",
            source_label: None,
            bundle: &base,
        }];
        assert!(compare_unicorn_ollvm_rounds(&one_round).is_err());

        let bundles = vec![base.clone(); 17];
        let ids = (0..17)
            .map(|index| format!("round-{index}"))
            .collect::<Vec<_>>();
        let inputs = bundles
            .iter()
            .zip(ids.iter())
            .map(|(bundle, round_id)| UnicornOllvmRoundInput {
                round_id,
                source_label: None,
                bundle,
            })
            .collect::<Vec<_>>();
        assert!(compare_unicorn_ollvm_rounds(&inputs[..16]).is_ok());
        assert!(compare_unicorn_ollvm_rounds(&inputs).is_err());
    }
}
