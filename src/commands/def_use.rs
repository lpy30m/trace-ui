use serde::Serialize;
use tauri::State;
use crate::taint::def_use::determine_def_use;
use crate::taint::insn_class;
use crate::taint::parser;
use crate::taint::types::parse_reg;
use crate::state::AppState;

/// 单次扫描最大行数（避免 24M 行全扫描卡顿）
const MAX_SCAN_RANGE: u32 = 50000;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefUseChain {
    pub def_seq: Option<u32>,
    pub use_seqs: Vec<u32>,
    pub redefined_seq: Option<u32>,
}

#[tauri::command]
pub fn get_reg_def_use_chain(
    session_id: String,
    seq: u32,
    reg_name: String,
    state: State<'_, AppState>,
) -> Result<DefUseChain, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} 不存在", session_id))?;

    let target_reg = parse_reg(&reg_name)
        .ok_or_else(|| format!("未知寄存器: {}", reg_name))?;

    let total = session.total_lines;

    // === 向上扫描：找最近一次 DEF 该寄存器的行 ===
    let mut def_seq: Option<u32> = None;
    if seq > 0 {
        let scan_start = seq.saturating_sub(MAX_SCAN_RANGE);
        for s in (scan_start..seq).rev() {
            if let Some(raw) = session.line_index.get_line(&session.mmap, s) {
                if let Ok(line_str) = std::str::from_utf8(raw) {
                    if let Some(parsed) = parser::parse_line(line_str) {
                        let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                        let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                        let (defs, _) = determine_def_use(cls, &parsed);
                        if defs.iter().any(|r| *r == target_reg) {
                            def_seq = Some(s);
                            break;
                        }
                    }
                }
            }
        }
    }

    // === 向下扫描：收集 USE 行，直到寄存器被重新 DEF ===
    let mut use_seqs: Vec<u32> = Vec::new();
    let mut redefined_seq: Option<u32> = None;
    let scan_end = total.min(seq + MAX_SCAN_RANGE);
    for s in (seq + 1)..scan_end {
        if let Some(raw) = session.line_index.get_line(&session.mmap, s) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                if let Some(parsed) = parser::parse_line(line_str) {
                    let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                    let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                    let (defs, uses) = determine_def_use(cls, &parsed);

                    // 先检查 USE（同一行可能既 USE 又 DEF，如 add x0, x0, #1）
                    if uses.iter().any(|r| *r == target_reg) {
                        use_seqs.push(s);
                    }

                    // 再检查 DEF（重新定义 = 扫描终点）
                    if defs.iter().any(|r| *r == target_reg) {
                        redefined_seq = Some(s);
                        break;
                    }
                }
            }
        }
    }

    Ok(DefUseChain {
        def_seq,
        use_seqs,
        redefined_seq,
    })
}
