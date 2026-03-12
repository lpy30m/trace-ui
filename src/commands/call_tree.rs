use serde::Serialize;
use tauri::State;
use crate::state::AppState;

#[derive(Serialize)]
pub struct CallTreeNodeDto {
    pub id: u32,
    pub func_addr: String,
    pub entry_seq: u32,
    pub exit_seq: u32,
    pub parent_id: Option<u32>,
    pub children_ids: Vec<u32>,
    pub line_count: u32,
}

#[tauri::command]
pub fn get_call_tree(session_id: String, state: State<'_, AppState>) -> Result<Vec<CallTreeNodeDto>, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id).ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let phase2 = session.phase2.as_ref().ok_or("索引尚未构建完成")?;

    let nodes: Vec<CallTreeNodeDto> = phase2
        .call_tree
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| CallTreeNodeDto {
            id: i as u32,
            func_addr: format!("0x{:x}", n.func_addr),
            entry_seq: n.entry_seq,
            exit_seq: n.exit_seq,
            parent_id: n.parent_id,
            children_ids: n.children_ids.clone(),
            line_count: n.exit_seq.saturating_sub(n.entry_seq) + 1,
        })
        .collect();

    Ok(nodes)
}
