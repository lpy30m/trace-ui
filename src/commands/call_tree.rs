use serde::Serialize;
use tauri::State;
use crate::state::AppState;
use crate::taint::call_tree::CallTreeNode;

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

fn node_to_dto(n: &CallTreeNode) -> CallTreeNodeDto {
    CallTreeNodeDto {
        id: n.id,
        func_addr: format!("0x{:x}", n.func_addr),
        entry_seq: n.entry_seq,
        exit_seq: n.exit_seq,
        parent_id: n.parent_id,
        children_ids: n.children_ids.clone(),
        line_count: n.exit_seq.saturating_sub(n.entry_seq) + 1,
    }
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
        .map(node_to_dto)
        .collect();

    Ok(nodes)
}

/// 返回 call tree 节点总数
#[tauri::command]
pub fn get_call_tree_node_count(session_id: String, state: State<'_, AppState>) -> Result<u32, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id).ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let phase2 = session.phase2.as_ref().ok_or("索引尚未构建完成")?;
    Ok(phase2.call_tree.nodes.len() as u32)
}

/// 返回指定节点的直接子节点（可选包含自身）
#[tauri::command]
pub fn get_call_tree_children(
    session_id: String,
    node_id: u32,
    include_self: bool,
    state: State<'_, AppState>,
) -> Result<Vec<CallTreeNodeDto>, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id).ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let phase2 = session.phase2.as_ref().ok_or("索引尚未构建完成")?;

    let node = phase2.call_tree.nodes.get(node_id as usize)
        .ok_or_else(|| format!("节点 {} 不存在", node_id))?;

    let mut result = Vec::new();

    if include_self {
        result.push(node_to_dto(node));
    }

    for &child_id in &node.children_ids {
        if let Some(child) = phase2.call_tree.nodes.get(child_id as usize) {
            result.push(node_to_dto(child));
        }
    }

    Ok(result)
}
