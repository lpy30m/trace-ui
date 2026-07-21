use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegValue {
    pub reg: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionRef {
    pub func_id: u32,
    pub func_addr: String,
    pub func_name: Option<String>,
    pub entry_seq: u32,
    pub exit_seq: u32,
    pub line_count: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionCallAnnotation {
    pub func_name: String,
    pub is_jni: bool,
    pub args: Vec<RegValue>,
    pub ret_value: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemTouch {
    pub addr: String,
    pub count: u32,
    pub size: u8,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionInspection {
    pub func_id: u32,
    pub func_addr: String,
    pub func_name: Option<String>,
    pub entry_seq: u32,
    pub exit_seq: u32,
    pub line_count: u32,
    pub parent: Option<FunctionRef>,
    pub entry_args: Vec<RegValue>,
    pub return_value: Option<String>,
    pub call_annotation: Option<FunctionCallAnnotation>,
    pub children: Vec<FunctionRef>,
    pub child_count: u32,
    pub memory_reads: Vec<MemTouch>,
    pub memory_writes: Vec<MemTouch>,
    pub scanned_lines: u32,
    pub io_truncated: bool,
}
