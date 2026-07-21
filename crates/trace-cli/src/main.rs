use std::sync::Arc;
use trace_core::TraceEngine;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let engine = Arc::new(TraceEngine::new());
    trace_mcp::start_stdio(engine).await
}
