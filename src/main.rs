use server_tester::cli::run_cli;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    run_cli().await
}