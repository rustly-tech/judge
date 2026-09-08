//! Standalone judge broker binary.

use anyhow::Context as _;
use clap::Parser;
use rustly_judge_broker::{routes, Queue};

/// A standalone, self-hostable judge broker.
///
/// This is not the hosted Rustly broker - that lives in the control plane, where
/// trust decisions belong. Use this to run the judge offline, in a lab, or when
/// developing a worker.
#[derive(Debug, Parser)]
#[command(name = "rustly-judge-broker", version, about)]
struct Args {
    /// Address to bind.
    #[arg(long, env = "RUSTLY_BROKER_BIND", default_value = "127.0.0.1:8090")]
    bind: String,

    /// Emit JSON logs.
    #[arg(long, env = "RUSTLY_LOG_FORMAT", default_value_t = false)]
    json_logs: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if args.json_logs {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .compact()
            .with_env_filter(filter)
            .init();
    }

    if !args.bind.starts_with("127.0.0.1") && !args.bind.starts_with("localhost") {
        tracing::warn!(
            bind = %args.bind,
            "this broker has no authentication; expose it only on a trusted network"
        );
    }

    let queue = Queue::new();
    let listener = tokio::net::TcpListener::bind(&args.bind)
        .await
        .with_context(|| format!("binding {}", args.bind))?;
    tracing::info!(bind = %args.bind, "rustly-judge-broker listening");

    axum::serve(listener, routes::router(queue))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await
        .context("serving")?;
    Ok(())
}
