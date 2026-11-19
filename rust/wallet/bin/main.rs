use clap::Parser as _;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let logs = tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
    );
    // JSON for Cloud Logging, which turns each line's fields into a
    // queryable payload (alerts forward on the `alert` field).
    if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
        logs.json().flatten_event(true).init();
    } else {
        logs.with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
            .init();
    }
    fastwithdraw_wallet::run(fastwithdraw_wallet::Config::parse()).await
}
