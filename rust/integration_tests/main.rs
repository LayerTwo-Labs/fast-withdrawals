//! Integration test runner. Run with `just test-it [FILTER]`.

use fastwithdraw_integration_tests::{
    tests,
    util::{BinPaths, Failures, LogRegistry, display_timings, kill_live_children},
};

/// Kills child processes on SIGINT/SIGTERM, where no destructors run.
fn spawn_signal_cleanup() {
    use tokio::signal::unix::{SignalKind, signal};
    tokio::spawn(async {
        let (Ok(mut interrupt), Ok(mut terminate)) = (
            signal(SignalKind::interrupt()),
            signal(SignalKind::terminate()),
        ) else {
            return;
        };
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
        let killed = kill_live_children();
        #[expect(clippy::print_stderr)]
        {
            eprintln!("\ninterrupted: killed {killed} child process(es)");
        }
        std::process::exit(130);
    });
}

#[tokio::main]
async fn main() -> anyhow::Result<std::process::ExitCode> {
    spawn_signal_cleanup();
    if let Some(path) = std::env::var_os("FASTWITHDRAW_INTEGRATION_TEST_ENV") {
        // Variables already set in the environment win over the file.
        dotenvy::from_path(&path)?;
    }
    let args = libtest_mimic::Arguments::from_args();
    if std::env::var_os("RUST_LOG").is_some() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .init();
    }
    let bins = BinPaths::from_env()?;
    let logs = LogRegistry::default();
    let failures = Failures::default();
    let trials = tests::all(&bins, &tokio::runtime::Handle::current(), &logs, &failures);
    let started = std::time::Instant::now();
    let conclusion = tokio::task::spawn_blocking(move || libtest_mimic::run(&args, trials)).await?;
    display_timings(started.elapsed());
    failures.display();
    Ok(conclusion.exit_code())
}
