//! Test harness plumbing: env-configured binaries, child processes with log
//! files, and failure reports that include those logs. Adapted from the
//! bip300301_enforcer integration tests.

use std::{
    collections::{BTreeSet, HashMap},
    ffi::OsStr,
    future::Future,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use anyhow::{Context as _, anyhow};
use parking_lot::Mutex;
use tokio::task::JoinHandle;

/// Binaries, from env vars (or the env file named by
/// `FASTWITHDRAW_INTEGRATION_TEST_ENV`).
#[derive(Clone, Debug)]
pub struct BinPaths {
    pub bitcoind: PathBuf,
    pub enforcer: PathBuf,
    pub electrs: PathBuf,
    pub thunder: PathBuf,
    pub api: PathBuf,
    pub wallet: PathBuf,
    pub pkcs11_tool: PathBuf,
    pub sweep: PathBuf,
    pub softhsm2_util: PathBuf,
    pub softhsm2_module: PathBuf,
}

impl BinPaths {
    pub fn from_env() -> anyhow::Result<Self> {
        let var = |key: &str| -> anyhow::Result<PathBuf> {
            std::env::var_os(key).map(PathBuf::from).with_context(|| {
                format!("missing env var `{key}`; run scripts/setup_integration_tests.sh")
            })
        };
        Ok(Self {
            bitcoind: var("BITCOIND")?,
            enforcer: var("BIP300301_ENFORCER")?,
            electrs: var("ELECTRS")?,
            thunder: var("THUNDER")?,
            api: var("FASTWITHDRAW_API")?,
            wallet: var("FASTWITHDRAW_WALLET")?,
            pkcs11_tool: var("FASTWITHDRAW_PKCS11")?,
            // Built alongside the api.
            sweep: var("FASTWITHDRAW_API")?.with_file_name("thunder-sweep"),
            softhsm2_util: var("SOFTHSM2_UTIL")?,
            softhsm2_module: var("SOFTHSM2_MODULE")?,
        })
    }
}

/// `(label, path)` of each log file, per test.
type LogFiles = HashMap<String, Vec<(String, PathBuf)>>;

/// Log files per test, dumped when the test fails.
#[derive(Clone, Default)]
pub struct LogRegistry(Arc<Mutex<LogFiles>>);

impl LogRegistry {
    pub fn register(&self, test: &str, label: impl Into<String>, path: PathBuf) {
        self.0
            .lock()
            .entry(test.to_owned())
            .or_default()
            .push((label.into(), path));
    }

    fn render(&self, test: &str) -> String {
        const TAIL_LINES: usize = 60;
        let mut out = String::new();
        for (label, path) in self.0.lock().get(test).cloned().unwrap_or_default() {
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            let lines: Vec<&str> = content.lines().collect();
            if lines.is_empty() {
                continue;
            }
            let tail = &lines[lines.len().saturating_sub(TAIL_LINES)..];
            out.push_str(&format!("\n--- {label} ({}) ---\n", path.display()));
            out.push_str(&tail.join("\n"));
            out.push('\n');
        }
        out
    }
}

/// `(test name, error, logs)` for every failed test.
#[derive(Clone, Default)]
pub struct Failures(Arc<Mutex<Vec<(String, String, String)>>>);

impl Failures {
    #[expect(clippy::print_stderr)]
    pub fn display(&self) {
        let failures = self.0.lock();
        for (test, error, logs) in failures.iter() {
            eprintln!("\n{}\nFAILED: {test}\nError: {error}{logs}", "=".repeat(80));
        }
    }
}

static TIMINGS: LazyLock<Mutex<Vec<(String, Duration)>>> = LazyLock::new(Default::default);

#[expect(clippy::print_stderr)]
pub fn display_timings(wall: Duration) {
    let mut timings = TIMINGS.lock().clone();
    timings.sort_by_key(|(_, duration)| std::cmp::Reverse(*duration));
    eprintln!(
        "\n{} tests in {:.1}s wall",
        timings.len(),
        wall.as_secs_f64()
    );
    for (name, duration) in timings {
        eprintln!("  {:>6.1}s  {name}", duration.as_secs_f64());
    }
}

/// Wraps an async test as a libtest-mimic trial with a timeout and log dumps.
pub fn trial<F, Fut>(
    name: &'static str,
    rt: tokio::runtime::Handle,
    logs: LogRegistry,
    failures: Failures,
    test: F,
) -> libtest_mimic::Trial
where
    F: FnOnce(TestContext) -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    const TIMEOUT: Duration = Duration::from_secs(15 * 60);
    libtest_mimic::Trial::test(name, move || {
        let started = Instant::now();
        let context = TestContext {
            name,
            logs: logs.clone(),
        };
        let result = std::thread::spawn(move || {
            rt.block_on(async {
                match tokio::time::timeout(TIMEOUT, test(context)).await {
                    Ok(result) => result,
                    Err(_) => Err(anyhow!("timed out after {TIMEOUT:?}")),
                }
            })
        })
        .join()
        .unwrap_or_else(|_| Err(anyhow!("test panicked")));
        TIMINGS.lock().push((name.to_owned(), started.elapsed()));
        if result.is_ok() {
            remove_test_dirs(name);
        }
        result.map_err(|err| {
            let error = format!("{err:#}");
            failures
                .0
                .lock()
                .push((name.to_owned(), error.clone(), logs.render(name)));
            error.into()
        })
    })
}

/// Root of the per-test directories.
pub fn test_root() -> PathBuf {
    std::env::temp_dir().join("fastwithdraw-it")
}

/// Removes a passed test's directories; failed tests keep theirs for
/// inspection. Best effort: its processes may still be exiting.
fn remove_test_dirs(name: &str) {
    let Ok(entries) = std::fs::read_dir(test_root()) else {
        return;
    };
    let prefix = format!("{name}-");
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            let _removed = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Environment variables children inherit from the harness. Everything else
/// is cleared, so stray config in the developer's shell or CI can't change
/// the services under test.
const INHERITED_ENV: &[&str] = &["PATH", "HOME", "TMPDIR", "LANG"];

fn clean_env(cmd: &mut tokio::process::Command) {
    cmd.env_clear();
    for key in INHERITED_ENV {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
}

#[derive(Clone)]
pub struct TestContext {
    pub name: &'static str,
    pub logs: LogRegistry,
}

/// PIDs of running children, killed on SIGINT/SIGTERM where no destructors run.
static LIVE_CHILDREN: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());

pub fn kill_live_children() -> usize {
    let pids: Vec<u32> = LIVE_CHILDREN.lock().iter().copied().collect();
    for pid in &pids {
        let _status = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status();
    }
    pids.len()
}

/// A child process that is killed when dropped.
pub struct Process {
    pub name: String,
    pid: Option<u32>,
    task: JoinHandle<()>,
    exited: Arc<Mutex<Option<String>>>,
}

impl Process {
    /// Spawns `command`, logging to `dir/{stdout,stderr}.txt`.
    pub fn spawn<I, S>(
        context: &TestContext,
        name: &str,
        dir: &Path,
        command: &Path,
        envs: &[(&str, String)],
        args: I,
    ) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        std::fs::create_dir_all(dir)?;
        let stdout = dir.join("stdout.txt");
        let stderr = dir.join("stderr.txt");
        context
            .logs
            .register(context.name, format!("{name} stdout"), stdout.clone());
        context
            .logs
            .register(context.name, format!("{name} stderr"), stderr.clone());
        let open = |path: &Path| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        };
        let mut cmd = tokio::process::Command::new(command);
        clean_env(&mut cmd);
        cmd.args(args)
            .envs(envs.iter().map(|(key, value)| (*key, value)))
            .stdout(open(&stdout)?)
            .stderr(open(&stderr)?)
            .kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn {name} ({})", command.display()))?;
        let pid = child.id();
        if let Some(pid) = pid {
            LIVE_CHILDREN.lock().insert(pid);
        }
        let exited = Arc::new(Mutex::new(None));
        let exited_clone = Arc::clone(&exited);
        let task = tokio::spawn(async move {
            let status = child.wait().await;
            if let Some(pid) = pid {
                LIVE_CHILDREN.lock().remove(&pid);
            }
            *exited_clone.lock() = Some(format!("{status:?}"));
        });
        Ok(Self {
            name: name.to_owned(),
            pid,
            task,
            exited,
        })
    }

    /// Fails if the process has exited.
    pub fn check_running(&self) -> anyhow::Result<()> {
        match &*self.exited.lock() {
            Some(status) => Err(anyhow!("{} exited: {status}", self.name)),
            None => Ok(()),
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // Dropping the aborted task drops the child, which kills it.
        self.task.abort();
        if let Some(pid) = self.pid {
            LIVE_CHILDREN.lock().remove(&pid);
        }
    }
}

/// Polls `check` until it succeeds, failing after `timeout`.
pub async fn wait_for<T, F, Fut>(what: &str, timeout: Duration, mut check: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    let deadline = Instant::now() + timeout;
    loop {
        // A hung check must not outlive the deadline either.
        let remaining = deadline.saturating_duration_since(Instant::now());
        let attempt = tokio::time::timeout(remaining.max(Duration::from_millis(250)), check())
            .await
            .unwrap_or_else(|_| Err(anyhow!("check hung")));
        match attempt {
            Ok(value) => return Ok(value),
            Err(err) if Instant::now() >= deadline => {
                return Err(err.context(format!("timed out waiting for {what}")));
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

/// A free localhost port, skipping ports another process already answers on.
pub fn reserve_port() -> anyhow::Result<u16> {
    for _ in 0..32 {
        let reserved = reserve_port::ReservedPort::random()?;
        let port = reserved.port();
        // Keep the reservation for the rest of the run.
        std::mem::forget(reserved);
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_err() {
            return Ok(port);
        }
    }
    Err(anyhow!("no free port"))
}

/// Runs `command` to completion, failing on a non-zero exit.
pub async fn run(command: &Path, envs: &[(&str, String)], args: &[&str]) -> anyhow::Result<String> {
    run_with_stdin(command, envs, args, "").await
}

/// [`run`], writing `stdin` to the command's standard input.
pub async fn run_with_stdin(
    command: &Path,
    envs: &[(&str, String)],
    args: &[&str],
    stdin: &str,
) -> anyhow::Result<String> {
    use tokio::io::AsyncWriteExt as _;
    let mut cmd = tokio::process::Command::new(command);
    clean_env(&mut cmd);
    let mut child = cmd
        .args(args)
        .envs(envs.iter().map(|(key, value)| (*key, value)))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("run {}", command.display()))?;
    let mut input = child.stdin.take().context("no stdin")?;
    input.write_all(stdin.as_bytes()).await?;
    drop(input);
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(anyhow!(
            "{} {args:?} failed ({}): {}",
            command.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
