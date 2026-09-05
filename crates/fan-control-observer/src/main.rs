use std::{
    env, fs,
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    process::ExitCode,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fan_control_observer::{AmbientTemperature, DEFAULT_SOCKET_PATH, PresenceTracker};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pt31553-fan-observer: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let (ambient, socket_path) = parse_arguments(env::args_os().skip(1))?;
    if unsafe { libc::geteuid() } != 0 {
        return Err("must run as root so the observer socket has protected identity".into());
    }
    validate_socket_parent(&socket_path)?;
    install_signal_handlers()?;
    let _terminal = TerminalMode::activate(io::stdin())?;
    let _socket = SocketPath::prepare(&socket_path)?;
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o666))?;
    listener.set_nonblocking(true)?;

    eprintln!(
        "Observer active at {:.3} C. Hold any key continuously; Ctrl-C stops.",
        f64::from(ambient.millicelsius()) / 1_000.0
    );
    let mut tracker = PresenceTracker::default();
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let mut input = [0_u8; 64];

    while !SHUTDOWN.load(Ordering::Relaxed) {
        let mut descriptor = libc::pollfd {
            fd: stdin.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd for the duration of the call.
        let poll_result = unsafe { libc::poll(&mut descriptor, 1, 100) };
        if poll_result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        } else if descriptor.revents & libc::POLLIN != 0 {
            match stdin.read(&mut input) {
                Ok(0) => return Err("observer terminal closed".into()),
                Ok(_) => tracker.record_activity(monotonic_millis()?),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }

        loop {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            stream.set_write_timeout(Some(Duration::from_millis(250)))?;
            let confirmation =
                tracker.confirmation(ambient, monotonic_millis()?, wall_unix_millis());
            serde_json::to_writer(&mut stream, &confirmation)?;
            stream.write_all(b"\n")?;
        }
    }
    Ok(())
}

fn parse_arguments(
    arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(AmbientTemperature, PathBuf), Box<dyn std::error::Error>> {
    let mut arguments = arguments;
    let mut ambient = None;
    let mut socket = PathBuf::from(DEFAULT_SOCKET_PATH);
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--ambient-celsius") if ambient.is_none() => {
                ambient = Some(
                    arguments
                        .next()
                        .ok_or("--ambient-celsius requires a value")?
                        .into_string()
                        .map_err(|_| "ambient temperature must be UTF-8")?
                        .parse()?,
                );
            }
            Some("--socket") => {
                socket = arguments.next().ok_or("--socket requires a path")?.into();
            }
            _ => return Err("usage: pt31553-fan-observer --ambient-celsius VALUE".into()),
        }
    }
    Ok((ambient.ok_or("--ambient-celsius is required")?, socket))
}

fn validate_socket_parent(socket_path: &Path) -> io::Result<()> {
    let parent = socket_path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "observer socket has no parent")
    })?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "observer socket parent must be a root-owned, non-writable directory",
        ));
    }
    Ok(())
}

struct SocketPath(PathBuf);

impl SocketPath {
    fn prepare(path: &Path) -> io::Result<Self> {
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && metadata.uid() == 0
                    && metadata.nlink() == 1 =>
            {
                if UnixStream::connect(path).is_ok() {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "another observer is already active",
                    ));
                }
                fs::remove_file(path)?;
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "refusing to replace an untrusted observer socket path",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(Self(path.to_owned()))
    }
}

impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct TerminalMode {
    fd: i32,
    original: libc::termios,
}

impl TerminalMode {
    fn activate(stdin: io::Stdin) -> io::Result<Self> {
        let fd = stdin.as_raw_fd();
        if unsafe { libc::isatty(fd) } != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stdin must be an interactive terminal",
            ));
        }
        let mut original = MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr initializes the termios value when it succeeds.
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful tcgetattr initialized original.
        let original = unsafe { original.assume_init() };
        let mut active = original;
        active.c_lflag &= !(libc::ICANON | libc::ECHO);
        active.c_cc[libc::VMIN] = 0;
        active.c_cc[libc::VTIME] = 0;
        // SAFETY: fd is a TTY and active is an initialized termios configuration.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &active) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, original })
    }
}

impl Drop for TerminalMode {
    fn drop(&mut self) {
        // SAFETY: fd remains the process stdin TTY; restoring is best-effort during shutdown.
        let _ = unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

extern "C" fn request_shutdown(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() -> io::Result<()> {
    // SAFETY: sigaction is zero-initializable before its fields are assigned below.
    let mut action = unsafe { MaybeUninit::<libc::sigaction>::zeroed().assume_init() };
    action.sa_sigaction = request_shutdown as *const () as usize;
    // SAFETY: action owns valid mask storage.
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: action contains a valid signal handler and mask.
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn monotonic_millis() -> io::Result<u64> {
    let mut timestamp = MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: timestamp points to writable storage for clock_gettime.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, timestamp.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful clock_gettime initialized timestamp.
    let timestamp = unsafe { timestamp.assume_init() };
    Ok(u64::try_from(timestamp.tv_sec)
        .unwrap_or(u64::MAX)
        .saturating_mul(1_000)
        .saturating_add(u64::try_from(timestamp.tv_nsec).unwrap_or(u64::MAX) / 1_000_000))
}

fn wall_unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}
