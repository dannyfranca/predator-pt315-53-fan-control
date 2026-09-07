use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const KERNEL_LOG: &str = "/dev/kmsg";
const MAX_KERNEL_RECORD_BYTES: usize = 8 * 1024;

pub(crate) struct SystemHealthMonitor {
    kernel_log: File,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SystemHealthObservation {
    pub(crate) system_stable: bool,
    pub(crate) kernel_faults: Vec<String>,
    pub(crate) nvidia_faults: Vec<String>,
}

impl SystemHealthMonitor {
    pub(crate) fn start() -> Result<Self, String> {
        Self::start_at(Path::new(KERNEL_LOG)).map_err(|error| {
            format!("cannot start root kernel-health observation at {KERNEL_LOG}: {error}")
        })
    }

    fn start_at(path: &Path) -> io::Result<Self> {
        let mut kernel_log = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        kernel_log.seek(SeekFrom::End(0))?;
        Ok(Self { kernel_log })
    }

    pub(crate) fn observe(&mut self) -> Result<SystemHealthObservation, String> {
        let mut kernel_faults = Vec::new();
        let mut nvidia_faults = Vec::new();
        loop {
            let mut record = [0_u8; MAX_KERNEL_RECORD_BYTES];
            match self.kernel_log.read(&mut record) {
                Ok(0) => break,
                Ok(length) => {
                    let (priority, message) = parse_kernel_record(&record[..length])?;
                    let is_nvidia_fault = is_nvidia_fault(&message);
                    if priority & 7 <= 3 {
                        kernel_faults.push(message.clone());
                    }
                    if is_nvidia_fault {
                        nvidia_faults.push(message);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(format!("cannot observe root kernel health: {error}")),
            }
        }
        Ok(SystemHealthObservation {
            system_stable: kernel_faults.is_empty() && nvidia_faults.is_empty(),
            kernel_faults,
            nvidia_faults,
        })
    }
}

fn parse_kernel_record(record: &[u8]) -> Result<(u8, String), String> {
    let record = std::str::from_utf8(record)
        .map_err(|_| "kernel-health record is not valid UTF-8".to_owned())?;
    let (metadata, payload) = record
        .split_once(';')
        .ok_or_else(|| "kernel-health record is malformed".to_owned())?;
    let priority = metadata
        .split(',')
        .next()
        .ok_or_else(|| "kernel-health record has no priority".to_owned())?
        .parse::<u8>()
        .map_err(|_| "kernel-health record priority is malformed".to_owned())?;
    Ok((priority, payload.trim_end().to_owned()))
}

fn is_nvidia_fault(message: &str) -> bool {
    message.contains("NVRM:") || message.contains("NVIDIA") && message.contains("Xid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_records_preserve_priority_and_message() {
        assert_eq!(
            parse_kernel_record(b"3,42,123456,-;fatal hardware fault\n").unwrap(),
            (3, "fatal hardware fault".into())
        );
        assert!(parse_kernel_record(b"not-a-record").is_err());
        assert!(parse_kernel_record(b"x,42,123456,-;bad priority").is_err());
    }

    #[test]
    fn nvidia_fault_matching_is_not_confused_with_generic_messages() {
        for (message, expected) in [
            ("NVRM: Xid (PCI:0000:01:00): 79", true),
            ("NVIDIA GPU Xid 79", true),
            ("NVIDIA driver initialized", false),
            ("unrelated Xid token", false),
        ] {
            assert_eq!(is_nvidia_fault(message), expected, "{message}");
        }
    }
}
