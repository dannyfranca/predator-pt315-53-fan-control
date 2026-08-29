use std::{
    error::Error,
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use fan_control_core::{
    PromotionInputs, ProtectedFileRequirement, sanitize_qualification_evidence_v1,
    validate_promotion_manifest_v1, validate_root_owned_protected_file,
    write_root_owned_bytes_atomically,
};

pub trait PromotionArtifactIo {
    fn read_bytes(&mut self, path: &Path, label: &str) -> Result<Vec<u8>, Box<dyn Error>>;

    fn read_utf8(&mut self, path: &Path, label: &str) -> Result<String, Box<dyn Error>> {
        String::from_utf8(self.read_bytes(path, label)?)
            .map_err(|_| format!("{label} must be UTF-8").into())
    }

    fn publish(&mut self, path: &Path, payload: &[u8]) -> Result<(), Box<dyn Error>>;
}

pub struct RootProtectedArtifactIo;

impl PromotionArtifactIo for RootProtectedArtifactIo {
    fn read_bytes(&mut self, path: &Path, label: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        validate_root_owned_protected_file(path, ProtectedFileRequirement::Regular)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        #[cfg(unix)]
        let protected = metadata.file_type().is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.permissions().mode() & 0o022 == 0;
        #[cfg(not(unix))]
        let protected = metadata.file_type().is_file();
        if !protected {
            return Err(
                format!("{label} must be a unique protected root-owned regular file").into(),
            );
        }
        let mut bytes = Vec::new();
        file.take(128 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > 128 * 1024 * 1024 {
            return Err(format!("{label} has an invalid size").into());
        }
        Ok(bytes)
    }

    fn publish(&mut self, path: &Path, payload: &[u8]) -> Result<(), Box<dyn Error>> {
        write_root_owned_bytes_atomically(path, payload).map_err(Into::into)
    }
}

pub fn redact_evidence_command(
    mut values: impl Iterator<Item = OsString>,
    io: &mut impl PromotionArtifactIo,
) -> Result<PathBuf, Box<dyn Error>> {
    let mut qualification_record = None;
    let mut evidence = None;
    let mut authorized_evidence_path = None;
    let mut output = None;
    while let Some(flag) = values.next() {
        if flag == "--help" {
            return Err("help must be handled by the command entry point".into());
        }
        let value = values
            .next()
            .ok_or_else(|| format!("missing value for {}", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--qualification-record") => {
                set_path(&mut qualification_record, value, "--qualification-record")?
            }
            Some("--evidence") => set_path(&mut evidence, value, "--evidence")?,
            Some("--authorized-evidence-path") => {
                set_path(
                    &mut authorized_evidence_path,
                    value,
                    "--authorized-evidence-path",
                )?;
            }
            Some("--output") => set_path(&mut output, value, "--output")?,
            Some(flag) => return Err(format!("unknown argument: {flag}").into()),
            None => return Err("redact-evidence argument flags must be UTF-8".into()),
        }
    }
    let qualification_record = qualification_record.ok_or("--qualification-record is required")?;
    let evidence = evidence.ok_or("--evidence is required")?;
    let authorized_evidence_path =
        authorized_evidence_path.ok_or("--authorized-evidence-path is required")?;
    let output = output.ok_or("--output is required")?;
    if evidence != authorized_evidence_path {
        return Err("--evidence must be the exact authorized evidence path".into());
    }
    let qualification_source = io.read_utf8(&qualification_record, "qualification record")?;
    let evidence_source = io.read_utf8(&evidence, "supervised endurance evidence")?;
    let sanitized = sanitize_qualification_evidence_v1(
        &qualification_source,
        &evidence_source,
        &authorized_evidence_path,
    )?;
    io.publish(&output, sanitized.as_bytes())?;
    Ok(output)
}

pub fn check_promotion_command(
    mut values: impl Iterator<Item = OsString>,
    io: &mut impl PromotionArtifactIo,
) -> Result<PathBuf, Box<dyn Error>> {
    let mut manifest = None;
    let mut qualification_record = None;
    let mut evidence = None;
    let mut authorized_evidence_path = None;
    let mut sanitized_evidence = None;
    let mut protected_policy = None;
    let mut package_provenance = None;
    let mut controller_package = None;
    let mut controller_signature = None;
    let mut package_manifest_signature = None;
    let mut output = None;
    while let Some(flag) = values.next() {
        if flag == "--help" {
            return Err("help must be handled by the command entry point".into());
        }
        let value = values
            .next()
            .ok_or_else(|| format!("missing value for {}", flag.to_string_lossy()))?;
        let (target, name) = match flag.to_str() {
            Some("--manifest") => (&mut manifest, "--manifest"),
            Some("--qualification-record") => (&mut qualification_record, "--qualification-record"),
            Some("--evidence") => (&mut evidence, "--evidence"),
            Some("--authorized-evidence-path") => {
                (&mut authorized_evidence_path, "--authorized-evidence-path")
            }
            Some("--sanitized-evidence") => (&mut sanitized_evidence, "--sanitized-evidence"),
            Some("--protected-policy") => (&mut protected_policy, "--protected-policy"),
            Some("--package-provenance") => (&mut package_provenance, "--package-provenance"),
            Some("--controller-package") => (&mut controller_package, "--controller-package"),
            Some("--controller-signature") => (&mut controller_signature, "--controller-signature"),
            Some("--package-manifest-signature") => (
                &mut package_manifest_signature,
                "--package-manifest-signature",
            ),
            Some("--output") => (&mut output, "--output"),
            Some(flag) => return Err(format!("unknown argument: {flag}").into()),
            None => return Err("check-promotion argument flags must be UTF-8".into()),
        };
        set_path(target, value, name)?;
    }
    let manifest = manifest.ok_or("--manifest is required")?;
    let qualification_record = qualification_record.ok_or("--qualification-record is required")?;
    let evidence = evidence.ok_or("--evidence is required")?;
    let authorized_evidence_path =
        authorized_evidence_path.ok_or("--authorized-evidence-path is required")?;
    let sanitized_evidence = sanitized_evidence.ok_or("--sanitized-evidence is required")?;
    let protected_policy = protected_policy.ok_or("--protected-policy is required")?;
    let package_provenance = package_provenance.ok_or("--package-provenance is required")?;
    let controller_package = controller_package.ok_or("--controller-package is required")?;
    let controller_signature = controller_signature.ok_or("--controller-signature is required")?;
    let package_manifest_signature =
        package_manifest_signature.ok_or("--package-manifest-signature is required")?;
    let output = output.ok_or("--output is required")?;
    if evidence != authorized_evidence_path {
        return Err("--evidence must be the exact authorized evidence path".into());
    }

    let manifest_source = io.read_utf8(&manifest, "promotion manifest")?;
    let qualification_source = io.read_utf8(&qualification_record, "qualification record")?;
    let evidence_source = io.read_utf8(&evidence, "supervised endurance evidence")?;
    let sanitized_source = io.read_utf8(&sanitized_evidence, "sanitized evidence")?;
    let policy_bytes = io.read_bytes(&protected_policy, "protected policy")?;
    let provenance_bytes = io.read_bytes(&package_provenance, "package provenance")?;
    let controller_bytes = io.read_bytes(&controller_package, "controller package")?;
    let controller_signature_bytes =
        io.read_bytes(&controller_signature, "controller signature")?;
    let package_signature_bytes =
        io.read_bytes(&package_manifest_signature, "package manifest signature")?;
    validate_promotion_manifest_v1(PromotionInputs {
        manifest_source: &manifest_source,
        qualification_record_source: &qualification_source,
        evidence_source: &evidence_source,
        authorized_evidence_path: &authorized_evidence_path,
        sanitized_evidence_source: &sanitized_source,
        protected_policy: &policy_bytes,
        package_provenance_source: &provenance_bytes,
        controller_package: &controller_bytes,
        controller_signature: &controller_signature_bytes,
        package_manifest_signature: &package_signature_bytes,
    })?;
    io.publish(&output, manifest_source.as_bytes())?;
    Ok(output)
}

fn set_path(
    target: &mut Option<PathBuf>,
    value: OsString,
    flag: &str,
) -> Result<(), Box<dyn Error>> {
    if target.is_some() {
        return Err(format!("duplicate argument: {flag}").into());
    }
    *target = Some(PathBuf::from(value));
    Ok(())
}
