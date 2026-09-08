use std::path::Path;
use std::process::Command;

#[test]
fn root_signer_rejects_untrusted_requests_and_signs_without_exporting_keys() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let source = r#"
import hashlib
import importlib.machinery
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

loader = importlib.machinery.SourceFileLoader('signer', sys.argv[1])
spec = importlib.util.spec_from_loader('signer', loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)

def rejects(callback):
    try:
        callback()
    except m.SigningError:
        return
    raise AssertionError('unsafe signing request accepted')

digest = '1' * 64
for args in ([], ['sign'], ['certificate', '../key'], ['sign', digest, digest, '/tmp/output'],
             ['export-key', digest], ['sign', digest, 'x' * 64]):
    rejects(lambda: m.main(args))
with patch.object(m.os, 'geteuid', return_value=1000):
    rejects(lambda: m.main(['certificate', digest]))

leaf = Path('/protected/key')
def metadata(mode=stat.S_IFREG | 0o400, uid=0, links=1):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=links)
for bad in (metadata(uid=1000), metadata(links=2), metadata(stat.S_IFLNK | 0o777),
            metadata(stat.S_IFREG | 0o644), metadata(stat.S_IFIFO | 0o400)):
    with patch.object(Path, 'lstat', lambda p: bad if p == leaf else metadata(stat.S_IFDIR | 0o755)):
        rejects(lambda: m.protected_path(leaf, private=True))
with patch.object(Path, 'lstat', lambda p: metadata(stat.S_IFDIR | 0o777) if p == leaf.parent
                  else metadata() if p == leaf else metadata(stat.S_IFDIR | 0o755)):
    rejects(lambda: m.protected_path(leaf, private=True))
with patch.object(Path, 'lstat', lambda p: metadata() if p == leaf else metadata(stat.S_IFDIR | 0o755)):
    m.protected_path(leaf, private=True)

image = bytearray(128)
image[:2] = b'MZ'
image[60:64] = (64).to_bytes(4, 'little')
image[64:70] = b'PE\0\0\x64\x86'
image = bytes(image)
m.validate_image(image, hashlib.sha256(image).hexdigest())
rejects(lambda: m.validate_image(image, digest))
rejects(lambda: m.validate_image(b'not PE', hashlib.sha256(b'not PE').hexdigest()))
with patch.object(m, 'MAX_IMAGE', 1):
    rejects(lambda: m.validate_image(image, hashlib.sha256(image).hexdigest()))

# Real OpenSSL/sbsign/sbverify; only root filesystem ownership and staging
# are simulated. No production key, privileged command, or boot mutation.
with tempfile.TemporaryDirectory(prefix='pt31553-signer-test-') as directory:
    root = Path(directory)
    key, cert = root / 'test-key.pem', root / 'test-certificate.pem'
    subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-subj', '/CN=ephemeral-signer-test', '-days', '1', '-keyout', str(key),
                    '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pem = cert.read_bytes()
    der = subprocess.check_output(['/usr/bin/openssl', 'x509', '-in', str(cert), '-outform', 'DER'])
    expected = hashlib.sha256(der).hexdigest()
    real_temporary_directory = tempfile.TemporaryDirectory
    real_run = m.run
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return real_run(command, **kwargs)
    with patch.object(m, 'PRIVATE_KEY', key), patch.object(m, 'CERTIFICATE', cert), \
         patch.object(m, 'protected_path') as protected, \
         patch.object(m.tempfile, 'TemporaryDirectory', lambda **kw: real_temporary_directory(dir=root)), \
         patch.object(m, 'run', run):
        assert m.certificate_bytes(expected) == pem
        rejects(lambda: m.certificate_bytes(digest))
        stub = Path('/usr/lib/systemd/boot/efi/linuxx64.efi.stub').read_bytes()
        m.validate_image(stub, hashlib.sha256(stub).hexdigest())
        signed = m.sign_image(stub, pem)
        assert signed != stub and key.read_bytes() not in signed
        assert not list(root.glob('tmp*')), 'root staging retained'
        protected.assert_any_call(key, private=True)
        assert any(c[0] == '/usr/bin/sbsign' and c[c.index('--key') + 1] == str(key) for c in calls)
        (root / 'signed.efi').write_bytes(signed)
        subprocess.run(['/usr/bin/sbverify', '--cert', str(cert), str(root / 'signed.efi')],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with patch.object(m, 'run', side_effect=m.SigningError('signing failed')):
            rejects(lambda: m.sign_image(stub, pem))
        assert not list(root.glob('tmp*')), 'failed signing retained staging'

    # Even a signing failure emits no image/certificate bytes to stdout.
    stdin = SimpleNamespace(buffer=io.BytesIO(image))
    stdout = SimpleNamespace(buffer=io.BytesIO())
    with patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'certificate_bytes', return_value=pem), \
         patch.object(m.sys, 'stdin', stdin), patch.object(m.sys, 'stdout', stdout), \
         patch.object(m, 'sign_image', side_effect=m.SigningError('failed')):
        rejects(lambda: m.main(['sign', expected, hashlib.sha256(image).hexdigest()]))
        assert stdout.buffer.getvalue() == b''
print('root signer contract passed')
"#;
    let output = Command::new("/usr/bin/python3")
        .args(["-I", "-c", source])
        .arg(workspace.join("scripts/pt31553-sign-kernel"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn executor_pins_the_reviewed_root_helper() {
    use sha2::{Digest, Sha256};
    let source = include_bytes!("../../../scripts/pt31553-sign-kernel");
    let wrapper = include_str!("../../../packaging/kernel/build-candidate");
    let digest = format!("{:x}", Sha256::digest(source));
    assert!(wrapper.contains(&format!("!= \"{digest}\"")));
    assert!(wrapper.contains("del expected[\"kernel-signing-key.pem\"]"));
    assert!(wrapper.contains("/usr/bin/pkexec \"$root_signer\" sign"));
}
