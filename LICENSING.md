# Licensing boundary

## Original repository work

Original Rust code, tests, scripts, documentation, schemas, and packaging metadata in this repository are licensed under the [MIT License](LICENSE), unless a file says otherwise.

## Linux-derived material

The Linux kernel is licensed `GPL-2.0-only`. This repository does not relicense Linux-derived material. The following remain under `GPL-2.0-only` and retain all upstream notices and provenance:

- pinned or downloaded Linux source archives and extracted source trees;
- Linux kernel configuration derived from an upstream or distribution kernel configuration;
- patches, source snippets, or generated kernel/module artifacts copied from or based on Linux; and
- any corresponding source staged under the ignored `packaging/kernel/sources/` directory or in an external source-lock bundle.

The source lock records immutable upstream identities and hashes; it does not change their license. When redistributing Linux-derived material or binaries, include the upstream `COPYING` file, preserve SPDX and copyright notices, and satisfy the `GPL-2.0-only` corresponding-source requirements. The canonical license text is included at [LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt) and in the pinned Linux source tree at `COPYING`.

Checked-in signed Git objects, public keys, and OCI manifests under `packaging/kernel/` are provenance records. Any embedded upstream text or cryptographic material retains its upstream terms; its presence is not an MIT ownership claim.

New Linux-derived files must be kept clearly separate from MIT code, carry `SPDX-License-Identifier: GPL-2.0-only` where the file format permits, and document their exact upstream repository, revision, and path. Do not combine GPL-derived source into an MIT-only file.
