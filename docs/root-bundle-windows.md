# Candidate Windows encrypted-bundle storage

`zrotext-root-bundle` is a dormant library for storing a proposed encrypted root
backup and its public card together. It is not a usable recovery CLI. Nothing
invokes it in the server or Android app. It does not generate roots or recovery
tokens, decrypt backups, display secrets, enroll roots, or access a network.

`EncryptedBundle::new` validates the bounded backup framing, independently
supplied public identity, and matching public-card digest. This does **not**
authenticate the encrypted content or prove that recovery will succeed. The
existing `root_backup::open` remains necessary for authenticated recovery.

## Supported boundary

The `Store` API exists only on Windows. It accepts an existing absolute drive
path with bounded ASCII components, on a fixed local NTFS volume, and opens or
exclusively creates a `zrotext-root-bundles` child. A future caller must choose
its approved storage parent; this library does not choose a user profile,
terminal, elevation policy, or interactive consent flow.

UNC paths, user-supplied device namespaces, Unicode paths, dot components,
stream syntax, reserved names, trailing spaces/dots, reparse points, remote or
non-NTFS volumes, and unsuitable permissions fail closed. Cloud folders and
removable storage are unsupported. Errors do not include paths or input bytes.

The adapter uses retained handles and single-component `NtCreateFile` calls,
with `FILE_OPEN_REPARSE_POINT`, rather than canonicalizing a path and reopening
it. Volume, ancestor, store and stage handles remain held throughout each
operation. Ancestors deny delete sharing; write sharing is necessary for the
native rename destination open. Their identities and attributes are rechecked
around child operations. A store or bundle also requires the current process
user as owner and a protected DACL with exactly one non-inherited full-access
allow entry for that user. Creation supplies that descriptor atomically.

This discretionary boundary excludes administrators, SYSTEM, malicious code
running as the same user, and compromised filesystem drivers. “Immutable” means
the API never replaces or edits an existing bundle; it does not prevent the user
or another privileged process from changing files after handles close.

## Publication and reconciliation

1. Exclusively create `pending-bundle-<public backup ID>` under the retained
   store handle. An existing pending name is a collision, not permission to reuse it.
2. Exclusively create `backup.ztrb` and `public.ztrc` with protected permissions.
   Write the supplied final bytes with short-write handling, flush each file,
   close and reopen it, and compare its identity and exact bounded contents.
   Files must be regular, non-reparse, single-link files on the same volume.
3. Close child handles before the native directory rename. Publish to
   `bundle-<public backup ID>` through the retained parent with replacement
   disabled. No path-based rename, copy, overwrite, or automatic deletion fallback
   exists.
4. Open the **destination name** under the retained parent and compare its
   directory identity with the still-held stage handle. Reopen both named files
   and compare their original identities, owner/DACL, bounds, link counts and
   exact bytes before returning success.

Write/flush failures may leave a pending encrypted/public bundle. A rename
failure other than a definite collision, or any failure after rename, is
`Indeterminate`: publication may have happened. Preserve the files and call
`reconcile` with the intended bundle to inspect the destination independently.
It never deletes pending data or automatically retries into an existing name.
Reconciliation proves matching files at that instant, not their creator,
anti-rollback, successful key recovery, or registration authority.

File flushing and a same-volume rename do not establish power-loss durability
or crash-atomic persistence of the directory namespace. A recoverable external
copy and a future fresh-process recovery exercise remain separate requirements.

## Verification

`cargo test --locked -p zrotext-root-bundle` includes pure public-format tests.
On Windows it also discovers native tests for permissions, publication,
collision, concurrent creation, partial writes, write/flush/rename failures,
post-publication uncertainty, parent rename refusal, junctions and junction
mutation, hardlinks, bounds, content tampering, and reopened identity checks.
Fixtures contain only the existing synthetic ciphertext and public metadata.
The separate read-only Windows workflow runs these native tests. A Linux test
run does not exercise the Windows adapter.

## Native API references

- [NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
- [FILE_RENAME_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information), including destination sharing and closed-child requirements
- [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
- [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)
- [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
