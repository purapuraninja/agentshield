# Archive scanning

AgentShield accepts a packaged extension as a direct scan target. Supported containers are `.zip`,
`.whl` (Python wheel, a ZIP container), `.tar`, and `.tar.gz`/`.tgz` (including npm tarballs).
Archive content is decoded to virtual source files in memory and is never written or extracted to the
host filesystem. Supported text entries then follow the same parser, rule, permission, evidence, and
reporting pipeline as ordinary files. Report paths use `archive.tgz!/path/inside/archive.ts` so
findings remain attributable.

The scanner validates every file entry, including entries whose extension is not scanned, before
decompression. Default limits are 1,000 files, 50 MiB total expanded bytes, a 100:1 compression
ratio, 20 path levels, 1,024 UTF-8 bytes per entry name, 2 MiB per scanned source entry, and 20 MiB
for the compressed archive. Absolute paths, Windows drive paths, parent traversal, NULs, duplicate
paths, malformed structures, invalid UTF-8 sources, and non-advancing limits produce an explicit
incomplete-analysis finding (`AS-SC-900`).

Format-specific handling:

- **ZIP and wheel** entries are validated through the central-directory listing before any entry is
  decompressed, so a bomb is rejected without expanding it.
- **TAR** headers are checksum-verified. Octal and GNU base-256 size fields are range-checked,
  entries whose data extends past the end of the archive are rejected, and hard links and symlinks
  are rejected outright because their targets can escape the archive. GNU long names and ustar path
  prefixes are supported; PAX and global extended headers are skipped rather than trusted.
- **TAR.GZ** is inflated as a stream with a hard output cap, so the expanded-size and
  compression-ratio limits apply before the tar structure is parsed.

Archive limits are also available through `ScanOptions` for embedding applications. Lowering a limit
is safe; raising one increases memory usage because selected entries are decoded in memory. Nested
archives are not unpacked recursively and remain listed in `PENDING.md`.
