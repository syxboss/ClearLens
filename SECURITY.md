# Security & Data-Safety Policy

ClearLens deletes files on user machines; therefore **data-safety bugs and rule false-positives are treated as high-severity security vulnerabilities**.

## Architectural Guarantees

1. **Hardcoded Protected Blocklist**: `crates/clearlens-core/src/safety.rs` enforces an un-overridable blocklist protecting OS roots, `.ssh`, `.gnupg`, `.aws`, `.kube`, `Keychains`, `.git`, `Desktop`, `Documents` (except narrowly scoped IM cache subdirectories), `Pictures`, `Movies` (except media render caches), and `Music`.
2. **Symlink & Reparse Isolation**: Traversal and deletion strictly inspect `symlink_metadata` and never follow symlinks or Windows junctions.
3. **Cloud-Only Placeholder Protection**: Files marked `SF_DATALESS`, `.icloud`, or `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` are skipped without reading contents.
4. **Forced Trash for `review_required`**: Ambiguous or user-facing items are unchecked by default and forcibly routed to the OS Recycle Bin / macOS Trash.

## Reporting a Vulnerability or Rule False-Positive

- **Never** open a public issue with sensitive personal paths or credentials.
- Use GitHub Security Advisories (Private Vulnerability Reporting) or the **Safety False-Positive** issue template for non-sensitive rule path issues so maintainers can ship an immediate blocklist patch.
