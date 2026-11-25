# Contributing to ClearLens

Thank you for helping make ClearLens safer, faster, and more transparent across Windows and macOS!

## Repository Layout

- `crates/clearlens-core`: Pure Rust scan engine, 5-stage safety pipeline, hybrid TOML rule engine, and Space Lens aggregator (zero UI dependencies).
- `crates/clearlens-cli`: Lightweight `clens` binary built on `clearlens-core`.
- `apps/desktop`: Tauri v2 + React + TypeScript + Tailwind CSS desktop client.
- `rules/`: Declarative TOML rule packs validated against `rules/schema/rule.schema.json` and `ProtectedBlocklist`.
- `docker/` & `tests/`: Isolated Docker multi-stage verification and E2E test suites.

## Adding or Updating a Cleaning Rule

1. Locate the appropriate category file under `rules/` (e.g., `rules/dev_ai/`, `rules/social_office/`, `rules/creative_media/`).
2. Add a `[[rules]]` entry with:
   - Unique dot-separated `id` (lowercase alphanumeric + `_` / `.`)
   - Bilingual `title` / `title_zh` and `impact_note` / `impact_note_zh`
   - Honest `risk`: `safe` (zero side-effects), `recreatable` (rebuilt on demand), or `review_required` (personal/ambiguous items, `default_checked = false`, `delete_mode = "trash"`)
   - Explicit `[rules.exclude]` patterns for databases (`*.db`, `*.sqlite*`), cookies/credentials, and user documents.
3. Validate your rule locally using Docker:
   ```bash
   docker build -f docker/Dockerfile.test -t clearlens-test:v0.1 .
   docker run --rm clearlens-test:v0.1
   ```

## Pull Request Checklist

- All Rust unit/integration tests and Docker E2E checks pass.
- Frontend changes pass `npx tsc --noEmit`, `npx vitest run`, and `npx vite build`.
- New UI strings exist in both `zh-CN` and `en` inside `apps/desktop/src/i18n.ts`.
- Never submit rules matching `Desktop`, `Documents` roots, `.ssh`, `.git`, or browser `Cookies` / `Login Data`.
