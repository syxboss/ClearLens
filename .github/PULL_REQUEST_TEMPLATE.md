## Summary

<!-- Describe what this PR changes and why. -->

## Verification Checklist

- [ ] Tested inside isolated Docker container (`docker build -f docker/Dockerfile.test -t clearlens-test:v0.1 . && docker run --rm clearlens-test:v0.1`)
- [ ] `clens rules validate` passes with zero blocklist violations
- [ ] No rules match `Desktop`, `Documents` roots, `.ssh`, `.git`, or browser `Cookies` / `Login Data`
- [ ] Bilingual UI strings updated in both `zh-CN` and `en` (`apps/desktop/src/i18n.ts`)
