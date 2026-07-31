# Cafe Scanner TLS — backlog

Items deferred; not blocking current releases unless noted.

---

## Fiber v3 — migrate off `gofiber/fiber/v2`

**Plan détaillé :** [docs/FIBER_V3_MIGRATION.md](docs/FIBER_V3_MIGRATION.md)

**T0 done :** pin `fiber/v2` **v2.52.14** (fix CVE-2026-45045 ; `BalancerForward` non utilisé).

**Reste :** cutover **T1** vers `fiber/v3` (≥ 3.4.0) dans `internal/scanner/core/core.go` (health only).

**Priority :** deliberate backlog — not blocking releases.
