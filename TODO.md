# Cafe Scanner TLS — backlog

Items deferred; not blocking current releases unless noted.

---

## Fiber v3 — migrate off `gofiber/fiber/v2`

**Plan détaillé :** [docs/FIBER_V3_MIGRATION.md](docs/FIBER_V3_MIGRATION.md)

**T0 done :** pin `fiber/v2` **v2.52.14** (fix CVE-2026-45045 ; `BalancerForward` non utilisé).

**Reste :** cutover **T1** vers `fiber/v3` (≥ 3.4.0) dans `internal/scanner/core/core.go` (health only).

**Priority :** deliberate backlog — not blocking releases.

---

## Dead code — nettoyer surface non atteinte (`deadcode ./...`)

**Context :** `deadcode ./...` remonte des funcs non atteignables depuis `cmd/scanner-tls` (préexistant ; hors Fiber T0).

| Package | Funcs |
| --- | --- |
| `pkg/scan` | `GetBySubject`, `Kinds`, `ValidTransition`, `IsTerminal` |
| `pkg/tls` | `TryPQCGroups` |

Note : `ValidTransition` / `IsTerminal` sont encore exercées par `pkg/scan/state_test.go` — soit les brancher en prod, soit les garder comme API testée, soit les supprimer avec les tests si vraiment morts.

**Acceptance :** `deadcode ./...` clean (ou allowlist documentée) ; `go test ./...` vert.

**Priority :** hygiene ; PR séparée du bump Fiber.

---

## Deps — bumper libs signalées par `govulncheck` (même sans appel)

**Context :** après Fiber v2.52.14, `govulncheck -show verbose ./...` : **0** vulns au niveau symbol (code non affecté), mais findings **package/module** sur le graphe transitif. Politique : **mettre à jour quand même** pour réduire le bruit Dependabot/OSV et le graphe, pas seulement les symboles appelés.

Candidats vus (à re-mesurer au moment du chore) :

| Module | Exemple | Fixed in (indicatif) |
| --- | --- | --- |
| `golang.org/x/text` | GO-2026-5970 | ≥ v0.39.0 |
| `github.com/klauspost/compress` | GO-2026-5841 (s2) | ≥ v1.18.7 |
| `golang.org/x/crypto` | SSH/agent/openpgp (GO-2026-50xx, GO-2026-5932) | ≥ v0.52.0 où applicable ; openpgp = Fixed N/A |
| `golang.org/x/sys` | GO-2026-5024 (windows) | ≥ v0.44.0 |

**Acceptance :** `go get` / `go mod tidy` ; `go test ./...` ; re-run `govulncheck` — package/module residual documenté si inévitable (ex. openpgp Fixed N/A).

**Priority :** après ou indépendant de Fiber T1 ; pas bloquant releases tant que symbol = 0.
