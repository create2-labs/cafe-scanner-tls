# Fiber v3 — plan de migration (`cafe-scanner-tls`)

**Statut :** T0 **done** (v2.52.14) ; cutover v3 encore backlog  
**Cible :** `github.com/gofiber/fiber/v3` ≥ **v3.4.0**  
**Source backlog :** [cafe-deploy/TODO.md — Fiber v3](https://github.com/create2-labs/cafe-deploy/blob/main/TODO.md)  
**État actuel :** `fiber/v2` **v2.52.14** (corrige CVE-2026-45045 ; `BalancerForward` non utilisé) — un seul point d’usage HTTP.

**Contrainte PR :** chaque PR ≤ **~400 lignes** (`git diff --stat` insertions+suppressions).  
**Contrainte produit :** contrat `GET /health` inchangé (JSON `status` / `checks.nats` / `checks.scanners`).

---

## 1. Inventaire actuel (v2)

| Élément | Détail |
| --- | --- |
| Fichier Fiber | `internal/scanner/core/core.go` uniquement (~124 lignes fichier) |
| Usage | `fiber.New`, `app.Get("/health", ...)`, `fiber.Map`, `app.Listen`, `app.Shutdown` |
| Handlers | 1 closure `func(c *fiber.Ctx) error` |
| Middleware | aucun (`cors` / `adaptor` / JWT absents) |
| `BodyParser` / `QueryInt` / `app.Test` | aucun |
| Tests Fiber | aucun dédié |

Fiber sert uniquement le **health server** du process scanner (port `SCANNER_HEALTH_PORT` / défaut `8081`). Le plan de scan NATS n’utilise pas Fiber.

---

## 2. Breaking changes applicables

| v2 | v3 |
| --- | --- |
| `github.com/gofiber/fiber/v2` | `github.com/gofiber/fiber/v3` |
| `func(c *fiber.Ctx)` | `func(c fiber.Ctx)` |
| `app.Listen(addr)` | inchangé en signature simple ; optionnel `ListenConfig` si on veut `DisableStartupMessage` |
| `fiber.Map` / `Status` / `JSON` | inchangés en usage |

Pas de CORS, pas de bind, pas de `c.Context()`, pas de suite `app.Test`.

---

## 3. Stratégie

1. ~~PR **T0** (prérequis sécurité) sur `main` : rester en v2, bumper à **v2.52.14**~~ **done**
2. Cutover v3 (**T1**) quand prêt — indépendant de Discovery côté interop ; préférable d’être déjà en 2.52.14 (c’est le cas).
3. PR **T1** : cutover v3 (code + deps) — doit rester ≤ 400 lignes ; sinon scinder deps / code.
4. Pas de branche stacking longue nécessaire (surface minuscule).

**Mesure :**

```bash
git diff --stat main...HEAD   # ≤ 400
```

---

## 4. Découpage des PRs

### PR T0 — Bump Fiber v2.52.12 → v2.52.14 — **done**

| | |
| --- | --- |
| **Scope** | `go.mod` / `go.sum` (+ docs plan) |
| **Hors scope** | Toute migration v3 |
| **Acceptation** | pin **v2.52.14** ; `go test ./...` vert |

---

### PR T1 — Migration Fiber v3 (cutover)

| | |
| --- | --- |
| **Scope** | `internal/scanner/core/core.go` + `go.mod` / `go.sum` → `fiber/v3@≥3.4.0` |
| **Changements code** | import `v3` ; handler `fiber.Ctx` (valeur) ; laisser `AppName` dans `fiber.Config` |
| **Est. lignes** | ~40–200 (code ~15–30 + tidy) |
| **Acceptation** | voir §5 |

**Si `go.sum` pousse le total > 400 :**

| PR | Contenu |
| --- | --- |
| **T1a** | `go.mod`/`go.sum` → v3 seulement (WIP compile : adapter `core.go` dans la foulée sur la même branche courte) |
| **T1b** | `core.go` API v3 |

Préférer une seule PR T1 si le compteur le permet (cas nominal).

**Diff attendu dans `core.go` (conceptuel) :**

```go
import "github.com/gofiber/fiber/v3"

app := fiber.New(fiber.Config{AppName: "Cafe Scanner TLS"})

app.Get("/health", func(c fiber.Ctx) error {
    // même JSON qu'aujourd'hui
    return c.Status(httpStatus).JSON(fiber.Map{ /* ... */ })
})
```

Ne pas modifier la forme JSON ni les codes 200/503.

---

### PR T2 — (optionnel) smoke / doc

| | |
| --- | --- |
| **Scope** | Si aucun test health n’existe : mini test HTTP `app.Test` **ou** note README « health contract » |
| **Est. lignes** | ≤ 150 |
| **Acceptation** | Documente le contrat ; pas obligatoire pour clôturer la migration |

Peut être omis si CI existante + smoke stack couvrent déjà `/health`.

---

## 5. Checklist de validation

- [ ] `rg 'gofiber/fiber/v2'` → vide
- [ ] `go test ./...` / job CI Dockerfile `ci` vert
- [ ] Conteneur : `GET /health` → `200` + `status=ok` quand NATS + runners OK ; `503` + `degraded` sinon
- [ ] Shutdown signal (SIGTERM) appelle toujours `app.Shutdown()`
- [ ] Pin image / Dependabot : plus d’alertes Fiber v2 sur ce repo

---

## 6. Risques

| Risque | Mitigation |
| --- | --- |
| Listen startup message bruyant en logs | optionnel `ListenConfig{DisableStartupMessage: true}` — hors chemin critique |
| Régression health JSON consommée par probes K8s/compose | comparer body byte-à-byte avec v2 en staging |
| Drift vs `cafe-scanner-wallet` | même découpage T0/T1 ; ouvrir les deux PRs v3 le même jour |

---

## 7. Coordination

1. ~~T0 (v2.52.14)~~ **done**
2. T1 quand prêt (interop OK avec Discovery encore en v2 ou déjà en v3)
3. Miroir avec [cafe-scanner-wallet `docs/FIBER_V3_MIGRATION.md`](https://github.com/create2-labs/cafe-scanner-wallet/blob/main/docs/FIBER_V3_MIGRATION.md)
