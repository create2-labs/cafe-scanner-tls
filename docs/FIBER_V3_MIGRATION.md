# Fiber v3 — plan de migration (`cafe-scanner-tls`)

**Statut :** T0 **done** ; T1 **done** (`fiber/v3` **v3.4.0**)  
**Cible :** `github.com/gofiber/fiber/v3` ≥ **v3.4.0**  
**Source backlog :** [cafe-deploy/TODO.md — Fiber v3](https://github.com/create2-labs/cafe-deploy/blob/main/TODO.md)  
**État actuel :** `fiber/v3` **v3.4.0** — un seul point d’usage HTTP (`GET /health`).

**Contrainte PR :** chaque PR ≤ **~400 lignes** (`git diff --stat` insertions+suppressions).  
**Contrainte produit :** contrat `GET /health` inchangé (JSON `status` / `checks.nats` / `checks.scanners`).

---

## 1. Inventaire (post-T1)

| Élément | Détail |
| --- | --- |
| Fichier Fiber | `internal/scanner/core/core.go` uniquement |
| Usage | `fiber.New`, `app.Get("/health", ...)`, `fiber.Map`, `app.Listen`, `app.Shutdown` |
| Handlers | 1 closure `func(c fiber.Ctx) error` |
| Middleware | aucun (`cors` / `adaptor` / JWT absents) |
| `BodyParser` / `QueryInt` / `app.Test` | aucun |
| Tests Fiber | aucun dédié |

Fiber sert uniquement le **health server** du process scanner (port `SCANNER_HEALTH_PORT` / défaut `8081`). Le plan de scan NATS n’utilise pas Fiber.

---

## 2. Breaking changes appliqués

| v2 | v3 |
| --- | --- |
| `github.com/gofiber/fiber/v2` | `github.com/gofiber/fiber/v3` |
| `func(c *fiber.Ctx)` | `func(c fiber.Ctx)` |
| `app.Listen(addr)` | inchangé en signature simple ; optionnel `ListenConfig` si on veut `DisableStartupMessage` |
| `fiber.Map` / `Status` / `JSON` | inchangés en usage |

Pas de CORS, pas de bind, pas de suite `app.Test`.

---

## 3. Stratégie

1. ~~PR **T0** (prérequis sécurité) sur `main` : rester en v2, bumper à **v2.52.14**~~ **done**
2. ~~Cutover v3 (**T1**)~~ **done**

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

### PR T1 — Migration Fiber v3 (cutover) — **done**

| | |
| --- | --- |
| **Scope** | `internal/scanner/core/core.go` + `go.mod` / `go.sum` → `fiber/v3@v3.4.0` |
| **Changements code** | import `v3` ; handler `fiber.Ctx` (valeur) ; `AppName` conservé |
| **Acceptation** | voir §5 |

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

- [x] `rg 'gofiber/fiber/v2'` → vide
- [x] `go test ./...` vert
- [ ] Conteneur : `GET /health` → `200` + `status=ok` quand NATS + runners OK ; `503` + `degraded` sinon
- [ ] Shutdown signal (SIGTERM) appelle toujours `app.Shutdown()`
- [x] Pin Dependabot / plus d’alertes Fiber v2 sur ce repo (après merge)

---

## 6. Risques

| Risque | Mitigation |
| --- | --- |
| Listen startup message bruyant en logs | optionnel `ListenConfig{DisableStartupMessage: true}` — hors chemin critique |
| Régression health JSON consommée par probes K8s/compose | comparer body byte-à-byte avec v2 en staging |
| Drift vs `cafe-scanner-wallet` | même découpage T0/T1 ; PRs v3 le même jour |

---

## 7. Coordination

1. ~~T0 (v2.52.14)~~ **done**
2. ~~T1 (v3.4.0)~~ **done**
3. Miroir avec [cafe-scanner-wallet `docs/FIBER_V3_MIGRATION.md`](https://github.com/create2-labs/cafe-scanner-wallet/blob/main/docs/FIBER_V3_MIGRATION.md)
