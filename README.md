# gitelab

Forge git **minimaliste, single container**, pensée pour les homelabs (< 10 personnes).
Pas de CI, pas de wiki, pas de discussions, pas d'agents : uniquement la gestion git
(clone/push en HTTPS et SSH, navigation web, permissions simples).

Un seul binaire Go, un seul process qui fait serveur HTTP **et** serveur SSH.

## Fonctionnalités

- Dépôts git bare stockés sur un volume `/data` (backup = copie du volume ou `git clone --mirror`)
- Clone/push over **HTTPS** (smart HTTP via `git http-backend`) et over **SSH** (serveur SSH embarqué, seules les commandes `git-upload-pack` / `git-receive-pack` / `git-upload-archive` sont autorisées)
- Authentification : utilisateurs locaux (mot de passe hashé en Argon2id), jetons d'accès personnels (`gtl_…`) pour HTTPS, clés SSH publiques pour le SSH
- UI web minimale : liste des dépôts, arborescence, contenu des fichiers, historique, commits, branches
- Permissions : dépôt public/privé, membres avec rôle `read`/`write`, propriétaire implicite `write`
- Sécurité de base : CSRF sur les formulaires, cookies `HttpOnly`/`SameSite=Lax`, rate limiting sur le login, validation stricte des noms de dépôts (anti path traversal)

## Démarrage rapide

```bash
docker compose up -d --build
```

Puis ouvre http://localhost:3000 et connecte-toi avec l'admin bootstrap
(`GITELAB_ADMIN_USER` / `GITELAB_ADMIN_PASSWORD` du compose).

## Utilisation

```bash
# HTTPS avec un jeton d'accès personnel (créé dans Paramètres)
git clone http://admin:gtl_XXXX@localhost:3000/admin/mon-projet.git

# SSH avec une clé enregistrée dans Paramètres (port 2222)
git clone ssh://git@localhost:2222/admin/mon-projet.git
```

## Configuration (variables d'environnement)

| Variable | Défaut | Rôle |
|---|---|---|
| `GITELAB_DATA_DIR` | `/data` | Dossier des données (repos + base SQLite + clé hôte SSH) |
| `GITELAB_HTTP_ADDR` | `:3000` | Adresse d'écoute HTTP |
| `GITELAB_SSH_ADDR` | `:2222` | Adresse d'écoute SSH |
| `GITELAB_EXTERNAL_URL` | `http://localhost:3000` | URL affichée pour les clones |
| `GITELAB_ADMIN_USER` / `GITELAB_ADMIN_PASSWORD` | vide | Bootstrap du premier admin si la base est vide |

Derrière un reverse proxy (TLS) ou un VPN (WireGuard/Tailscale), ne pas oublier de
régler `GITELAB_EXTERNAL_URL`.

## Développement

```bash
go build ./...     # compiler
go test ./...      # test d'intégration end-to-end (HTTP + SSH + push/clone git)
go vet ./...       # vet
```

## Architecture

```
 Navigateur / git (HTTPS)                git (SSH, port 2222)
        │                                        │
        ▼                                        ▼
 ┌───────────── single process Go (gitelab) ─────────────┐
 │  net/http :3000          gliderlabs/ssh :2222        │
 │  ├─ UI web (templates)   ├─ auth clé publique        │
 │  ├─ git smart HTTP ──► git http-backend              │
 │  └─ auth session/PAT     └─► git upload/receive-pack │
 │         └──────────┬──────────┘                     │
 │              SQLite (modernc, pur Go)                 │
 │              /data/repos/<owner>/<name>.git (bare)    │
 └───────────────────────────────────────────────────────┘
```

## Limites connues (volontaires)

- Pas de merge requests pour l'instant (prévu en v1), pas de CI/wiki/issues/LFS, pas de hooks serveur
- Les noms de branches contenant `/` ne sont pas navigables dans l'UI web (OK en ligne de commande)
- Un seul nœud : la haute dispo n'est pas le but (chaque clone reste un backup)

## Licence

MIT
