# ntfywui – Weboberfläche für ntfy

Eine schlanke, sichere Weboberfläche zur Verwaltung eines selbst gehosteten [ntfy](https://ntfy.sh)-Servers:
Benutzer, Zugriffsrechte (ACL), Access-Tokens – und optional das Senden von Nachrichten.

- **Go, nur Standardbibliothek** – keine externen Abhängigkeiten, ein einzelnes Binary inkl. Templates/Assets
- arbeitet über die **ntfy-CLI** direkt auf der Auth-Datenbank des Servers
- moderne Oberfläche mit **Hell-/Dunkelmodus**, mobil nutzbar, ohne externe Ressourcen (strikte CSP)

## Funktionen

| Bereich | Was geht |
| --- | --- |
| **Übersicht** | Kennzahlen (Benutzer, Regeln, Tokens, Standardzugriff), Serverstatus & ntfy-Version, Aktivitätsdiagramm der letzten 14 Tage, letzte Ereignisse, Schnellaktionen |
| **Benutzer** | Liste mit Suche, Rollen- und Rechte-Übersicht; anlegen (inkl. Passwortgenerator), Passwort/Rolle/Tier ändern, löschen; anonymer Zugriff („Jeder“) |
| **Zugriffsrechte** | Rechte pro Topic/Muster vergeben (`alerts`, `backup_*`), einzelne Regeln entfernen, alle Regeln aller Benutzer filterbar, Standardzugriff sichtbar |
| **Tokens** | alle Tokens aller Benutzer mit Label, Ablauf, letzter Nutzung; erstellen (Anzeige nur einmal + Kopieren-Button), löschen |
| **Nachricht senden** | Titel, Text, Priorität, Tags, Klick-Link, Markdown, optional Token – mit Live-Vorschau (benötigt `NTFYWUI_NTFY_URL`) |
| **WebUI-Admins** | Rollen *Betrachter*, *Operator*, *Administrator*; Passwort setzen, deaktivieren, 2FA zurücksetzen |
| **Mein Konto** | eigenes Passwort ändern, **2FA per QR-Code** einrichten (TOTP, z. B. Aegis, 2FAS, Google Authenticator) |
| **Audit-Log** | alle Änderungen und Anmeldungen, Suche, Kategorien, Export als JSONL |

## Schnellstart (Docker Compose)

```bash
cp .env.example .env
# NTFYWUI_SECRET setzen, z. B. mit: openssl rand -base64 48
docker compose up -d --build
```

- ntfy: <http://localhost:8080>
- ntfywui: <http://localhost:8090> – Anmeldung mit `NTFYWUI_BOOTSTRAP_USER` / `NTFYWUI_BOOTSTRAP_PASS`

Die mitgelieferte [examples/server.yml](examples/server.yml) aktiviert die Authentifizierung
(`auth-file`, `auth-default-access: deny-all`) und wird in beide Container gemountet.

> **Wichtig:** Das ntfy-Image in der WebUI (`NTFY_VERSION` im Dockerfile) sollte zur Version des ntfy-Servers passen,
> da die CLI direkt auf dessen Datenbank arbeitet.

## Konfiguration

| Variable | Flag | Standard | Beschreibung |
| --- | --- | --- | --- |
| `NTFYWUI_SECRET` | `-secret` | – | **Pflicht.** ≥ 32 Bytes, base64 empfohlen (`ntfywui -gen-secret`) |
| `NTFYWUI_LISTEN` | `-listen` | `:8080` | Listen-Adresse |
| `NTFYWUI_BASE_PATH` | `-base-path` | – | z. B. `/ntfywui` hinter einem Reverse Proxy |
| `NTFYWUI_DATA_DIR` | `-data-dir` | `/data` | `admins.json`, `audit.jsonl` |
| `NTFYWUI_COOKIE_SECURE` | `-cookie-secure` | `true` | Secure-Cookies (HTTPS nötig; `localhost` geht auch per HTTP) |
| `NTFYWUI_TRUST_PROXY` | `-trust-proxy` | – | CIDRs vertrauenswürdiger Proxies für `X-Forwarded-For` |
| `NTFYWUI_NTFY_BIN` | `-ntfy-bin` | `/usr/bin/ntfy` | Pfad zur ntfy-CLI |
| `NTFYWUI_NTFY_CONFIG` | `-ntfy-config` | `/etc/ntfy/server.yml` | wird der CLI als `NTFY_CONFIG_FILE` übergeben |
| `NTFYWUI_NTFY_TIMEOUT` | `-ntfy-timeout` | `10s` | Timeout pro CLI-Aufruf |
| `NTFYWUI_NTFY_URL` | `-ntfy-url` | – | URL des ntfy-Servers (z. B. `http://ntfy:80`) – aktiviert „Nachricht senden“ und den Health-Check |
| `NTFYWUI_BOOTSTRAP_USER` / `_PASS` | – | – | erster Admin; wird nur angelegt, solange **kein** Admin existiert |

Weitere Flags: `-version`, `-gen-secret`, `-healthcheck` (für Docker `HEALTHCHECK`).

## Rollen

- **Betrachter** – sieht Übersicht, Benutzer und deren Rechte, ändert nichts
- **Operator** – verwaltet ntfy-Benutzer, Zugriffsrechte und Tokens, kann Nachrichten senden
- **Administrator** – zusätzlich WebUI-Admins und Audit-Log

## Sicherheit

- Sitzungen sind verschlüsselt und signiert (AES-256-GCM), absolut 12 h gültig; nach Passwortänderung/Deaktivierung werden alle anderen Sitzungen ungültig
- CSRF-Token für alle schreibenden Anfragen, strikte Content-Security-Policy (keine Inline-Skripte/-Styles), Security-Header
- Passwörter mit PBKDF2-SHA256 (600 000 Iterationen); ältere Hashes werden beim Login automatisch aufgewertet
- Login-Sperre nach wiederholten Fehlversuchen (pro IP und Benutzer), gleichförmige Antwortzeiten bei unbekannten Benutzern
- Zwei-Faktor-Anmeldung als separater Schritt, TOTP-Codes können nicht wiederverwendet werden
- Eingaben werden vor der Übergabe an die CLI streng validiert (keine Argument-Injection), Passwörter gehen per Umgebungsvariable an die CLI
- Schutz vor Open Redirects, Schutz vor dem Entfernen/Herabstufen des letzten Administrators
- `X-Forwarded-For` wird nur von konfigurierten Proxies akzeptiert und von rechts ausgewertet

Vergib Admin-Rechte sparsam und betreibe die WebUI hinter HTTPS.

## Entwicklung

```bash
go test ./...                       # Unit- und End-to-End-Tests (mit simulierter ntfy-CLI)
go run ./cmd/ntfywui -secret "$(go run ./cmd/ntfywui -gen-secret)" -data-dir ./data -cookie-secure=false

# Oberfläche mit Beispieldaten ansehen (ohne ntfy, automatisch als "admin" angemeldet):
NTFYWUI_DEMO_ADDR=127.0.0.1:8099 go test ./internal/app -run TestDemoServer -v
```

### CI (GitHub Actions, Self-Hosted Runner)

[.github/workflows/ci.yml](.github/workflows/ci.yml) läuft auf einem Runner mit den Labels `self-hosted` und `linux`
(Voraussetzungen: Docker, `bash`, Internetzugang für Go und GitHub):

- **Test & Build** bei jedem Push und Pull Request: `gofmt`, `go vet`, `go test`, Linux-Binary als Artefakt
- **Docker-Image**: wird bei Pull Requests nur gebaut, bei `main` und Tags `v*` nach `ghcr.io/<owner>/<repo>` gepusht
- Pull Requests aus Forks werden aus Sicherheitsgründen **nicht** auf dem Self-Hosted Runner ausgeführt

Projektstruktur:

```text
cmd/ntfywui/         Einstiegspunkt, Flags/Umgebung
internal/app/        HTTP-Handler, Rendering, Templates & statische Assets (embedded)
internal/ntfy/       Wrapper und Parser für die ntfy-CLI
internal/security/   Sessions, CSRF, PBKDF2, TOTP, Rate-Limits, Header
internal/store/      WebUI-Admins (JSON) und Audit-Log (JSONL)
internal/qr/         QR-Code-Encoder für die 2FA-Einrichtung
```

## Lizenz

MIT
