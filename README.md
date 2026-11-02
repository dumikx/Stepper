# Stepper

Contor de urcări pe treaptă/cutie cu camera telefonului (MediaPipe Pose în browser).
Fiecare urcare = înălțimea treptei (setabilă, implicit 22 cm) adăugată la elevație.

- Conturi (cu cod de invitație opțional), istoric sesiuni pe server, pagină de detaliu cu grafic
- Import puls din Polar Flow (AccessLink API) pentru sesiunea respectivă
- Se instalează pe ecranul principal (PWA)

## Railway: variabile

| Variabilă | Ce e |
|---|---|
| `DATABASE_URL` | referință la serviciul Postgres (`${{Postgres.DATABASE_URL}}`) |
| `SECRET_KEY` | șir aleator lung (ține utilizatorii logați între deploy-uri) |
| `INVITE_CODE` | opțional; dacă e setat, contul nou cere acest cod |
| `POLAR_CLIENT_ID`, `POLAR_CLIENT_SECRET` | din admin.polaraccesslink.com; callback: `https://<domeniu>/polar/callback` |

Local: `pip install -r requirements.txt && COOKIE_INSECURE=1 flask --app app run` (SQLite în `instance/`).
