"""Stepper: climb counter (camera pose detection in the browser) with accounts, history and Polar heart rate import."""
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlencode

import requests
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template, request, send_from_directory,
                   session as cookie, url_for)
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

db_url = os.environ.get("DATABASE_URL", "sqlite:///" + os.path.join(app.instance_path, "stepper.db"))
if db_url.startswith("postgres://"):
    db_url = "postgresql://" + db_url[len("postgres://"):]
if db_url.startswith("postgresql://"):
    db_url = "postgresql+psycopg://" + db_url[len("postgresql://"):]
os.makedirs(app.instance_path, exist_ok=True)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SQLALCHEMY_DATABASE_URI=db_url,
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
    PERMANENT_SESSION_LIFETIME=timedelta(days=365),
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_INSECURE") != "1",
    SESSION_COOKIE_HTTPONLY=True,
)
INVITE_CODE = os.environ.get("INVITE_CODE", "").strip()
POLAR_CLIENT_ID = os.environ.get("POLAR_CLIENT_ID", "").strip()
POLAR_CLIENT_SECRET = os.environ.get("POLAR_CLIENT_SECRET", "").strip()
POLAR_AUTH_URL = "https://flow.polar.com/oauth2/authorization"
POLAR_TOKEN_URL = "https://polarremote.com/v2/oauth2/token"
POLAR_API = os.environ.get("POLAR_API_BASE", "https://www.polaraccesslink.com")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")

db = SQLAlchemy(app)


# ---------------- Models ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    pw_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    settings = db.Column(db.JSON, default=dict)
    polar_token = db.Column(db.String(512))
    polar_user_id = db.Column(db.String(64))


class Workout(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    started_at = db.Column(db.BigInteger, nullable=False)   # epoch ms (client clock)
    ended_at = db.Column(db.BigInteger)                     # epoch ms of last update
    active_ms = db.Column(db.BigInteger, default=0)         # time excluding pauses
    height_cm = db.Column(db.Float, nullable=False)
    climbs = db.Column(db.JSON, default=list)               # epoch ms of each climb (manual +1 included)
    hr = db.Column(db.JSON)                                 # [[epoch_ms, bpm], ...] from Polar
    hr_source = db.Column(db.String(120))
    note = db.Column(db.String(200))
    legs = db.Column(db.Text)                                # one char per climb: L, R or ? (lead leg)
    loads = db.Column(db.JSON)                               # per climb: [vest kg, kg per ankle]

    @property
    def n(self):
        return len(self.climbs or [])

    @property
    def elevation_m(self):
        return self.n * self.height_cm / 100

    def hr_stats(self):
        vals = [b for _, b in (self.hr or []) if b]
        if not vals:
            return None
        return {"avg": round(sum(vals) / len(vals)), "max": max(vals), "min": min(vals)}

    def leg_counts(self):
        s = self.legs or ""
        return {"L": s.count("L"), "R": s.count("R"), "?": self.n - s.count("L") - s.count("R")}

    def load_stats(self):
        loads = (self.loads or [])[: self.n]
        if not any(v or a for v, a in loads):
            return None
        kg = [v + 2 * a for v, a in loads]
        return {"volume_kgm": round(sum(kg) * self.height_cm / 100),
                "max_kg": max(kg), "vest_max": max(v for v, _ in loads), "ankle_max": max(a for _, a in loads),
                "loaded_climbs": sum(1 for k in kg if k)}

    def summary(self):
        return {"id": self.id, "started_at": self.started_at, "ended_at": self.ended_at, "active_ms": self.active_ms,
                "height_cm": self.height_cm, "climbs": self.n, "elevation_m": round(self.elevation_m, 2),
                "hr": self.hr_stats(), "note": self.note, "legs": self.leg_counts(),
                "load": self.load_stats()}


with app.app_context():
    db.create_all()
    # Lightweight migration: columns added after the first deploy.
    cols = {c["name"] for c in db.inspect(db.engine).get_columns("workout")}
    for name, ddl in (("legs", "TEXT"), ("loads", "JSON")):
        if name not in cols:
            with db.engine.begin() as conn:
                conn.execute(db.text(f"ALTER TABLE workout ADD COLUMN {name} {ddl}"))


# ---------------- Auth helpers ----------------
@app.before_request
def load_user():
    uid = cookie.get("uid")
    g.user = db.session.get(User, uid) if uid else None


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not g.user:
            if request.path.startswith("/api/"):
                return jsonify(error="not_logged_in"), 401
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def own_workout(wid):
    w = db.session.get(Workout, wid)
    if not w or w.user_id != g.user.id:
        abort(404)
    return w


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = User.query.filter(db.func.lower(User.username) == request.form.get("username", "").strip().lower()).first()
        if u and check_password_hash(u.pw_hash, request.form.get("password", "")):
            cookie.clear(); cookie.permanent = True; cookie["uid"] = u.id
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("counter"))
        flash("Utilizator sau parolă greșită.")
    return render_template("auth.html", mode="login", invite=bool(INVITE_CODE))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        if INVITE_CODE and request.form.get("invite", "").strip() != INVITE_CODE:
            flash("Codul de invitație nu e corect.")
        elif not (3 <= len(name) <= 40) or not all(c.isalnum() or c in "._-" for c in name):
            flash("Numele trebuie să aibă 3–40 de caractere: litere, cifre, punct, minus, underscore.")
        elif len(pw) < 6:
            flash("Parola trebuie să aibă cel puțin 6 caractere.")
        elif User.query.filter(db.func.lower(User.username) == name.lower()).first():
            flash("Numele e deja folosit.")
        else:
            u = User(username=name, pw_hash=generate_password_hash(pw), settings={})
            db.session.add(u); db.session.commit()
            cookie.clear(); cookie.permanent = True; cookie["uid"] = u.id
            return redirect(url_for("counter"))
    return render_template("auth.html", mode="register", invite=bool(INVITE_CODE))


@app.route("/logout", methods=["POST"])
def logout():
    cookie.clear()
    return redirect(url_for("login"))


# ---------------- Pages ----------------
@app.route("/")
@login_required
def counter():
    return render_template("counter.html", settings=g.user.settings or {})


@app.route("/istoric")
@login_required
def history():
    ws = Workout.query.filter_by(user_id=g.user.id).order_by(Workout.started_at.desc()).limit(500).all()
    ws = [w for w in ws if w.n or (w.active_ms or 0) > 60000]
    tot = {"m": sum(w.elevation_m for w in ws), "n": sum(w.n for w in ws), "ms": sum(w.active_ms or 0 for w in ws),
           "vol": sum((w.load_stats() or {}).get("volume_kgm", 0) for w in ws)}
    return render_template("history.html", workouts=[w.summary() for w in ws], tot=tot)


@app.route("/sesiune/<int:wid>")
@login_required
def workout_page(wid):
    w = own_workout(wid)
    return render_template("workout.html", w=w.summary(), climbs=w.climbs or [], hr=w.hr or [], hr_source=w.hr_source,
                           polar=bool(g.user.polar_token), polar_configured=bool(POLAR_CLIENT_ID))


@app.route("/cont")
@login_required
def account():
    return render_template("account.html", polar=bool(g.user.polar_token), polar_configured=bool(POLAR_CLIENT_ID),
                           redirect_uri=polar_redirect_uri() if POLAR_CLIENT_ID else None,
                           client_hint=(POLAR_CLIENT_ID[:6] + "…") if POLAR_CLIENT_ID else None)


@app.route("/manifest.webmanifest")
def manifest():
    return send_from_directory("static", "manifest.webmanifest", mimetype="application/manifest+json")


# ---------------- API ----------------
def clean_ms(v):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    return v if 1_500_000_000_000 < v < 4_000_000_000_000 else None


@app.post("/api/settings")
@login_required
def api_settings():
    data = request.get_json(silent=True) or {}
    allowed = {"height": float, "facing": str, "beep": bool, "voice": bool, "up": float, "down": float, "model": int, "swapLR": bool,
               "vest": float, "ankle": float, "ankleOn": bool}
    s = dict(g.user.settings or {})
    for k, t in allowed.items():
        if k in data:
            try:
                s[k] = t(data[k])
            except (TypeError, ValueError):
                pass
    g.user.settings = s
    db.session.commit()
    return jsonify(ok=True)


@app.post("/api/workouts")
@login_required
def api_create():
    data = request.get_json(silent=True) or {}
    start = clean_ms(data.get("started_at"))
    h = data.get("height_cm")
    if not start or not isinstance(h, (int, float)) or not 5 <= h <= 60:
        return jsonify(error="bad_input"), 400
    w = Workout(user_id=g.user.id, started_at=start, ended_at=start, height_cm=float(h), climbs=[], active_ms=0)
    db.session.add(w); db.session.commit()
    return jsonify(id=w.id)


@app.route("/api/workouts/<int:wid>", methods=["PUT", "DELETE"])
@login_required
def api_workout(wid):
    w = own_workout(wid)
    if request.method == "DELETE":
        db.session.delete(w); db.session.commit()
        return jsonify(ok=True)
    data = request.get_json(silent=True) or {}
    # Full-state upsert from the client: idempotent, so a retried request can't double count.
    if "climbs" in data and isinstance(data["climbs"], list) and len(data["climbs"]) <= 20000:
        w.climbs = sorted(c for c in (clean_ms(x) for x in data["climbs"]) if c)
    if "active_ms" in data and isinstance(data["active_ms"], (int, float)) and data["active_ms"] >= 0:
        w.active_ms = int(data["active_ms"])
    if clean_ms(data.get("ended_at")):
        w.ended_at = clean_ms(data["ended_at"])
    if "note" in data:
        w.note = str(data["note"])[:200] or None
    if isinstance(data.get("hr"), list) and 0 < len(data["hr"]) <= 20000 and not (w.hr_source or "").startswith("Polar"):
        pts = []
        for p in data["hr"]:
            if isinstance(p, list) and len(p) == 2 and clean_ms(p[0]) and isinstance(p[1], (int, float)) and 25 <= p[1] <= 250:
                pts.append([clean_ms(p[0]), int(p[1])])
        if pts:
            w.hr, w.hr_source = pts, "live, centură Bluetooth"
    if isinstance(data.get("loads"), list) and len(data["loads"]) <= 20000:
        def ok(x):
            return isinstance(x, (int, float)) and 0 <= x <= 60
        w.loads = [[float(l[0]), float(l[1])] if isinstance(l, list) and len(l) == 2 and ok(l[0]) and ok(l[1]) else [0.0, 0.0]
                   for l in data["loads"]]
    if isinstance(data.get("legs"), str) and len(data["legs"]) <= 20000:
        w.legs = "".join(c if c in "LR" else "?" for c in data["legs"])
    db.session.commit()
    return jsonify(w.summary())


# ---------------- Polar AccessLink ----------------
def polar_redirect_uri():
    """Must match the URL registered at admin.polaraccesslink.com character for character."""
    if PUBLIC_URL:
        return PUBLIC_URL + "/polar/callback"
    url = url_for("polar_callback", _external=True)
    if url.startswith("http://") and not request.host.startswith(("localhost", "127.0.0.1")):
        url = "https://" + url[len("http://"):]
    return url


def polar_state_signer():
    return URLSafeTimedSerializer(app.secret_key, salt="polar-oauth")


def polar_done(ok, message):
    # The OAuth round trip may come back in a browser that lacks the app's login cookie
    # (iOS opens other sites from a Home Screen app in a separate view), so don't rely on it.
    if g.user:
        flash(message)
        return redirect(url_for("account"))
    return render_template("polar_done.html", ok=ok, message=message)


@app.route("/polar/connect")
@login_required
def polar_connect():
    if not POLAR_CLIENT_ID:
        abort(404)
    state = polar_state_signer().dumps({"uid": g.user.id, "n": secrets.token_urlsafe(8)})
    q = {"response_type": "code", "client_id": POLAR_CLIENT_ID, "scope": "accesslink.read_all",
         "redirect_uri": polar_redirect_uri(), "state": state}
    return redirect(POLAR_AUTH_URL + "?" + urlencode(q))


@app.route("/polar/callback")
def polar_callback():
    try:
        uid = polar_state_signer().loads(request.args.get("state", ""), max_age=900)["uid"]
    except (BadSignature, KeyError, TypeError):
        uid = None
    user = db.session.get(User, uid) if uid else None
    if not user or "code" not in request.args:
        reason = request.args.get("error", "")
        return polar_done(False, "Conectarea la Polar a fost anulată sau a expirat. Încearcă din nou din pagina Cont."
                          + (f" (Polar: {reason})" if reason else ""))
    r = requests.post(POLAR_TOKEN_URL, auth=(POLAR_CLIENT_ID, POLAR_CLIENT_SECRET), timeout=20,
                      headers={"Accept": "application/json"},
                      data={"grant_type": "authorization_code", "code": request.args["code"],
                            "redirect_uri": polar_redirect_uri()})
    if r.status_code != 200:
        app.logger.warning("Polar token exchange failed: %s %s", r.status_code, r.text[:300])
        return polar_done(False, f"Polar a refuzat conectarea (cod {r.status_code}).")
    tok = r.json()
    token, puid = tok.get("access_token"), str(tok.get("x_user_id", ""))
    # Register the user with our client; 409 means already registered, which is fine.
    rr = requests.post(f"{POLAR_API}/v3/users", json={"member-id": f"stepper-{user.id}"}, timeout=20,
                       headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    if rr.status_code not in (200, 201, 409):
        app.logger.warning("Polar user registration failed: %s %s", rr.status_code, rr.text[:300])
        return polar_done(False, f"Nu am putut înregistra contul la Polar (cod {rr.status_code}).")
    user.polar_token, user.polar_user_id = token, puid
    db.session.commit()
    return polar_done(True, "Contul Polar e conectat.")


@app.post("/polar/disconnect")
@login_required
def polar_disconnect():
    if g.user.polar_token and g.user.polar_user_id:
        try:
            requests.delete(f"{POLAR_API}/v3/users/{g.user.polar_user_id}", timeout=15,
                            headers={"Authorization": f"Bearer {g.user.polar_token}"})
        except requests.RequestException:
            pass
    g.user.polar_token = g.user.polar_user_id = None
    db.session.commit()
    flash("Contul Polar a fost deconectat.")
    return redirect(url_for("account"))


def parse_polar_time(ex):
    """Exercise start as epoch ms. Polar gives local start-time plus start-time-utc-offset in minutes."""
    st = ex.get("start-time") or ex.get("start_time")
    off = ex.get("start-time-utc-offset", ex.get("start_time_utc_offset", 0)) or 0
    dt = datetime.fromisoformat(st.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone(timedelta(minutes=int(off))))
    return int(dt.timestamp() * 1000)


def parse_duration_ms(s):
    """ISO-8601 duration like PT1H2M3.5S -> ms."""
    if not s or not s.startswith("PT"):
        return 0
    total, num = 0.0, ""
    for ch in s[2:]:
        if ch.isdigit() or ch == ".":
            num += ch
        else:
            total += float(num or 0) * {"H": 3600, "M": 60, "S": 1}.get(ch, 0); num = ""
    return int(total * 1000)


def hr_series(ex, start_ms):
    for smp in ex.get("samples") or []:
        if str(smp.get("sample-type", smp.get("sample_type"))) == "0":   # 0 = heart rate
            rate = float(smp.get("recording-rate", smp.get("recording_rate", 1)) or 1)
            out = []
            for i, v in enumerate(str(smp.get("data", "")).split(",")):
                try:
                    b = int(float(v))
                except ValueError:
                    continue
                if 25 <= b <= 250:
                    out.append([int(start_ms + i * rate * 1000), b])
            return out
    return []


@app.post("/api/workouts/<int:wid>/polar")
@login_required
def api_polar_import(wid):
    w = own_workout(wid)
    if not g.user.polar_token:
        return jsonify(error="Contul Polar nu e conectat."), 400
    H = {"Authorization": f"Bearer {g.user.polar_token}", "Accept": "application/json"}
    try:
        r = requests.get(f"{POLAR_API}/v3/exercises", headers=H, timeout=20)
    except requests.RequestException:
        return jsonify(error="Polar nu răspunde. Încearcă mai târziu."), 502
    if r.status_code == 401:
        g.user.polar_token = None; db.session.commit()
        return jsonify(error="Accesul la Polar a expirat. Conectează din nou contul din pagina Cont."), 401
    if r.status_code == 204 or not r.content:
        return jsonify(error="Polar nu are antrenamente noi. Sincronizează aplicația Polar Flow și încearcă din nou."), 404
    if r.status_code != 200:
        return jsonify(error=f"Polar a răspuns cu eroarea {r.status_code}."), 502

    w_start, w_end = w.started_at, max(w.ended_at or w.started_at, (w.climbs or [w.started_at])[-1])
    best, best_overlap = None, 0
    for ex in r.json() or []:
        try:
            s = parse_polar_time(ex)
        except (TypeError, ValueError, AttributeError):
            continue
        e = s + parse_duration_ms(ex.get("duration"))
        overlap = min(e, w_end) - max(s, w_start)
        if overlap > best_overlap:
            best, best_overlap = ex, overlap
    if not best:
        return jsonify(error="Nu am găsit în Polar un antrenament care se suprapune cu această sesiune."), 404

    try:
        d = requests.get(f"{POLAR_API}/v3/exercises/{best['id']}", params={"samples": "true"}, headers=H, timeout=30)
        d.raise_for_status()
    except requests.RequestException:
        return jsonify(error="Nu am putut descărca pulsul de la Polar."), 502
    ex = d.json()
    series = hr_series(ex, parse_polar_time(ex))
    margin = 2 * 60 * 1000
    series = [p for p in series if w_start - margin <= p[0] <= w_end + margin]
    if not series:
        return jsonify(error="Antrenamentul Polar găsit nu are date de puls."), 404
    w.hr = series
    w.hr_source = f"Polar · {ex.get('detailed-sport-info') or ex.get('sport') or 'antrenament'}"
    db.session.commit()
    return jsonify(ok=True, points=len(series), hr=w.hr_stats())


@app.get("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
