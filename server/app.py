#!/usr/bin/env python3
"""Minimal callback + GitHub deploy webhook API for BeynePlay landing."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import smtplib
import ssl
import subprocess
import sys
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

ENV_PATH = Path(os.environ.get("BEYNEPLAY_ENV", "/etc/beyneplay/landing.env"))
HOST = os.environ.get("BEYNEPLAY_API_HOST", "127.0.0.1")
PORT = int(os.environ.get("BEYNEPLAY_API_PORT", "8787"))
DEPLOY_SCRIPT = os.environ.get(
    "BEYNEPLAY_DEPLOY_SCRIPT", "/usr/local/sbin/beyneplay-landing-deploy.sh"
)
LEADS_PATH = Path(os.environ.get("BEYNEPLAY_LEADS", "/var/lib/beyneplay/leads.jsonl"))
MAX_BODY = 1024 * 1024
REQUIRED = ("name", "login", "phone", "description")


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        values[key.strip()] = raw.strip().strip('"').strip("'")
    return values


def smtp_ready(cfg: dict[str, str]) -> bool:
    if not cfg.get("SMTP_HOST"):
        return False
    # Google SMTP relay can be IP-authorized without mailbox login.
    if cfg.get("SMTP_USER") or cfg.get("SMTP_PASS"):
        return bool(cfg.get("SMTP_USER") and cfg.get("SMTP_PASS"))
    return True


def normalize_smtp_password(password: str) -> str:
    # Google App Passwords are often copied with spaces: "xxxx xxxx xxxx xxxx"
    return password.replace(" ", "").strip()


def save_lead(payload: dict[str, str]) -> None:
    from datetime import datetime, timezone

    LEADS_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    with LEADS_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def parse_recipients(*chunks: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for chunk in chunks:
        for addr in (chunk or "").split(","):
            email = addr.strip()
            if email and email not in seen:
                seen.add(email)
                out.append(email)
    return out


def send_mail(cfg: dict[str, str], payload: dict[str, str]) -> None:
    host = cfg["SMTP_HOST"]
    port = int(cfg.get("SMTP_PORT") or "587")
    user = (cfg.get("SMTP_USER") or "").strip()
    password = normalize_smtp_password(cfg.get("SMTP_PASS") or "")
    use_tls = str(cfg.get("SMTP_USE_TLS") or "").strip().lower() in {"1", "true", "yes", "on"}
    mail_from = cfg.get("SMTP_FROM") or user or "yanayava@beyneplay.com"
    primary = parse_recipients(cfg.get("MAIL_TO") or mail_from)
    bcc = parse_recipients(cfg.get("MAIL_BCC") or "")
    recipients = parse_recipients(",".join(primary + bcc))
    if not recipients:
        raise ValueError("no mail recipients configured")

    msg = EmailMessage()
    msg["Subject"] = f"BeynePlay: заявка от {payload['name']}"
    msg["From"] = mail_from
    msg["To"] = ", ".join(primary)
    reply = payload.get("login") or ""
    if "@" in reply:
        msg["Reply-To"] = reply
    msg.set_content(
        "Новая заявка с лендинга beyneplay.kz\n\n"
        f"Имя: {payload['name']}\n"
        f"Логин: {payload['login']}\n"
        f"Телефон: {payload['phone']}\n"
        f"Описание:\n{payload['description']}\n"
    )

    context = ssl.create_default_context()
    if port == 465 and not use_tls:
        with smtplib.SMTP_SSL(host, port, context=context, timeout=30) as smtp:
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg, to_addrs=recipients)
        return

    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.ehlo()
        if use_tls or port == 587:
            smtp.starttls(context=context)
            smtp.ehlo()
        if user and password:
            smtp.login(user, password)
        smtp.send_message(msg, to_addrs=recipients)




def parse_callback_body(handler: BaseHTTPRequestHandler) -> dict[str, str]:
    length = int(handler.headers.get("Content-Length") or "0")
    if length <= 0 or length > 64 * 1024:
        raise ValueError("invalid body size")
    raw = handler.rfile.read(length)
    content_type = (handler.headers.get("Content-Type") or "").split(";")[0].strip().lower()

    if content_type == "application/json":
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("json object required")
        return {k: str(data.get(k, "")).strip() for k in REQUIRED}

    if content_type in ("application/x-www-form-urlencoded", ""):
        parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        return {k: (parsed.get(k, [""])[0] or "").strip() for k in REQUIRED}

    raise ValueError("unsupported content type")


def validate(payload: dict[str, str]) -> str | None:
    for key in REQUIRED:
        if not payload.get(key):
            return f"missing field: {key}"
        if len(payload[key]) > 2000:
            return f"field too long: {key}"
    if not re.search(r"\d", payload["phone"]):
        return "invalid phone"
    return None


def verify_github_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    if not secret or not signature_header or not signature_header.startswith("sha256="):
        return False
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={digest}", signature_header)


def run_deploy() -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            ["sudo", "-n", DEPLOY_SCRIPT],
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "deploy failed").strip()
        return False, err[-500:]
    return True, "deploy started"


class Handler(BaseHTTPRequestHandler):
    server_version = "BeynePlayLandingAPI/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[landing-api] {self.address_string()} - {fmt % args}", file=sys.stderr)

    def _cors(self) -> None:
        origin = self.headers.get("Origin")
        if origin in (
            "https://beyneplay.kz",
            "https://www.beyneplay.kz",
            "http://beyneplay.kz",
            "http://www.beyneplay.kz",
            "http://127.0.0.1",
            "http://localhost",
        ):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self._cors()
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/api/callback":
            self._json(404, {"ok": False, "error": "not found"})
            return
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/api/health":
            cfg = load_env(ENV_PATH)
            self._json(
                200,
                {
                    "ok": True,
                    "smtp_configured": smtp_ready(cfg),
                    "deploy_webhook_configured": bool(cfg.get("DEPLOY_WEBHOOK_SECRET")),
                },
            )
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.rstrip("/")
        if path == "/api/github-webhook":
            self._handle_github_webhook()
            return
        if path != "/api/callback":
            self._json(404, {"ok": False, "error": "not found"})
            return

        try:
            payload = parse_callback_body(self)
        except Exception:
            self._json(400, {"ok": False, "error": "invalid request body"})
            return

        error = validate(payload)
        if error:
            self._json(400, {"ok": False, "error": error})
            return

        cfg = load_env(ENV_PATH)

        try:
            save_lead(payload)
        except Exception as exc:  # noqa: BLE001
            print(f"[landing-api] lead save error: {exc}", file=sys.stderr)
            self._json(500, {"ok": False, "error": "не удалось сохранить заявку"})
            return

        email_sent = False
        email_error = None
        if smtp_ready(cfg):
            try:
                send_mail(cfg, payload)
                email_sent = True
            except smtplib.SMTPAuthenticationError as exc:
                email_error = "smtp_auth"
                print(f"[landing-api] smtp auth error: {exc}", file=sys.stderr)
            except Exception as exc:  # noqa: BLE001
                email_error = "smtp_send"
                print(f"[landing-api] smtp error: {exc}", file=sys.stderr)
        else:
            email_error = "smtp_not_configured"
            print("[landing-api] smtp not configured; lead saved only", file=sys.stderr)

        # Заявку принимаем всегда после сохранения. Письмо — best effort.
        self._json(
            200,
            {
                "ok": True,
                "email_sent": email_sent,
                "email_error": email_error,
            },
        )

    def _handle_github_webhook(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0 or length > MAX_BODY:
            self._json(400, {"ok": False, "error": "invalid body size"})
            return
        body = self.rfile.read(length)
        cfg = load_env(ENV_PATH)
        secret = cfg.get("DEPLOY_WEBHOOK_SECRET", "")
        signature = self.headers.get("X-Hub-Signature-256")
        if not verify_github_signature(secret, body, signature):
            self._json(401, {"ok": False, "error": "invalid signature"})
            return

        event = self.headers.get("X-GitHub-Event", "")
        if event == "ping":
            self._json(200, {"ok": True, "pong": True})
            return
        if event != "push":
            self._json(200, {"ok": True, "ignored": event})
            return

        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._json(400, {"ok": False, "error": "invalid json"})
            return

        ref = payload.get("ref")
        if ref != "refs/heads/main":
            self._json(200, {"ok": True, "ignored": ref})
            return

        ok, message = run_deploy()
        if not ok:
            print(f"[landing-api] deploy failed: {message}", file=sys.stderr)
            self._json(500, {"ok": False, "error": message})
            return
        self._json(200, {"ok": True, "deployed": True})


def main() -> None:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[landing-api] listening on http://{HOST}:{PORT}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
