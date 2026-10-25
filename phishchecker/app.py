"""The web app: a page to paste an email or link, plus a small JSON API."""

from pathlib import Path

from flask import Flask, jsonify, render_template, request

from . import __version__
from .analyzer import analyze_email, analyze_url, model_metrics

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"

# Shown under the paste box. Keys are file names in samples/.
EMAIL_SAMPLES = {
    "phishing_paypal.eml": "Fake PayPal warning",
    "phishing_ceo_giftcard.txt": "Boss asking for gift cards",
    "phishing_delivery_sms.txt": "Parcel fee text message",
    "legit_order_shipped.eml": "Real shipping notice",
    "legit_colleague.txt": "Message from a colleague",
}
URL_SAMPLES = [
    "http://paypal.com.account-restore.xyz/webscr/login.php",
    "https://rnicrosoft-office365.com/login",
    "https://www.google.com/url?q=http://secure-bank-update.top/verify",
    "https://github.com/PapkoSD/aiphishingchecker",
    "bit.ly/3xYzAb",
]

MAX_UPLOAD_BYTES = 5 * 1024 * 1024


def _read_sample(name):
    if name not in EMAIL_SAMPLES:
        raise ValueError("Unknown sample.")
    path = SAMPLES_DIR / name
    return path.read_bytes() if path.suffix == ".eml" else path.read_text(encoding="utf-8")


def _email_input():
    """Return (raw email, text to show back in the box) from the submitted form."""
    upload = request.files.get("eml")
    if upload and upload.filename:
        data = upload.read()
        return data, data.decode("utf-8", errors="replace")
    sample = request.form.get("sample")
    if sample:
        raw = _read_sample(sample)
        return raw, raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
    text = request.form.get("text", "")
    return text, text


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

    def page(**context):
        context.setdefault("tab", "email")
        return render_template(
            "index.html",
            email_samples=EMAIL_SAMPLES,
            url_samples=URL_SAMPLES,
            metrics=model_metrics(),
            version=__version__,
            **context,
        )

    @app.get("/")
    def index():
        return page(tab="url" if request.args.get("tab") == "url" else "email")

    @app.post("/check/email")
    def check_email():
        raw, shown = _email_input()
        try:
            result = analyze_email(raw)
        except ValueError as exc:
            return page(tab="email", email_text=shown, error=str(exc)), 400
        return page(tab="email", email_text=shown, result=result)

    @app.post("/check/url")
    def check_url():
        url = request.form.get("url", "")
        try:
            result = analyze_url(url)
        except ValueError as exc:
            return page(tab="url", url_text=url, error=str(exc)), 400
        return page(tab="url", url_text=url, result=result)

    @app.post("/api/check/email")
    def api_email():
        if request.files.get("eml"):
            raw = request.files["eml"].read()
        else:
            raw = (request.get_json(silent=True) or {}).get("text", "")
        try:
            return jsonify(analyze_email(raw))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

    @app.post("/api/check/url")
    def api_url():
        url = (request.get_json(silent=True) or {}).get("url", "")
        try:
            return jsonify(analyze_url(url))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

    @app.get("/health")
    def health():
        return jsonify(status="ok", version=__version__)

    @app.errorhandler(413)
    def too_large(_):
        message = "That file is too big. Emails over 5 MB can't be checked."
        if request.path.startswith("/api/"):
            return jsonify(error=message), 413
        return page(tab="email", error=message), 413

    return app
