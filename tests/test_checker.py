"""Smoke tests: the shipped models load and the main examples get the right verdict."""

from pathlib import Path

import pytest

from phishchecker.analyzer import analyze_email, analyze_url
from phishchecker.app import create_app
from phishchecker.domains import find_lookalike

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.mark.parametrize("url", [
    "https://www.paypal.com/signin",
    "https://accounts.google.com/ServiceLogin",
    "https://github.com/PapkoSD/aiphishingchecker",
])
def test_official_sites_are_safe(url):
    assert analyze_url(url)["verdict"] == "safe"


@pytest.mark.parametrize("url", [
    "http://paypal.com.account-restore.xyz/webscr/login.php",
    "http://192.168.10.5/banking/login.php",
    "https://paypa1.com/login",
    "https://www.google.com/url?q=http://secure-bank-update.top/verify",
])
def test_phishing_links_are_caught(url):
    assert analyze_url(url)["verdict"] == "phishing"


def test_shortened_links_are_suspicious_not_certain():
    assert analyze_url("bit.ly/3xYzAb")["verdict"] == "suspicious"


@pytest.mark.parametrize("domain, imitates", [
    ("paypa1.com", "paypal.com"),
    ("rnicrosoft.com", "microsoft.com"),
    ("paypal.com", None),
    ("example.com", None),
])
def test_lookalike_domains(domain, imitates):
    assert find_lookalike(domain) == imitates


@pytest.mark.parametrize("sample, verdict", [
    ("phishing_paypal.eml", "phishing"),
    ("phishing_ceo_giftcard.txt", "phishing"),
    ("phishing_delivery_sms.txt", "phishing"),
    ("legit_order_shipped.eml", "safe"),
    ("legit_colleague.txt", "safe"),
])
def test_sample_emails(sample, verdict):
    path = SAMPLES / sample
    raw = path.read_bytes() if path.suffix == ".eml" else path.read_text(encoding="utf-8")
    assert analyze_email(raw)["verdict"] == verdict


def test_paypal_sample_explains_the_red_flags():
    reasons = " ".join(r["text"] for r in analyze_email((SAMPLES / "phishing_paypal.eml").read_bytes())["reasons"])
    assert "sender's name" in reasons
    assert "authentication" in reasons
    assert "actually goes to" in reasons


def test_empty_input_is_rejected():
    with pytest.raises(ValueError):
        analyze_email("   ")
    with pytest.raises(ValueError):
        analyze_url("")


def test_web_pages_and_api():
    client = create_app().test_client()
    assert client.get("/").status_code == 200
    assert client.get("/health").get_json()["status"] == "ok"

    page = client.post("/check/url", data={"url": "https://paypa1.com/login"})
    assert b"Likely phishing" in page.data

    api = client.post("/api/check/url", json={"url": "https://www.paypal.com/signin"})
    assert api.get_json()["verdict"] == "safe"

    api = client.post("/api/check/email", json={"text": ""})
    assert api.status_code == 400
