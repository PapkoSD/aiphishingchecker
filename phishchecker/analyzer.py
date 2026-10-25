"""Score emails and URLs and explain the result in plain language.

The machine-learning models give the main score. On top of that, a few
well-understood checks (official domains, look-alike domains, spoofed sender
names, links whose text and target differ, failed SPF/DKIM/DMARC) adjust it and
produce the reasons shown to the user.
"""

import json
import re
from functools import cache
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

import joblib
import numpy as np
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

from .domains import find_lookalike, is_user_content, trusted_match
from .email_parser import parse_email
from .url_features import BRANDS, FEATURE_NAMES, SENSITIVE_WORDS, describe_url, normalize_url, split_url

MODEL_DIR = Path(__file__).resolve().parent / "models"

SAFE_BELOW = 0.35
PHISHING_FROM = 0.65
MAX_LINKS = 25

# How brand names are written in explanations (default: Title Case).
BRAND_DISPLAY = {
    "paypal": "PayPal", "icloud": "iCloud", "office365": "Office 365", "linkedin": "LinkedIn",
    "whatsapp": "WhatsApp", "ebay": "eBay", "dhl": "DHL", "ups": "UPS", "usps": "USPS",
    "hsbc": "HSBC", "metamask": "MetaMask", "docusign": "DocuSign", "wetransfer": "WeTransfer",
    "americanexpress": "American Express", "amex": "Amex", "fedex": "FedEx", "wellsfargo": "Wells Fargo",
}

RISKY_ATTACHMENTS = (
    ".html", ".htm", ".shtml", ".svg", ".exe", ".scr", ".bat", ".cmd", ".com", ".js",
    ".vbs", ".jar", ".iso", ".img", ".msi", ".lnk", ".hta", ".docm", ".xlsm", ".pptm",
)


@cache
def email_model():
    return joblib.load(MODEL_DIR / "email_model.joblib")


@cache
def url_model():
    return joblib.load(MODEL_DIR / "url_model.joblib")


@cache
def model_metrics():
    path = MODEL_DIR / "metrics.json"
    return json.loads(path.read_text()) if path.exists() else {}


def verdict(score):
    if score >= PHISHING_FROM:
        return "phishing"
    if score >= SAFE_BELOW:
        return "suspicious"
    return "safe"


def _reason(text, level="danger"):
    """level: "danger" pushes towards phishing, "warning" is worth a look, "good" is reassuring."""
    return {"text": text, "level": level}


# ---------------------------------------------------------------- URLs

def _url_feature_reasons(desc, contributions):
    """Explain the hand-crafted URL features that pushed the score up."""
    host, registered = desc["_host"], desc["_registered"]
    messages = {
        "has_ip": f"Uses a raw IP address ({host}) instead of a website name.",
        "has_at": f"Contains an \"@\" before the domain. Browsers ignore everything before it, so the link really goes to {host}.",
        "has_port": "Uses an unusual port number, which normal websites rarely do.",
        "has_punycode": f"The domain uses special look-alike characters ({host}).",
        "is_shortener": "It's a shortened link, so the real destination is hidden.",
        "suspicious_tld": f"Uses a domain ending (.{registered.rsplit('.', 1)[-1]}) that is popular with scammers.",
        "brand_impersonation": f"Mentions {', '.join(BRAND_DISPLAY.get(b, b.title()) for b in desc['_brands'])} "
                               f"but the website is actually {registered}.",
        "embedded_domain": f"Puts a fake domain at the start ({host}) so it looks like a real site at a glance.",
        "sensitive_words": "Contains words used to lure people: "
                           + ", ".join(w for w in SENSITIVE_WORDS if w in normalize_url(desc["_url"])) + ".",
        "subdomain_levels": "Has an unusually long chain of subdomains.",
        "host_hyphens": "The domain name has several hyphens, a common trick (e.g. secure-login-bank.com).",
        "url_length": "Very long link that makes it hard to see where it really goes.",
        "redirect_in_path": "Contains another web address inside it, so it may redirect you somewhere else.",
        "percent_encoded": "Uses lots of encoded characters to hide what the link says.",
        "digit_ratio": "The domain name contains a lot of numbers.",
        "host_entropy": "The domain name looks randomly generated.",
    }
    # Only explain a feature if it is actually "on" for this URL.
    active = {
        "has_ip": desc["has_ip"], "has_at": desc["has_at"], "has_port": desc["has_port"],
        "has_punycode": desc["has_punycode"], "is_shortener": desc["is_shortener"],
        "suspicious_tld": desc["suspicious_tld"], "brand_impersonation": desc["brand_impersonation"],
        "embedded_domain": desc["embedded_domain"], "sensitive_words": desc["sensitive_words"] > 0,
        "subdomain_levels": desc["subdomain_levels"] >= 3, "host_hyphens": desc["host_hyphens"] >= 2,
        "url_length": desc["url_length"] > 100, "redirect_in_path": desc["redirect_in_path"],
        "percent_encoded": desc["percent_encoded"] > 3,
        "digit_ratio": desc["digit_ratio"] > 0.3 and not desc["has_ip"],
        "host_entropy": desc["host_entropy"] > 3.9,
    }
    ranked = sorted(
        (name for name in messages if active[name] and contributions.get(name, 0) > 0.05),
        key=lambda name: -contributions[name],
    )
    return [_reason(messages[name]) for name in ranked]


def _model_url_score(normalized):
    """Return (probability, per-feature contributions, char n-gram contribution)."""
    model = url_model()
    union, clf = model.named_steps["features"], model.named_steps["clf"]
    x = union.transform([normalized])
    coef = clf.coef_[0]
    contrib = x.multiply(coef).toarray()[0] if hasattr(x, "multiply") else x[0] * coef
    n_hand = len(FEATURE_NAMES)
    hand = dict(zip(FEATURE_NAMES, contrib[-n_hand:]))
    chars = float(np.sum(contrib[:-n_hand]))
    proba = float(clf.predict_proba(x)[0, 1])
    return proba, hand, chars


def _redirect_target(url):
    """If the link carries another URL in its query string (?url=..., ?q=...), return it."""
    try:
        query = urlsplit(url if "://" in url else "http://" + url).query
    except ValueError:
        return None
    for _, value in parse_qsl(query):
        value = unquote(value)
        if re.match(r"https?://", value, re.IGNORECASE):
            return value
    return None


def analyze_url(url, _depth=0):
    url = url.strip()
    normalized = normalize_url(url)
    if not normalized:
        raise ValueError("Please enter a link to check.")

    desc = describe_url(url)
    desc["_url"] = url
    host, registered = desc["_host"], desc["_registered"]
    _, path, _, _ = split_url(normalized)

    score, contributions, char_contrib = _model_url_score(normalized)
    reasons = _url_feature_reasons(desc, contributions)
    if char_contrib > 1.5 and not desc["is_shortener"]:
        reasons.append(_reason("The wording of the link looks like phishing links the model has seen before.", "warning"))

    lookalike = find_lookalike(registered)
    trusted = trusted_match(host)
    user_content = is_user_content(host, path)
    redirect = _redirect_target(url) if _depth == 0 else None

    if lookalike:
        score = max(score, 0.95)
        reasons.insert(0, _reason(f"{registered} is a look-alike of {lookalike}. Check the spelling carefully."))
    elif trusted and not user_content:
        score = min(score, 0.05)
        reasons = [_reason(f"This is the official {trusted} website.", "good")]
    if desc["is_shortener"] and not lookalike:
        # Shorteners are used by everyone; the model can't see the destination.
        score = min(max(score, 0.4), 0.6)
        reasons = [_reason(
            "It's a shortened link, so the real destination is hidden. Don't click it unless you trust "
            "the sender; a link-expander website can show you where it goes first.", "warning")]
    if user_content:
        score = max(score, 0.4)
        reasons.insert(0, _reason(
            f"Hosted on {host}, a legitimate service where anyone can publish pages or share files. "
            "Scammers use these to look trustworthy, so check who sent it.", "warning"))
    if redirect:
        target = analyze_url(redirect, _depth=1)
        if target["score"] > score:
            score = target["score"]
            reasons = [r for r in reasons if r["level"] != "good"]
        reasons.insert(0, _reason(
            f"The link sends you on to another site: {target['host']} (rated {target['verdict']}).",
            "danger" if target["verdict"] != "safe" else "warning"))

    if not reasons and score < SAFE_BELOW:
        reasons.append(_reason("Nothing about this link looks like typical phishing.", "good"))

    return {
        "type": "url",
        "url": url,
        "host": host,
        "registered_domain": registered,
        "score": round(score, 3),
        "verdict": verdict(score),
        "reasons": reasons,
    }


# ---------------------------------------------------------------- emails

def _top_phrases(text, limit=6):
    """Words and phrases in the message that pushed the score towards phishing."""
    model = email_model()
    vec, clf = model.named_steps["tfidf"], model.named_steps["clf"]
    x = vec.transform([text])
    contrib = x.multiply(clf.coef_[0]).tocsr()
    names = vec.get_feature_names_out()
    order = np.argsort(-contrib.data)
    phrases = []
    for value, i in zip(contrib.data[order], contrib.indices[order]):
        if value <= 0.15:
            break
        name = names[i]
        if "token" in name or all(word in ENGLISH_STOP_WORDS for word in name.split()):
            continue
        if any(name in p or p in name for p in phrases):
            continue
        phrases.append(name)
        if len(phrases) == limit:
            break
    return phrases


def _domain_of(address):
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def _registered(domain):
    return describe_url(domain)["_registered"] if domain else ""


def _header_reasons(parsed):
    """Strong warning signs in the sender, reply-to and authentication headers."""
    reasons, strong = [], 0
    from_domain = _domain_of(parsed.from_addr)
    from_reg = _registered(from_domain)

    if parsed.from_name and from_domain:
        name_tokens = set(re.split(r"[^a-z0-9]+", parsed.from_name.lower()))
        brands = sorted(b for b in BRANDS if b in name_tokens and from_reg.split(".")[0] != b)
        if brands and not trusted_match(from_domain):
            reasons.append(_reason(
                f"The sender's name says \"{parsed.from_name}\", but the email really came from {parsed.from_addr}."))
            strong += 1

    lookalike = find_lookalike(from_reg)
    if lookalike:
        reasons.append(_reason(f"The sender's domain {from_reg} is a look-alike of {lookalike}."))
        strong += 1

    reply_reg = _registered(_domain_of(parsed.reply_to))
    if reply_reg and from_reg and reply_reg != from_reg:
        reasons.append(_reason(
            f"Replies would go to a different address ({parsed.reply_to}) than the sender's.", "warning"))

    auth = parsed.auth_results.lower()
    failed = [check.upper() for check in ("spf", "dkim", "dmarc") if re.search(rf"\b{check}=(fail|softfail)", auth)]
    if failed:
        reasons.append(_reason(
            f"The sender failed email authentication ({', '.join(failed)}), so it may not be who it claims to be."))
        strong += 1
    elif re.search(r"\bdmarc=pass\b", auth) and re.search(r"\b(spf|dkim)=pass\b", auth):
        reasons.append(_reason("The sender passed email authentication checks (SPF/DKIM/DMARC).", "good"))

    for name in parsed.attachments:
        if name.lower().endswith(RISKY_ATTACHMENTS):
            reasons.append(_reason(f"Has a risky attachment: {name}. Don't open it unless you were expecting it."))
            strong += 1
    return reasons, strong


def _link_text_mismatch(href, text):
    """A link that *shows* one website but *goes to* another."""
    shown = re.search(r"((?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,})", text.lower())
    if not shown or not href.lower().startswith(("http", "www")):
        return None
    shown_reg = _registered(split_url(normalize_url(shown.group(1)))[0])
    real_reg = describe_url(href)["_registered"]
    if shown_reg and real_reg and shown_reg != real_reg:
        return shown_reg, real_reg
    return None


def analyze_email(raw):
    parsed = parse_email(raw)
    text = f"{parsed.subject}\n\n{parsed.body}".strip()
    if not text and not parsed.links:
        raise ValueError("The email looks empty. Paste the full message, or upload the .eml file.")

    text_score = float(email_model().predict_proba([text])[0, 1]) if text else 0.0
    reasons, strong = _header_reasons(parsed)

    links, seen = [], set()
    for href, link_text in parsed.links:
        if not href.lower().startswith(("http://", "https://", "www.")):
            continue
        key = normalize_url(href)
        if key in seen:
            continue
        seen.add(key)
        result = analyze_url(href)
        mismatch = _link_text_mismatch(href, link_text)
        if mismatch:
            result["score"] = max(result["score"], 0.9)
            result["verdict"] = verdict(result["score"])
            reasons.append(_reason(f"A link shows \"{mismatch[0]}\" but actually goes to {mismatch[1]}."))
            strong += 1
        result["text"] = link_text
        links.append(result)
        if len(links) == MAX_LINKS:
            break
    links.sort(key=lambda r: -r["score"])

    link_score = links[0]["score"] if links else 0.0
    risky_links = [l for l in links if l["verdict"] == "phishing"]
    if risky_links:
        reasons.append(_reason(
            f"Contains {len(risky_links)} suspicious link{'s' if len(risky_links) > 1 else ''}, "
            f"e.g. {risky_links[0]['host']}."))

    # The text model is the main signal; risky links and strong warning signs raise it.
    score = 1 - (1 - text_score) * (1 - 0.6 * link_score)
    if strong:
        score = max(score, min(0.4 + 0.15 * strong, 0.95))

    phrases = _top_phrases(text) if text_score >= SAFE_BELOW else []
    if phrases:
        reasons.append(_reason(
            "Uses wording common in phishing: " + ", ".join(f"\"{p}\"" for p in phrases) + ".", "warning"))
    if not reasons and score < SAFE_BELOW:
        reasons.append(_reason("The wording doesn't look like typical phishing.", "good"))
    if not parsed.has_headers:
        reasons.append(_reason(
            "Tip: upload the .eml file (or paste the full original with headers) to also check the real sender.",
            "info"))

    return {
        "type": "email",
        "score": round(score, 3),
        "verdict": verdict(score),
        "text_score": round(text_score, 3),
        "subject": parsed.subject,
        "sender": parsed.from_addr,
        "sender_name": parsed.from_name,
        "reasons": reasons,
        "links": links,
        "attachments": parsed.attachments,
    }
