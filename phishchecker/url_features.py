"""URL normalisation and hand-crafted URL features.

Shared by the training script and the web app, so a URL is always turned into
features the same way. The trained model pickles a reference to
``URLFeatureExtractor``, so keep it importable from this module.
"""

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import unquote

import numpy as np
import tldextract
from sklearn.base import BaseEstimator, TransformerMixin

# Use the public-suffix list bundled with tldextract, never fetch it online.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc",
    "bl.ink", "s.id", "v.gd", "lnkd.in", "qrco.de", "short.io", "bitly.com",
}

# TLDs that show up far more often in phishing than in legitimate sites.
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "kim", "work", "loan", "men", "party", "review", "stream", "download",
    "racing", "win", "bid", "icu", "cyou", "rest", "cfd", "sbs", "buzz",
    "monster", "quest", "online", "site", "fun",
}

# Brands that are commonly impersonated. A brand name anywhere in the URL
# *except* the real registered domain is a strong phishing signal.
BRANDS = {
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook",
    "netflix", "amazon", "google", "gmail", "facebook", "instagram", "whatsapp",
    "dhl", "fedex", "ups", "usps", "chase", "wellsfargo", "citibank", "hsbc",
    "santander", "revolut", "binance", "coinbase", "metamask", "steam",
    "dropbox", "docusign", "adobe", "linkedin", "ebay", "yahoo", "wetransfer",
    "americanexpress", "amex", "barclays", "booking", "airbnb", "spotify",
}

SENSITIVE_WORDS = (
    "login", "log-in", "signin", "sign-in", "logon", "verify", "verification",
    "account", "update", "secure", "security", "confirm", "banking", "password",
    "unlock", "suspend", "wallet", "invoice", "payment", "billing", "webscr",
    "authenticate", "recover", "restore", "unusual", "limited", "credential",
)

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://")
_WWW_RE = re.compile(r"^www\d?\.")


def normalize_url(url):
    """Lower-case and strip the parts that don't help tell phishing apart.

    The scheme, a leading ``www.`` and a trailing slash are removed. In the
    training data legitimate URLs rarely carry a scheme, so keeping it would
    teach the model that ``https://`` means phishing.
    """
    url = url.strip().strip("<>\"'").lower()
    url = _SCHEME_RE.sub("", url)
    url = _WWW_RE.sub("", url)
    return url.rstrip("/")


def split_url(normalized):
    """Split a normalised URL into (host, rest, has_userinfo, has_port)."""
    cut = len(normalized)
    for sep in "/?#":
        idx = normalized.find(sep)
        if idx != -1:
            cut = min(cut, idx)
    netloc, rest = normalized[:cut], normalized[cut:]
    has_userinfo = "@" in netloc
    if has_userinfo:
        netloc = netloc.rsplit("@", 1)[1]
    has_port = bool(re.search(r":\d+$", netloc))
    host = re.sub(r":\d+$", "", netloc)
    return host, rest, has_userinfo, has_port


def host_only(url):
    """Return just the host part of a URL, normalised."""
    return split_url(normalize_url(url))[0]


def _is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        # Hex or decimal encoded IPs, e.g. 0x7f000001 or 3232235777
        return bool(re.fullmatch(r"(0x[0-9a-f]{8}|\d{8,10})", host))


def _entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def describe_url(url):
    """Return a dict of named, human-meaningful features for one URL."""
    normalized = normalize_url(url)
    host, rest, has_userinfo, has_port = split_url(normalized)
    parts = _extract(host)
    registered = parts.top_domain_under_public_suffix or host
    subdomain = parts.subdomain
    tld = parts.suffix.rsplit(".", 1)[-1] if parts.suffix else ""
    path = unquote(rest)

    # Brand appears outside the real registered domain (paypal.secure-login.com,
    # secure-login.com/paypal/, paypal-help.com). Short brands must match a whole
    # word so "ups" doesn't fire on "groups".
    tokens = set(re.split(r"[^a-z0-9]+", f"{subdomain} {path} {parts.domain}"))
    impersonated = sorted(
        b for b in BRANDS
        if parts.domain != b
        and any(t == b or (len(b) >= 6 and b in t) for t in tokens)
    )

    return {
        "url_length": len(normalized),
        "host_length": len(host),
        "host_dots": host.count("."),
        "host_hyphens": host.count("-"),
        "subdomain_levels": len(subdomain.split(".")) if subdomain else 0,
        "path_depth": path.count("/"),
        "query_params": path.count("&") + ("?" in path),
        "digit_ratio": sum(c.isdigit() for c in host) / max(len(host), 1),
        "has_ip": int(_is_ip(host)),
        "has_at": int(has_userinfo),
        "has_port": int(has_port),
        "has_punycode": int("xn--" in host),
        "is_shortener": int(registered in URL_SHORTENERS),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "brand_impersonation": int(bool(impersonated)),
        "sensitive_words": sum(w in normalized for w in SENSITIVE_WORDS),
        "host_entropy": _entropy(host),
        "embedded_domain": int(bool(re.search(r"\.(com|net|org)[.\-]", subdomain + "."))),
        "redirect_in_path": int("//" in path or "http" in path),
        "percent_encoded": path.count("%"),
        # Not model features, used for explanations only
        "_host": host,
        "_registered": registered,
        "_brands": impersonated,
    }


FEATURE_NAMES = [
    "url_length", "host_length", "host_dots", "host_hyphens", "subdomain_levels",
    "path_depth", "query_params", "digit_ratio", "has_ip", "has_at", "has_port",
    "has_punycode", "is_shortener", "suspicious_tld", "brand_impersonation",
    "sensitive_words", "host_entropy", "embedded_domain", "redirect_in_path",
    "percent_encoded",
]

# Counts that can be large get log-scaled so one huge URL doesn't dominate.
_LOG_FEATURES = {"url_length", "host_length", "path_depth", "query_params", "percent_encoded"}


def feature_vector(desc):
    return [
        math.log1p(desc[name]) if name in _LOG_FEATURES else float(desc[name])
        for name in FEATURE_NAMES
    ]


class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    """scikit-learn transformer: normalised URL strings -> hand-crafted features."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return np.array([feature_vector(describe_url(u)) for u in X], dtype=np.float64)

    def get_feature_names_out(self, input_features=None):
        return np.array(FEATURE_NAMES, dtype=object)
