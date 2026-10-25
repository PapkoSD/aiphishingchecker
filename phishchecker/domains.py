"""Known official domains, user-content hosts and look-alike detection."""

from functools import cache
from pathlib import Path

TRUSTED_DOMAINS_FILE = Path(__file__).resolve().parent / "data" / "trusted_domains.txt"

# Legitimate services where *anyone* can publish a page or share a file.
# Phishers love them because the domain itself looks trustworthy, so links on
# these hosts are never treated as safe just because of the domain.
USER_CONTENT_HOSTS = (
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle",
    "storage.googleapis.com", "firebasestorage.googleapis.com", "script.google.com",
    "forms.office.com", "sharepoint.com", "onedrive.live.com", "1drv.ms",
    "dropbox.com/s/", "dl.dropboxusercontent.com", "github.io", "gitlab.io",
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "r2.dev",
    "netlify.app", "vercel.app", "herokuapp.com", "glitch.me", "repl.co",
    "weebly.com", "wixsite.com", "blogspot.com", "wordpress.com",
    "000webhostapp.com", "notion.site", "typeform.com", "jotform.com",
    "ipfs.io", "linktr.ee", "canva.site", "squarespace.com", "webflow.io",
)

# Characters and pairs that look alike, used to spot domains like paypa1.com.
_HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("@", "a")]


@cache
def trusted_domains():
    lines = TRUSTED_DOMAINS_FILE.read_text(encoding="utf-8").splitlines()
    return frozenset(
        line.strip().lower() for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    )


def _matches(host, domain):
    return host == domain or host.endswith("." + domain)


def is_user_content(host, path=""):
    target = host + path
    return any(_matches(host, h) or target.startswith(h) for h in USER_CONTENT_HOSTS)


def trusted_match(host):
    """Return the trusted domain that ``host`` belongs to, or None."""
    for domain in trusted_domains():
        if _matches(host, domain):
            return domain
    return None


def _edit_distance(a, b, limit=2):
    """Levenshtein distance, giving up early once it exceeds ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return prev[-1]


def _deglyph(label):
    for fake, real in _HOMOGLYPHS:
        label = label.replace(fake, real)
    return label


def find_lookalike(registered_domain):
    """Return the trusted domain that ``registered_domain`` imitates, or None.

    Catches typos and swapped characters (paypa1.com, rnicrosoft.com,
    arnazon.de, gooogle.com) by comparing the name part of the domain with
    each trusted domain's name part.
    """
    if not registered_domain or registered_domain in trusted_domains():
        return None
    label = registered_domain.split(".")[0]
    if len(label) < 4:
        return None
    for domain in sorted(trusted_domains()):
        real = domain.split(".")[0]
        if len(real) < 5 or label == real:
            continue
        if _deglyph(label) == real:
            return domain
        if len(real) >= 6 and _edit_distance(label, real, limit=1) == 1:
            return domain
    return None
