"""Turn pasted email text or a raw .eml file into the pieces the analyser needs."""

import re
from dataclasses import dataclass, field
from email import message_from_bytes, message_from_string, policy
from email.utils import parseaddr
from html import unescape
from html.parser import HTMLParser

_HEADER_LINE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s")
_KEY_HEADERS = ("from:", "subject:", "to:", "date:", "received:", "return-path:", "message-id:")
_URL_RE = re.compile(r"""(?:https?://|www\.)[^\s<>"'()\[\]{}]+""", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?"


@dataclass
class ParsedEmail:
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    auth_results: str = ""
    body: str = ""
    # (href, visible link text); text is "" for links found in plain text
    links: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    has_headers: bool = False


class _HTMLToText(HTMLParser):
    """Collect readable text and <a href> links from an HTML email body."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.links = []
        self._skip = 0
        self._href = None
        self._link_text = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head", "title"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href")
            self._link_text = []
        elif tag in ("br", "p", "div", "tr", "li", "h1", "h2", "h3", "table"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head", "title"):
            self._skip = max(0, self._skip - 1)
        elif tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), " ".join("".join(self._link_text).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.parts.append(data)
        if self._href is not None:
            self._link_text.append(data)

    def text(self):
        text = "".join(self.parts)
        text = re.sub(r"[ \t\xa0]+", " ", text)
        return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def html_to_text(html):
    parser = _HTMLToText()
    parser.feed(html)
    parser.close()
    return parser.text(), parser.links


def find_urls(text):
    return [m.group(0).rstrip(_TRAILING_PUNCT) for m in _URL_RE.finditer(text)]


def looks_like_raw_email(text):
    """True when pasted text starts with real email headers (e.g. "Show original")."""
    head = text.lstrip()[:5000].lower()
    first_line = head.split("\n", 1)[0]
    return bool(_HEADER_LINE_RE.match(first_line)) and sum(h in head for h in _KEY_HEADERS) >= 2


def _part_text(part):
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError, AssertionError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _from_message(msg):
    parsed = ParsedEmail(has_headers=True)
    parsed.subject = str(msg.get("subject", "") or "")
    parsed.from_name, parsed.from_addr = parseaddr(str(msg.get("from", "") or ""))
    parsed.reply_to = parseaddr(str(msg.get("reply-to", "") or ""))[1]
    parsed.auth_results = " ".join(str(h) for h in msg.get_all("authentication-results", []) or [])

    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            parsed.attachments.append(filename or "(unnamed attachment)")
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            plain.append(_part_text(part))
        elif ctype == "text/html":
            html.append(_part_text(part))

    links = []
    html_text = ""
    if html:
        html_text, links = html_to_text("\n".join(html))
    parsed.body = "\n\n".join(plain).strip() or html_text
    if not links:
        links = [(u, "") for u in find_urls(parsed.body)]
    parsed.links = links
    return parsed


def parse_email(raw):
    """Parse pasted text or the bytes of an uploaded .eml file."""
    if isinstance(raw, bytes):
        return _from_message(message_from_bytes(raw, policy=policy.default))

    if looks_like_raw_email(raw):
        return _from_message(message_from_string(raw.lstrip(), policy=policy.default))

    # Plain pasted message. Pick up a "Subject:" line if the user copied one.
    parsed = ParsedEmail()
    text = raw.strip()
    match = re.match(r"subject:\s*(.+)\n", text, re.IGNORECASE)
    if match:
        parsed.subject = match.group(1).strip()
        text = text[match.end():].strip()
    if re.search(r"<(html|body|a|div|table)\b", text, re.IGNORECASE):
        parsed.body, parsed.links = html_to_text(text)
    else:
        parsed.body = unescape(text)
        parsed.links = [(u, "") for u in find_urls(parsed.body)]
    return parsed
