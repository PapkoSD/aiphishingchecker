"""Text clean-up for the email/message model.

Shared by the training script and the web app. The trained model pickles a
reference to ``clean_text``, so keep it importable from this module.
"""

import re

_URL_RE = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_MONEY_RE = re.compile(r"[$€£]\s?\d[\d,.]*|\d[\d,.]*\s?(usd|eur|gbp|dollars|euros)\b", re.IGNORECASE)
_NUMBER_RE = re.compile(r"\b\d[\d,.]*\b")
_SPACES_RE = re.compile(r"\s+")

# Words that only identify where a training email came from (the Enron,
# linguistics mailing-list and Nazario corpora), not whether it is phishing.
# Removing them stops the model learning "mentions Enron = safe" or
# "addressed to jose@monkey.org = phishing".
CORPUS_ARTIFACTS = frozenset("""
    enron ect hou hpl houston vince kaminski kaminskiect shirley crenshaw daren
    louise gas energy corp linguist linguistics sociolinguistics ling lang
    language university edu paliourg spamassassin exmh razor sourceforge zzzz jm
    netnoteinc slashdot cnet url date subject cc bcc forwarded original message
    pm am jose nazario monkey
""".split())


def clean_text(text):
    """Normalise a message so the model sees patterns, not specific values.

    Links, email addresses, amounts of money and other numbers are replaced
    with placeholder words, so "$5,000" and "$20" both become ``moneytoken``.
    """
    text = text.lower()
    text = _URL_RE.sub(" urltoken ", text)
    text = _EMAIL_RE.sub(" emailtoken ", text)
    text = _MONEY_RE.sub(" moneytoken ", text)
    text = _NUMBER_RE.sub(" numtoken ", text)
    return _SPACES_RE.sub(" ", text).strip()
