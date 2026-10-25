"""Train the email / message phishing classifier.

TF-IDF over words and two-word phrases, fed into logistic regression. A linear
model is used on purpose: every word gets a weight, so the app can show *which*
phrases made a message look like phishing.

Training data:

  * texts.json          legitimate emails and SMS only (Hugging Face). Its "phishing"
                        half is mostly ordinary spam (pills, stock tips, ringtones),
                        which taught the model that any commercial email is phishing
                        and made it flag real receipts and account alerts. Spam is not
                        phishing, so that half is left out.
  * Nazario_5.csv       real phishing emails 2015-2022 + legitimate mail (Zenodo)
  * Nigerian_Fraud.csv  advance-fee scams (Zenodo)
  * extra_examples.json hand-written modern examples (legit account notifications,
                        CEO gift-card scams, MFA fatigue, fake invoices...) that the
                        public datasets barely cover. These are always kept in the
                        training set and given extra weight; they are never used
                        to score the model.

    python training/train_email_model.py
"""

import json
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from common import MODEL_DIR, evaluate, load_dataset, load_email_csv, print_metrics, save_metrics

from phishchecker.text_features import CORPUS_ARTIFACTS, clean_text

EXTRA_EXAMPLES = Path(__file__).resolve().parent / "extra_examples.json"
EXTRA_WEIGHT = 25.0


def build_model():
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            preprocessor=clean_text,
            stop_words=sorted(CORPUS_ARTIFACTS),
            ngram_range=(1, 2),
            min_df=3,
            max_df=0.9,
            max_features=60_000,
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(C=4.0, class_weight="balanced", max_iter=2000)),
    ])


def load_public_data():
    t, l = load_dataset("texts.json")
    texts = [text for text, label in zip(t, l) if label == 0]
    labels = [0] * len(texts)
    print(f"  {'texts.json':20s} {len(texts):6,} messages (legitimate only)")
    for name in ["Nazario_5.csv", "Nigerian_Fraud.csv"]:
        t, l = load_email_csv(name)
        print(f"  {name:20s} {len(t):6,} messages ({sum(l):,} phishing)")
        texts += t
        labels += l
    return texts, labels


def fit(texts, labels, extra_texts, extra_labels):
    weights = np.r_[np.ones(len(texts)), np.full(len(extra_texts), EXTRA_WEIGHT)]
    return build_model().fit(texts + extra_texts, labels + extra_labels, clf__sample_weight=weights)


def main():
    print("Loading data:")
    texts, labels = load_public_data()
    extras = json.loads(EXTRA_EXAMPLES.read_text(encoding="utf-8"))
    extra_texts = [e["text"] for e in extras]
    extra_labels = [e["label"] for e in extras]
    print(f"  {EXTRA_EXAMPLES.name:20s} {len(extras):6,} messages ({sum(extra_labels):,} phishing)")

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, stratify=labels, random_state=42
    )

    start = time.time()
    model = fit(X_train, y_train, extra_texts, extra_labels)
    metrics = evaluate(y_test, model.predict_proba(X_test)[:, 1])
    metrics.update(train_size=len(X_train) + len(extras), test_size=len(X_test))
    print_metrics(f"Held-out test set ({time.time() - start:.0f}s to train)", metrics)

    # Ship a model trained on all the data; the metrics above are the honest estimate.
    model = fit(texts, labels, extra_texts, extra_labels)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_DIR / "email_model.joblib", compress=3)
    save_metrics("email", metrics)
    print(f"\nSaved {MODEL_DIR / 'email_model.joblib'}")


if __name__ == "__main__":
    main()
