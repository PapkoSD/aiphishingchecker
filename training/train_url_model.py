"""Train the URL phishing classifier.

Two kinds of features are combined and fed into logistic regression:

  * character 3-5-grams of the URL, which pick up patterns like "-secure-" or
    "verify-acc" that phishing links reuse;
  * hand-crafted features (IP address as host, brand name in the wrong place,
    shortener, suspicious TLD, ...), which also power the app's explanations.

Two fixes for quirks of the dataset:

  * URLs are normalised (scheme and "www." removed). Most legitimate URLs in
    the data have no scheme, so otherwise "https://" would look like phishing.
  * Every legitimate URL in the data has a path, while many phishing ones are a
    bare domain. To stop the model learning "no path = phishing", the bare host
    of every URL is added as an extra example with the same label.

The test split groups URLs by registered domain, so the model is always scored
on websites it has never seen, which is a much harder, more honest test.

    python training/train_url_model.py
"""

import random
import time

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler

from common import MODEL_DIR, evaluate, load_dataset, print_metrics, save_metrics

from phishchecker.url_features import URLFeatureExtractor, host_only, normalize_url, split_url

# The full dataset (~1.3M URLs after augmentation) needs several GB of RAM.
# A random sample of this size trains in a few minutes on a laptop.
MAX_SAMPLES = 500_000


def build_model():
    return Pipeline([
        ("features", FeatureUnion([
            ("chars", TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                lowercase=False,
                min_df=5,
                max_features=200_000,
                sublinear_tf=True,
                dtype=np.float32,
            )),
            ("handcrafted", Pipeline([
                ("extract", URLFeatureExtractor()),
                ("scale", StandardScaler()),
            ])),
        ])),
        ("clf", LogisticRegression(C=2.0, max_iter=2000)),
    ])


def prepare(urls, labels):
    """Normalise, add bare-host examples, and drop URLs seen with both labels."""
    seen = {}
    for url, label in zip(urls, labels):
        for variant in (normalize_url(url), host_only(url)):
            if variant:
                seen.setdefault(variant, set()).add(label)
    return [(u, labs.pop()) for u, labs in seen.items() if len(labs) == 1]


def main():
    urls, labels = load_dataset("urls.json")
    print(f"Loaded {len(urls):,} URLs ({sum(labels):,} phishing)")

    rows = prepare(urls, labels)
    print(f"{len(rows):,} unique URLs after normalising and adding bare hosts")
    random.Random(42).shuffle(rows)
    rows = rows[:MAX_SAMPLES]
    X = [u for u, _ in rows]
    y = np.array([label for _, label in rows])

    # Group by the last two host labels (close enough to the registered domain).
    groups = [".".join(split_url(u)[0].split(".")[-2:]) for u in X]
    train_idx, test_idx = next(GroupShuffleSplit(test_size=0.2, random_state=42).split(X, y, groups))
    X_train, y_train = [X[i] for i in train_idx], y[train_idx]
    X_test, y_test = [X[i] for i in test_idx], y[test_idx]

    start = time.time()
    model = build_model().fit(X_train, y_train)
    metrics = evaluate(y_test, model.predict_proba(X_test)[:, 1])
    metrics.update(train_size=len(X_train), test_size=len(X_test))
    print_metrics(f"Held-out test set, unseen domains ({time.time() - start:.0f}s to train)", metrics)

    model = build_model().fit(X, y)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_DIR / "url_model.joblib", compress=3)
    save_metrics("url", metrics)
    print(f"\nSaved {MODEL_DIR / 'url_model.joblib'}")


if __name__ == "__main__":
    main()
