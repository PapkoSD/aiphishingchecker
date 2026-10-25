"""Helpers shared by the training scripts."""

import csv
import json
import sys
from datetime import date
from email.header import decode_header, make_header
from pathlib import Path

from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data" / "raw"
MODEL_DIR = ROOT / "phishchecker" / "models"
METRICS_FILE = MODEL_DIR / "metrics.json"

# Make `import phishchecker` work when a script is run as `python training/x.py`.
sys.path.insert(0, str(ROOT))


def load_dataset(name):
    path = DATA_DIR / name
    if not path.exists():
        sys.exit(f"{path} not found. Run `python training/download_data.py` first.")
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)
    return [r["text"] for r in rows], [int(r["label"]) for r in rows]


def _decode_subject(subject):
    try:
        return str(make_header(decode_header(subject)))
    except Exception:
        return subject


def load_email_csv(name):
    """Load one of the Zenodo CSVs as "Subject: ...\n\nbody" texts."""
    path = DATA_DIR / name
    if not path.exists():
        sys.exit(f"{path} not found. Run `python training/download_data.py` first.")
    csv.field_size_limit(sys.maxsize)
    texts, labels = [], []
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            body = (row.get("body") or "").strip()
            if not body:
                continue
            texts.append(f"Subject: {_decode_subject(row.get('subject') or '')}\n\n{body}")
            labels.append(int(row["label"]))
    return texts, labels


def evaluate(y_true, proba, threshold=0.5):
    pred = [int(p >= threshold) for p in proba]
    return {
        "accuracy": round(accuracy_score(y_true, pred), 4),
        "precision": round(precision_score(y_true, pred), 4),
        "recall": round(recall_score(y_true, pred), 4),
        "f1": round(f1_score(y_true, pred), 4),
        "roc_auc": round(roc_auc_score(y_true, proba), 4),
    }


def save_metrics(model_name, metrics):
    """Merge one model's test metrics into phishchecker/models/metrics.json."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    all_metrics = {}
    if METRICS_FILE.exists():
        all_metrics = json.loads(METRICS_FILE.read_text())
    all_metrics[model_name] = {**metrics, "trained_on": date.today().isoformat()}
    METRICS_FILE.write_text(json.dumps(all_metrics, indent=2) + "\n")


def print_metrics(title, metrics):
    print(f"\n{title}")
    for key, value in metrics.items():
        print(f"  {key:>10}: {value}")
