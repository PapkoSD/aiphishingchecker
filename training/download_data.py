"""Download the public phishing datasets used to train the models.

Sources:

  ealvaradob/phishing-dataset on Hugging Face (Apache-2.0)
  https://huggingface.co/datasets/ealvaradob/phishing-dataset
    texts.json          ~14k emails + ~6k SMS messages, labelled 1 (phishing) / 0 (legit)
    urls.json           ~835k URLs, labelled 1 (phishing) / 0 (legit)

  Phishing Email Curated Datasets, Al-Subaiey et al. (CC BY 4.0)
  https://doi.org/10.5281/zenodo.8339691
    Nazario_5.csv       real phishing emails collected by Jose Nazario (2015-2022),
                        mixed with legitimate mail
    Nigerian_Fraud.csv  "Nigerian prince" advance-fee scams

Files are saved to data/raw/ (ignored by git). Run from the repo root:

    python training/download_data.py
"""

import sys
import urllib.request
from pathlib import Path

HF_URL = "https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/{}"
ZENODO_URL = "https://zenodo.org/api/records/8339691/files/{}/content"
FILES = {
    "texts.json": HF_URL,
    "urls.json": HF_URL,
    "Nazario_5.csv": ZENODO_URL,
    "Nigerian_Fraud.csv": ZENODO_URL,
}
DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"


def _progress(name):
    def hook(blocks, block_size, total):
        if total <= 0:
            return
        done = min(blocks * block_size, total)
        pct = done * 100 // total
        sys.stdout.write(f"\r  {name}: {pct:3d}% ({done / 1e6:.1f} / {total / 1e6:.1f} MB)")
        sys.stdout.flush()

    return hook


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for name, url in FILES.items():
        target = DATA_DIR / name
        if target.exists() and target.stat().st_size > 0:
            print(f"  {name}: already downloaded, skipping")
            continue
        tmp = target.with_suffix(".part")
        urllib.request.urlretrieve(url.format(name), tmp, _progress(name))
        tmp.rename(target)
        print()
    print(f"Done. Data is in {DATA_DIR}")


if __name__ == "__main__":
    main()
