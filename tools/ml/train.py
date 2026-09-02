#!/usr/bin/env python3
"""
PR 14 — Section 3 — offline trainer for the AntiStealer ML family
classifier.

This script consumes a labelled-features CSV exported from the analyser
(`AntiStealer.Core/MlFeatureVector` produces 64-float vectors per
sample; see `features.py` for the schema) and emits a `model.json` that
the runtime classifier in `AntiStealer.Core/MlClassifier.cs` can load.

Output schema (matches `AntiStealer.Core/MlClassifier.cs:MlModelFile`):

    {
      "version": 1,
      "feature_dim": 64,
      "classes": ["clean", "RedLine", "Lumma", "Rhadamanthys", ...],
      "weights": [[64 floats], ...K rows],
      "bias":    [b0, b1, ...K floats],
      "platt":   [{"a": A_k, "b": B_k}, ...K]   # optional, Platt scaler
    }

Usage:

    python tools/ml/train.py \
        --features features.csv \
        --output    family.json \
        --calibrate                 # also fits Platt scaling

CSV columns:

    label,f0,f1,...,f63

The trainer uses scikit-learn's LogisticRegression (multinomial) as the
backbone and a per-class Platt scaler (sigmoid fit on a held-out
calibration split). Both are intentionally simple so the resulting
weights deserialise into our compact JSON shape and run on any host
without an ONNX runtime.

Note: this script is *not* compiled by the .NET build. It's an
offline tool — install dependencies with `pip install scikit-learn`.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


@dataclass
class TrainingData:
    feature_dim: int
    classes: List[str]
    X: List[List[float]]
    y: List[int]

    @classmethod
    def load_csv(cls, path: Path) -> "TrainingData":
        rows: List[List[float]] = []
        labels: List[str] = []
        with path.open("r", newline="") as fh:
            reader = csv.reader(fh)
            header = next(reader, None)
            if not header or header[0].lower() != "label":
                sys.exit("CSV must have header starting with 'label'")
            feat_dim = len(header) - 1
            for row in reader:
                if not row:
                    continue
                if len(row) != feat_dim + 1:
                    sys.exit(f"row has {len(row)} cols, expected {feat_dim + 1}")
                labels.append(row[0])
                rows.append([float(x) for x in row[1:]])
        classes = sorted(set(labels))
        y = [classes.index(l) for l in labels]
        return cls(feat_dim, classes, rows, y)


def _split(data: TrainingData, calib_frac: float = 0.2) -> Tuple[TrainingData, TrainingData]:
    # Deterministic split — keep last `calib_frac` of each class for
    # calibration. Simpler and reproducible compared to random shuffling.
    train_X: List[List[float]] = []
    train_y: List[int] = []
    cal_X: List[List[float]] = []
    cal_y: List[int] = []
    per_class: Dict[int, List[int]] = {}
    for idx, lbl in enumerate(data.y):
        per_class.setdefault(lbl, []).append(idx)
    for lbl, idxs in per_class.items():
        n_cal = max(1, int(len(idxs) * calib_frac))
        for i, idx in enumerate(idxs):
            target_X, target_y = (cal_X, cal_y) if i >= len(idxs) - n_cal else (train_X, train_y)
            target_X.append(data.X[idx])
            target_y.append(lbl)
    return (
        TrainingData(data.feature_dim, data.classes, train_X, train_y),
        TrainingData(data.feature_dim, data.classes, cal_X, cal_y),
    )


def _fit_logreg(data: TrainingData) -> Tuple[List[List[float]], List[float]]:
    try:
        from sklearn.linear_model import LogisticRegression  # type: ignore
    except ImportError:
        sys.exit("scikit-learn is required: pip install scikit-learn")

    clf = LogisticRegression(
        penalty="l2",
        C=1.0,
        solver="lbfgs",
        max_iter=2000,
        multi_class="multinomial",
        n_jobs=1,
    )
    clf.fit(data.X, data.y)
    # `coef_` is (K, D); for binary K=1, expand to 2 rows so the runtime
    # always sees one row per class.
    coef = clf.coef_
    intercept = clf.intercept_
    if coef.shape[0] == 1 and len(data.classes) == 2:
        coef = [[-c for c in coef[0]], list(coef[0])]
        intercept = [-intercept[0], intercept[0]]
    return [[float(x) for x in row] for row in coef], [float(b) for b in intercept]


def _fit_platt(
    data: TrainingData,
    weights: List[List[float]],
    bias: List[float],
) -> List[Dict[str, float]]:
    # Per-class Platt scaling. We want p(y=k | s) = sigmoid(A_k s + B_k)
    # where s is the model's raw decision-value for class k. Fit a 1-D
    # logistic regression per class on the held-out calibration set.
    try:
        from sklearn.linear_model import LogisticRegression  # type: ignore
    except ImportError:
        sys.exit("scikit-learn is required: pip install scikit-learn")

    K = len(data.classes)
    platt: List[Dict[str, float]] = []
    for k in range(K):
        raw = [sum(w * v for w, v in zip(weights[k], xrow)) + bias[k] for xrow in data.X]
        y_bin = [1 if y == k else 0 for y in data.y]
        # Edge case: monoclass calibration split — skip Platt for that class.
        if sum(y_bin) == 0 or sum(y_bin) == len(y_bin):
            platt.append({"a": 1.0, "b": 0.0})
            continue
        lr = LogisticRegression(C=1e6, solver="lbfgs", max_iter=1000)
        lr.fit([[s] for s in raw], y_bin)
        platt.append({"a": float(lr.coef_[0][0]), "b": float(lr.intercept_[0])})
    return platt


def _emit_synthetic(data: TrainingData) -> Tuple[List[List[float]], List[float], List[Dict[str, float]]]:
    """Tiny deterministic fallback used by CI / unit tests when
    scikit-learn isn't installed. Produces an identity-ish model:
    each feature votes for a single class round-robin. Not meant to
    classify well — just to produce a well-formed model.json so the
    runtime loader has something to chew on."""
    K = len(data.classes)
    D = data.feature_dim
    weights = [[0.0] * D for _ in range(K)]
    bias = [0.0] * K
    for k in range(K):
        for i in range(D):
            if i % K == k:
                weights[k][i] = 1.0
    platt = [{"a": 1.0, "b": 0.0} for _ in range(K)]
    return weights, bias, platt


def train(args: argparse.Namespace) -> None:
    data = TrainingData.load_csv(Path(args.features))
    if args.synthetic:
        weights, bias, platt = _emit_synthetic(data)
    else:
        train_split, cal_split = _split(data, calib_frac=0.2)
        weights, bias = _fit_logreg(train_split)
        platt = _fit_platt(cal_split, weights, bias) if args.calibrate else None  # type: ignore[assignment]

    model = {
        "version": 1,
        "feature_dim": data.feature_dim,
        "classes": data.classes,
        "weights": weights,
        "bias": bias,
    }
    if platt is not None:
        model["platt"] = platt

    Path(args.output).write_text(json.dumps(model, indent=2))
    print(f"wrote {args.output}: K={len(data.classes)} D={data.feature_dim}")


def main(argv: Sequence[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Train AntiStealer family classifier.")
    p.add_argument("--features", required=True, help="CSV with header 'label,f0,f1,...'")
    p.add_argument("--output", required=True, help="Path to write model.json")
    p.add_argument("--calibrate", action="store_true", help="Fit Platt scaling")
    p.add_argument(
        "--synthetic",
        action="store_true",
        help="Emit a deterministic identity model (no sklearn required)",
    )
    args = p.parse_args(argv)
    train(args)


if __name__ == "__main__":
    main()
