"""Model evaluation helpers."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


logger = logging.getLogger(__name__)


class Evaluator:
    """Evaluate ransomware detection models with standard classification metrics."""

    def evaluate(self, model: Any, features: pd.DataFrame, target: pd.Series) -> dict[str, float]:
        """Evaluate a trained model against labeled data."""
        logger.info("Evaluating model on %s rows.", len(features))
        predictions = model.predict(features)
        probabilities = self._predict_positive_probability(model, features)
        tn, fp, fn, tp = confusion_matrix(target, predictions, labels=[0, 1]).ravel()

        metrics = {
            "accuracy": accuracy_score(target, predictions),
            "precision": precision_score(target, predictions, zero_division=0),
            "recall": recall_score(target, predictions, zero_division=0),
            "f1": f1_score(target, predictions, zero_division=0),
            "roc_auc": roc_auc_score(target, probabilities) if probabilities is not None else 0.0,
            "true_negatives": float(tn),
            "false_positives": float(fp),
            "false_negatives": float(fn),
            "true_positives": float(tp),
        }
        return {name: float(value) for name, value in metrics.items()}

    def generate_report(self, metrics: dict[str, float]) -> str:
        """Generate a text summary from evaluation metrics."""
        logger.info("Generating evaluation report.")
        return "\n".join(
            [
                f"Accuracy:  {metrics['accuracy']:.4f}",
                f"Precision: {metrics['precision']:.4f}",
                f"Recall:    {metrics['recall']:.4f}",
                f"F1 Score:  {metrics['f1']:.4f}",
                f"ROC AUC:   {metrics['roc_auc']:.4f}",
                "Confusion Matrix:",
                f"  TN={metrics['true_negatives']:.0f} FP={metrics['false_positives']:.0f}",
                f"  FN={metrics['false_negatives']:.0f} TP={metrics['true_positives']:.0f}",
            ]
        )

    def save_metrics(self, metrics: dict[str, float], output_path: Path) -> None:
        """Save evaluation metrics as JSON."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        logger.info("Saved metrics to %s.", output_path)

    def _predict_positive_probability(
        self, model: Any, features: pd.DataFrame
    ) -> pd.Series | None:
        """Return positive-class probabilities when the model supports them."""
        if not hasattr(model, "predict_proba"):
            return None

        probabilities = model.predict_proba(features)
        if probabilities.shape[1] < 2:
            return None

        return probabilities[:, 1]
