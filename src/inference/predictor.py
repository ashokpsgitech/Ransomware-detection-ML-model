"""Prediction engine implementation and CLI."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from src.extractor.pe_extractor import PEFeatureExtractor

logger = logging.getLogger(__name__)


class Predictor:
    """Load a trained model and classify extracted PE features."""

    def __init__(self, model_path: Path) -> None:
        """Initialize the predictor with a trained model path."""
        self.model_path = Path(model_path)
        self.bundle = None
        self.model = None
        self.feature_columns = []

    def load_model(self) -> None:
        """Load the trained machine learning model bundle."""
        if self.bundle is not None:
            return

        logger.info("Loading model bundle from %s", self.model_path)
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")

        self.bundle = joblib.load(self.model_path)
        self.model = self.bundle["model"]
        self.feature_columns = self.bundle["feature_columns"]
        logger.info("Model loaded successfully. Features: %d", len(self.feature_columns))

    def _align_features(self, features: dict[str, Any]) -> pd.DataFrame:
        """Align input features with the expected training columns."""
        df = pd.DataFrame([features])

        # Add any missing columns as None/NaN
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = None

        # Select and order columns exactly as they were during training
        return df[self.feature_columns]

    def predict(self, features: dict[str, Any]) -> int:
        """Predict a class label from extracted PE features (1 = Ransomware, 0 = Non-ransomware)."""
        self.load_model()
        df_aligned = self._align_features(features)
        prediction = self.model.predict(df_aligned)[0]
        return int(prediction)

    def predict_proba(self, features: dict[str, Any]) -> float:
        """Predict the ransomware probability for extracted PE features."""
        self.load_model()
        df_aligned = self._align_features(features)

        if not hasattr(self.model, "predict_proba"):
            raise AttributeError("Loaded model does not support predict_proba")

        probabilities = self.model.predict_proba(df_aligned)[0]
        # Return probability of the positive class (Ransomware, class 1)
        return float(probabilities[1])


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for single-file prediction."""
    parser = argparse.ArgumentParser(description="Predict if an executable is ransomware.")
    parser.add_argument("--file", type=Path, required=True, help="Path to the executable to analyze.")
    parser.add_argument(
        "--model",
        type=Path,
        default=Path("models/ransomware_detector_custom.pkl"),
        help="Path to the trained model bundle.",
    )
    return parser


def main() -> None:
    """Run prediction from the command line."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    args = build_arg_parser().parse_args()

    if not args.file.exists():
        logger.error("File not found: %s", args.file)
        sys.exit(1)

    extractor = PEFeatureExtractor()
    if not extractor.validate_file(args.file):
        logger.error("File is not a valid Windows Portable Executable (PE): %s", args.file)
        sys.exit(1)

    try:
        features = extractor.extract(args.file)
        predictor = Predictor(args.model)
        label = predictor.predict(features)
        prob = predictor.predict_proba(features)

        print("\n" + "=" * 50)
        print(f"File:        {args.file.name}")
        print(f"Prediction:  {'RANSOMWARE' if label == 1 else 'Non-ransomware'}")
        print(f"Probability: {prob * 100:.2f}%")
        print("=" * 50 + "\n")
    except Exception as e:
        logger.exception("Prediction failed: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
