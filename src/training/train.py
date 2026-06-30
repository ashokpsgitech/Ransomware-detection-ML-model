"""Model training pipeline."""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from src.data.preprocess import CATEGORICAL_COLUMNS, Preprocessor
from src.evaluation.evaluate import Evaluator


logger = logging.getLogger(__name__)

DEFAULT_RANDOM_STATE = 42


class Trainer:
    """Train and persist ransomware detection models."""

    def __init__(
        self,
        model_output_path: Path,
        random_state: int = DEFAULT_RANDOM_STATE,
        n_estimators: int = 300,
    ) -> None:
        """Initialize the trainer with a model output path."""
        self.model_output_path = model_output_path
        self.random_state = random_state
        self.n_estimators = n_estimators

    def build_model(self, features: pd.DataFrame | None = None) -> Pipeline:
        """Create the configured machine learning model."""
        logger.info("Building Random Forest training pipeline.")
        categorical_features = self._get_categorical_features(features)
        numeric_features = self._get_numeric_features(features, categorical_features)

        preprocessor = ColumnTransformer(
            transformers=[
                (
                    "numeric",
                    SimpleImputer(strategy="median"),
                    numeric_features,
                ),
                (
                    "categorical",
                    Pipeline(
                        steps=[
                            ("imputer", SimpleImputer(strategy="most_frequent")),
                            ("encoder", _build_one_hot_encoder()),
                        ]
                    ),
                    categorical_features,
                ),
            ],
            remainder="drop",
        )

        classifier = RandomForestClassifier(
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            class_weight="balanced",
            n_jobs=-1,
        )

        return Pipeline(
            steps=[
                ("preprocessor", preprocessor),
                ("classifier", classifier),
            ]
        )

    def train(self, features: pd.DataFrame, target: pd.Series) -> Pipeline:
        """Train a model using feature data and target labels."""
        logger.info("Training model on %s rows and %s features.", *features.shape)
        model = self.build_model(features)
        model.fit(features, target)
        return model

    def save_model(self, model: Any) -> None:
        """Persist a trained model to disk."""
        self.model_output_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, self.model_output_path)
        logger.info("Saved model to %s.", self.model_output_path)

    def run(
        self,
        features: pd.DataFrame,
        target: pd.Series,
        test_size: float = 0.2,
    ) -> dict[str, Any]:
        """Train, evaluate, and persist a model."""
        train_features, test_features, train_target, test_target = train_test_split(
            features,
            target,
            test_size=test_size,
            random_state=self.random_state,
            stratify=target,
        )
        start_time = time.perf_counter()
        model = self.train(train_features, train_target)
        training_time = time.perf_counter() - start_time
        metrics = Evaluator().evaluate(model, test_features, test_target, training_time=training_time)

        bundle = {
            "model": model,
            "metrics": metrics,
            "feature_columns": list(features.columns),
            "categorical_columns": self._get_categorical_features(features),
            "numeric_columns": self._get_numeric_features(
                features,
                self._get_categorical_features(features),
            ),
            "random_state": self.random_state,
            "test_size": test_size,
        }
        self.save_model(bundle)

        return {
            "model": model,
            "metrics": metrics,
            "train_rows": int(train_features.shape[0]),
            "test_rows": int(test_features.shape[0]),
        }

    def _get_categorical_features(self, features: pd.DataFrame | None) -> list[str]:
        """Return categorical columns available in the feature matrix."""
        if features is None:
            return list(CATEGORICAL_COLUMNS)

        configured = [column for column in CATEGORICAL_COLUMNS if column in features.columns]
        object_columns = list(features.select_dtypes(include="object").columns)
        return list(dict.fromkeys([*configured, *object_columns]))

    def _get_numeric_features(
        self,
        features: pd.DataFrame | None,
        categorical_features: list[str],
    ) -> list[str]:
        """Return numeric columns available in the feature matrix."""
        if features is None:
            return []

        categorical_set = set(categorical_features)
        return [column for column in features.columns if column not in categorical_set]


def _build_one_hot_encoder() -> OneHotEncoder:
    """Create a version-compatible one-hot encoder."""
    try:
        return OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    except TypeError:
        return OneHotEncoder(handle_unknown="ignore", sparse=False)


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for model training."""
    parser = argparse.ArgumentParser(description="Train a ransomware detection model.")
    parser.add_argument(
        "--dataset",
        type=Path,
        action="append",
        default=None,
        help="Path to an input dataset. Pass more than once to combine datasets.",
    )
    parser.add_argument(
        "--model-output",
        type=Path,
        default=Path("models/ransomware_detector.pkl"),
        help="Path where the trained model bundle should be saved.",
    )
    parser.add_argument(
        "--metrics-output",
        type=Path,
        default=Path("reports/training_metrics.json"),
        help="Path where evaluation metrics should be saved.",
    )
    parser.add_argument(
        "--profile-output",
        type=Path,
        default=Path("reports/dataset_profile.json"),
        help="Path where the dataset profile should be saved.",
    )
    parser.add_argument("--test-size", type=float, default=0.2, help="Test split fraction.")
    parser.add_argument("--random-state", type=int, default=DEFAULT_RANDOM_STATE)
    parser.add_argument("--n-estimators", type=int, default=300)
    return parser


def main() -> None:
    """Run model training from the command line."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    args = build_arg_parser().parse_args()
    dataset_paths = _normalize_dataset_paths(args.dataset)
    preprocessing_result = _load_training_data(dataset_paths, args.profile_output)
    trainer = Trainer(
        model_output_path=args.model_output,
        random_state=args.random_state,
        n_estimators=args.n_estimators,
    )
    result = trainer.run(
        preprocessing_result["features"],
        preprocessing_result["target"],
        test_size=args.test_size,
    )
    evaluator = Evaluator()
    evaluator.save_metrics(result["metrics"], args.metrics_output)
    logger.info("Train rows: %s. Test rows: %s.", result["train_rows"], result["test_rows"])
    logger.info("\n%s", evaluator.generate_report(result["metrics"]))


def _normalize_dataset_paths(dataset_arg: list[Path] | None) -> list[Path]:
    """Normalize argparse dataset values into a list of paths."""
    if dataset_arg is None:
        return [Path("datasets/Final_Dataset_without_duplicate.csv")]
    return dataset_arg


def _load_training_data(dataset_paths: list[Path], profile_output: Path) -> dict[str, Any]:
    """Load and combine one or more datasets for model training."""
    if len(dataset_paths) == 1:
        return Preprocessor(dataset_paths[0], profile_output).run()

    cleaned_frames = []
    profiles = []
    for dataset_path in dataset_paths:
        preprocessor = Preprocessor(dataset_path)
        raw_data = preprocessor.load_dataset()
        cleaned_data = preprocessor.clean(raw_data)
        cleaned_frames.append(cleaned_data)
        profiles.append(
            {
                "dataset": str(dataset_path),
                "raw": preprocessor.inspect(raw_data),
                "cleaned": preprocessor.inspect(cleaned_data),
            }
        )

    combined_data = pd.concat(cleaned_frames, ignore_index=True).drop_duplicates().reset_index(drop=True)
    preprocessor = Preprocessor(dataset_paths[0])
    features, target = preprocessor.split_features_target(combined_data)
    profile = {
        "datasets": profiles,
        "cleaned": preprocessor.inspect(combined_data),
        "feature_count": int(features.shape[1]),
        "target_distribution": {
            str(label): int(count) for label, count in target.value_counts().sort_index().items()
        },
    }
    profile_output.parent.mkdir(parents=True, exist_ok=True)
    profile_output.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    return {
        "raw_data": None,
        "cleaned_data": combined_data,
        "features": features,
        "target": target,
        "profile": profile,
    }


if __name__ == "__main__":
    main()
