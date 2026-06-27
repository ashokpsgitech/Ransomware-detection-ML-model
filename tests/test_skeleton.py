"""Skeleton import tests."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.data.preprocess import PE_FEATURE_COLUMNS, Preprocessor
from src.data.sample_dataset_builder import SampleDatasetBuilder
from src.evaluation.evaluate import Evaluator
from src.extractor.pe_extractor import PEFeatureExtractor
from src.inference.predictor import Predictor
from src.monitor.folder_monitor import FolderMonitor
from src.training.train import Trainer


def test_skeleton_imports() -> None:
    """Verify that skeleton classes are importable."""
    assert Preprocessor
    assert Evaluator
    assert PEFeatureExtractor
    assert Predictor
    assert FolderMonitor
    assert Trainer


def test_preprocessor_creates_target_and_drops_leakage() -> None:
    """Verify that preprocessing removes leakage fields and creates a binary target."""
    data = pd.DataFrame(
        {
            "md5": ["a", "b"],
            "sha1": ["c", "d"],
            "EntryPoint": ["0x10", "0x20"],
            "SizeOfCode": ["0x20", "0x40"],
            "SizeOfImage": ["0x100", "0x200"],
            "SizeOfHeaders": ["0x10", "0x20"],
            "registry_read": [5.0, 10.0],
            "apis": [100.0, 200.0],
            "random_note": ["ignore", "ignore"],
            "PEType": ["PE32", "PE32+"],
            "Class": ["Benign", "Malware"],
            "Category": ["Benign", "Ransomware"],
            "Family": ["Benign", "TestFamily"],
        }
    )

    cleaned = Preprocessor(Path("dummy.csv")).clean(data)

    assert "target" in cleaned.columns
    assert cleaned["target"].tolist() == [0, 1]
    assert "md5" not in cleaned.columns
    assert "sha1" not in cleaned.columns
    assert "Category" not in cleaned.columns
    assert "registry_read" not in cleaned.columns
    assert "apis" not in cleaned.columns
    assert "random_note" not in cleaned.columns
    assert cleaned["EntryPoint"].tolist() == [16.0, 32.0]


def test_trainer_builds_pipeline_from_features() -> None:
    """Verify that the trainer builds a scikit-learn pipeline."""
    features = pd.DataFrame(
        {
            "SizeOfCode": [1.0, 2.0],
            "SizeOfImage": [10.0, 20.0],
            "PEType": ["PE32", "PE32+"],
        }
    )

    model = Trainer(Path("models/test.pkl"), n_estimators=1).build_model(features)

    assert "preprocessor" in model.named_steps
    assert "classifier" in model.named_steps


def test_pe_extractor_feature_contract() -> None:
    """Verify that the PE extractor uses the training feature contract."""
    features = PEFeatureExtractor()._empty_feature_dict()

    assert list(features) == list(PE_FEATURE_COLUMNS)
    assert len(features) == 57


def test_sample_dataset_builder_uses_expected_columns(tmp_path: Path) -> None:
    """Verify that sample dataset output keeps the expected schema when empty."""
    output_path = tmp_path / "samples.csv"

    dataset = SampleDatasetBuilder(
        sample_dir=tmp_path,
        label="Ransomware",
        output_path=output_path,
    ).run()

    assert output_path.exists()
    assert list(dataset.columns) == [*PE_FEATURE_COLUMNS, "Category", "source_file"]
