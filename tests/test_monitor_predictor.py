"""Tests for the Predictor and FolderMonitor implementations."""

from __future__ import annotations

import time
from pathlib import Path

import pandas as pd
import pytest
from sklearn.pipeline import Pipeline

from src.inference.predictor import Predictor
from src.monitor.folder_monitor import FolderMonitor


class MockModel:
    """Mock Scikit-learn model for testing."""

    def __init__(self) -> None:
        self.predict_calls = 0
        self.predict_proba_calls = 0

    def predict(self, X: pd.DataFrame) -> list[int]:
        self.predict_calls += 1
        return [1] * len(X)

    def predict_proba(self, X: pd.DataFrame) -> list[list[float]]:
        self.predict_proba_calls += 1
        return [[0.1, 0.9]] * len(X)


def test_predictor_align_features(tmp_path: Path) -> None:
    """Verify that Predictor aligns input features to training schema."""
    model_path = tmp_path / "mock_model.pkl"
    predictor = Predictor(model_path)

    # Set up mock bundle data
    predictor.feature_columns = ["EntryPoint", "SizeOfCode", "ImageBase"]
    predictor.model = MockModel()
    predictor.bundle = {
        "model": predictor.model,
        "feature_columns": predictor.feature_columns,
    }

    # Test features mapping: some present, some missing, extra features
    input_features = {"EntryPoint": 1234, "ImageBase": 4194304, "ExtraCol": "ignored"}
    aligned = predictor._align_features(input_features)

    # Should match length and naming of training features
    assert list(aligned.columns) == ["EntryPoint", "SizeOfCode", "ImageBase"]
    assert aligned.iloc[0]["EntryPoint"] == 1234
    assert aligned.iloc[0]["ImageBase"] == 4194304
    # Missing columns should default to None
    assert aligned.iloc[0]["SizeOfCode"] is None
    # Extra columns should be dropped
    assert "ExtraCol" not in aligned.columns


def test_predictor_predictions(tmp_path: Path) -> None:
    """Verify predict and predict_proba invoke model methods."""
    model_path = tmp_path / "mock_model.pkl"
    predictor = Predictor(model_path)

    mock_model = MockModel()
    predictor.model = mock_model
    predictor.feature_columns = ["EntryPoint"]
    predictor.bundle = {
        "model": mock_model,
        "feature_columns": predictor.feature_columns,
    }

    input_features = {"EntryPoint": 1234}
    assert predictor.predict(input_features) == 1
    assert mock_model.predict_calls == 1

    assert predictor.predict_proba(input_features) == 0.9
    assert mock_model.predict_proba_calls == 1


def test_folder_monitor_lifecycle(tmp_path: Path) -> None:
    """Verify FolderMonitor starts and stops correctly without errors."""
    detected_files = []

    def callback(file_path: Path) -> None:
        detected_files.append(file_path)

    monitor = FolderMonitor(tmp_path, callback)
    
    # Verify directory is created if missing
    watch_path = tmp_path / "subdir"
    assert not watch_path.exists()
    
    monitor_sub = FolderMonitor(watch_path, callback)
    monitor_sub.start()
    assert watch_path.exists()
    
    # Clean shutdown
    monitor_sub.stop()
