"""Application entry point and orchestrator."""

from __future__ import annotations

import argparse
import json
import logging
import time
import urllib.request
from pathlib import Path
from typing import Callable

from src.extractor.pe_extractor import PEFeatureExtractor
from src.inference.predictor import Predictor
from src.monitor.folder_monitor import FolderMonitor
from src.training.train import Trainer

logger = logging.getLogger(__name__)


def make_monitor_callback(predictor: Predictor, notify_url: str) -> Callable[[Path], None]:
    """Create a callback function to handle detected executables."""
    extractor = PEFeatureExtractor()

    def on_executable_detected(file_path: Path) -> None:
        logger.info("Scanning newly detected file: %s", file_path)
        try:
            features = extractor.extract(file_path)
            label = predictor.predict(features)
            prob = predictor.predict_proba(features)

            category = "Ransomware" if label == 1 else "Benign"

            # Prepare a list of key PE features to display
            key_features = {
                "EntryPoint": features.get("EntryPoint"),
                "SizeOfCode": features.get("SizeOfCode"),
                "SizeOfImage": features.get("SizeOfImage"),
                "ImageBase": features.get("ImageBase"),
                "CodeDensity": f"{features.get('CodeDensity', 0.0):.6f}",
                "HeaderRatio": f"{features.get('HeaderRatio', 0.0):.6f}",
                "TextRawToVirtualRatio": f"{features.get('TextRawToVirtualRatio', 0.0):.6f}",
            }

            # Print a detailed scan report
            report = "\n".join([
                "=" * 60,
                f"SCAN REPORT FOR NEW EXECUTABLE: {file_path.name}",
                "-" * 60,
                "Extracted Key PE Features:",
                f"  EntryPoint:             {key_features['EntryPoint']}",
                f"  SizeOfCode:             {key_features['SizeOfCode']} bytes",
                f"  SizeOfImage:            {key_features['SizeOfImage']} bytes",
                f"  ImageBase:              {key_features['ImageBase']}",
                f"  CodeDensity:            {key_features['CodeDensity']}",
                f"  HeaderRatio:            {key_features['HeaderRatio']}",
                f"  TextRawToVirtualRatio:  {key_features['TextRawToVirtualRatio']}",
                "-" * 60,
                "Model Prediction Output:",
                f"  Predicted Category:     {category.upper()}",
                f"  Ransomware Probability: {prob * 100:.2f}%",
                "=" * 60
            ])
            logger.info("\n%s\n", report)

            if label == 1:
                logger.warning("Ransomware threat detected: %s", file_path.name)
                # Send alert to the host notification bridge
                payload = {
                    "title": "⚠️ Ransomware Detected! ⚠️",
                    "message": (
                        f"File '{file_path.name}' is suspected to be ransomware "
                        f"({prob * 100:.1f}% confidence)."
                    ),
                }
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    notify_url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=3.0) as response:
                        res = response.read().decode("utf-8")
                        logger.info("Host notification response: %s", res)
                except Exception as ex:
                    logger.error("Failed to notify host bridge at %s: %s", notify_url, ex)
            else:
                logger.info("File %s classified as benign. No alert triggered.", file_path.name)
        except Exception as e:
            logger.error("Failed to analyze file %s: %s", file_path, e)

    return on_executable_detected


def main() -> None:
    """Orchestrate training, prediction, or monitoring modes."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="Real-Time Pre-Execution Ransomware Detection Orchestrator")
    parser.add_argument(
        "--mode",
        choices=("train", "predict", "monitor"),
        required=True,
        help="Pipeline execution mode.",
    )
    parser.add_argument(
        "--monitor-dir",
        type=Path,
        default=Path("C:/monitored_folder"),
        help="Directory to watch for new files (monitor mode).",
    )
    parser.add_argument(
        "--model-path",
        type=Path,
        default=Path("models/ransomware_detector_custom.pkl"),
        help="Path to the trained model bundle.",
    )
    parser.add_argument(
        "--notify-url",
        default="http://host.docker.internal:5454/notify",
        help="URL of the host notification bridge (monitor mode).",
    )
    parser.add_argument(
        "--file",
        type=Path,
        help="File path to analyze (predict mode).",
    )

    args = parser.parse_args()

    if args.mode == "train":
        logger.info("Starting training pipeline...")
        # Note: training logic is already fully self-contained in train.py,
        # but we can call it from here as well.
        raise NotImplementedError("For training, run: python -m src.training.train")

    elif args.mode == "predict":
        if args.file is None:
            parser.error("--file is required when --mode is predict.")
        logger.info("Starting single-file prediction...")
        extractor = PEFeatureExtractor()
        if not extractor.validate_file(args.file):
            logger.error("Not a valid PE executable file: %s", args.file)
            return

        features = extractor.extract(args.file)
        predictor = Predictor(args.model_path)
        predictor.load_model()
        if predictor.bundle and "metrics" in predictor.bundle:
            from src.evaluation.evaluate import Evaluator
            report = Evaluator().generate_report(predictor.bundle["metrics"])
            logger.info("\nLoaded Model Metrics:\n%s\n", report)

        label = predictor.predict(features)
        prob = predictor.predict_proba(features)
        logger.info("Prediction: %s (Prob: %.2f%%)", "RANSOMWARE" if label == 1 else "Benign", prob * 100)

    elif args.mode == "monitor":
        logger.info("Initializing background directory monitor...")
        if not args.model_path.exists():
            logger.error("Model file not found at %s. Please train the model first.", args.model_path)
            return

        predictor = Predictor(args.model_path)
        predictor.load_model()
        if predictor.bundle and "metrics" in predictor.bundle:
            from src.evaluation.evaluate import Evaluator
            report = Evaluator().generate_report(predictor.bundle["metrics"])
            logger.info("\nTrained Model Metrics:\n%s\n", report)

        callback = make_monitor_callback(predictor, args.notify_url)
        monitor = FolderMonitor(args.monitor_dir, callback)

        try:
            monitor.start()
            logger.info("Monitoring started. Press Ctrl+C to terminate.")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutdown signal received.")
        finally:
            monitor.stop()


if __name__ == "__main__":
    main()
