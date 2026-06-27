"""Build labeled PE-feature datasets from sample folders."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import pandas as pd

from src.data.preprocess import LABEL_SOURCE_COLUMN, PE_FEATURE_COLUMNS
from src.extractor.pe_extractor import PEFeatureExtractor


logger = logging.getLogger(__name__)

class SampleDatasetBuilder:
    """Extract PE features from a folder and save them as labeled training rows."""

    def __init__(
        self,
        sample_dir: Path,
        label: str,
        output_path: Path,
        recursive: bool = True,
    ) -> None:
        """Initialize the dataset builder."""
        self.sample_dir = sample_dir
        self.label = label
        self.output_path = output_path
        self.recursive = recursive
        self.extractor = PEFeatureExtractor()

    def run(self) -> pd.DataFrame:
        """Extract features from all valid PE samples and write the output CSV."""
        rows: list[dict[str, object]] = []
        for file_path in self._iter_candidate_files():
            if not self.extractor.validate_file(file_path):
                logger.warning("Skipping non-PE file: %s.", file_path)
                continue

            try:
                features = self.extractor.extract(file_path)
            except Exception:
                logger.exception("Failed to extract features from %s.", file_path)
                continue

            features[LABEL_SOURCE_COLUMN] = self.label
            features["source_file"] = str(file_path)
            rows.append(features)
            logger.info("Extracted features from %s.", file_path)

        columns = [*PE_FEATURE_COLUMNS, LABEL_SOURCE_COLUMN, "source_file"]
        dataset = pd.DataFrame(rows, columns=columns)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        dataset.to_csv(self.output_path, index=False)
        logger.info("Wrote %s rows to %s.", len(dataset), self.output_path)
        return dataset

    def _iter_candidate_files(self) -> list[Path]:
        """Return candidate sample files from the configured folder."""
        if not self.sample_dir.exists():
            raise FileNotFoundError(f"Sample directory not found: {self.sample_dir}")

        pattern = "**/*" if self.recursive else "*"
        return [path for path in self.sample_dir.glob(pattern) if path.is_file()]


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for sample dataset extraction."""
    parser = argparse.ArgumentParser(description="Extract PE features from labeled samples.")
    parser.add_argument("--samples", type=Path, required=True, help="Folder containing samples.")
    parser.add_argument(
        "--label",
        choices=("Benign", "Ransomware"),
        required=True,
        help="Label to assign to every extracted sample.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="CSV output path for extracted features.",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Only scan the top-level sample folder.",
    )
    return parser


def main() -> None:
    """Run sample dataset extraction from the command line."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    args = build_arg_parser().parse_args()
    SampleDatasetBuilder(
        sample_dir=args.samples,
        label=args.label,
        output_path=args.output,
        recursive=not args.no_recursive,
    ).run()


if __name__ == "__main__":
    main()
