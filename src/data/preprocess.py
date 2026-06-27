"""Dataset preprocessing pipeline."""

from __future__ import annotations

import argparse
import json
import logging
import re
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


logger = logging.getLogger(__name__)

TARGET_COLUMN = "target"
LABEL_SOURCE_COLUMN = "Category"
LEAKAGE_COLUMNS = ("md5", "sha1", "Class", "Category", "Family")
NON_EXTRACTABLE_COLUMNS = (
    "registry_read",
    "registry_write",
    "registry_delete",
    "registry_total",
    "network_threats",
    "network_dns",
    "network_http",
    "network_connections",
    "processes_malicious",
    "processes_suspicious",
    "processes_monitored",
    "total_procsses",
    "files_malicious",
    "files_suspicious",
    "files_text",
    "files_unknown",
    "dlls_calls",
    "apis",
)
PE_FEATURE_COLUMNS = (
    "EntryPoint",
    "PEType",
    "MachineType",
    "magic_number",
    "bytes_on_last_page",
    "pages_in_file",
    "relocations",
    "size_of_header",
    "min_extra_paragraphs",
    "max_extra_paragraphs",
    "init_ss_value",
    "init_sp_value",
    "init_ip_value",
    "init_cs_value",
    "over_lay_number",
    "oem_identifier",
    "address_of_ne_header",
    "Magic",
    "SizeOfCode",
    "SizeOfInitializedData",
    "SizeOfUninitializedData",
    "AddressOfEntryPoint",
    "BaseOfCode",
    "BaseOfData",
    "ImageBase",
    "SectionAlignment",
    "FileAlignment",
    "OperatingSystemVersion",
    "ImageVersion",
    "SizeOfImage",
    "SizeOfHeaders",
    "Checksum",
    "Subsystem",
    "DllCharacteristics",
    "SizeofStackReserve",
    "SizeofStackCommit",
    "SizeofHeapCommit",
    "SizeofHeapReserve",
    "LoaderFlags",
    "text_VirtualSize",
    "text_VirtualAddress",
    "text_SizeOfRawData",
    "text_PointerToRawData",
    "text_PointerToRelocations",
    "text_PointerToLineNumbers",
    "text_Characteristics",
    "rdata_VirtualSize",
    "rdata_VirtualAddress",
    "rdata_SizeOfRawData",
    "rdata_PointerToRawData",
    "rdata_PointerToRelocations",
    "rdata_PointerToLineNumbers",
    "rdata_Characteristics",
    "CodeDensity",
    "HeaderRatio",
    "TextRawToVirtualRatio",
    "RdataRawToVirtualRatio",
)
CATEGORICAL_COLUMNS = (
    "PEType",
    "MachineType",
    "magic_number",
    "Magic",
    "Subsystem",
    "DllCharacteristics",
    "text_Characteristics",
    "rdata_Characteristics",
)
HEX_PATTERN = re.compile(r"0x[0-9a-fA-F]+")


class Preprocessor:
    """Prepare raw ransomware datasets for model training."""

    def __init__(self, dataset_path: Path, profile_output_path: Path | None = None) -> None:
        """Initialize the preprocessor with a dataset path."""
        self.dataset_path = dataset_path
        self.profile_output_path = profile_output_path

    def load_dataset(self) -> pd.DataFrame:
        """Load the configured dataset."""
        logger.info("Loading dataset from %s.", self.dataset_path)
        if not self.dataset_path.exists():
            raise FileNotFoundError(f"Dataset not found: {self.dataset_path}")

        suffix = self.dataset_path.suffix.lower()
        if suffix == ".csv":
            return pd.read_csv(self.dataset_path)
        if suffix in {".xlsx", ".xls"}:
            return pd.read_excel(self.dataset_path)

        raise ValueError(f"Unsupported dataset format: {self.dataset_path.suffix}")

    def clean(self, data: pd.DataFrame) -> pd.DataFrame:
        """Clean a raw dataset."""
        logger.info("Cleaning dataset with shape %s.", data.shape)
        cleaned = data.copy()
        cleaned = cleaned.drop_duplicates().reset_index(drop=True)
        cleaned = self._create_target(cleaned)
        cleaned = self._drop_leakage_columns(cleaned)
        cleaned = self._convert_numeric_like_columns(cleaned)
        cleaned = self._add_ratio_features(cleaned)
        cleaned = self._keep_pe_feature_columns(cleaned)
        cleaned = self._drop_constant_features(cleaned)
        return cleaned.drop_duplicates().reset_index(drop=True)

    def split_features_target(self, data: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
        """Split a cleaned dataset into features and target labels."""
        logger.info("Splitting features and target.")
        if TARGET_COLUMN not in data.columns:
            raise ValueError(f"Cleaned dataset must contain '{TARGET_COLUMN}'.")

        features = data.drop(columns=[TARGET_COLUMN])
        target = data[TARGET_COLUMN].astype(int)
        return features, target

    def run(self) -> dict[str, Any]:
        """Run the complete preprocessing pipeline."""
        raw_data = self.load_dataset()
        profile_before = self.inspect(raw_data)
        cleaned_data = self.clean(raw_data)
        features, target = self.split_features_target(cleaned_data)

        profile = {
            "raw": profile_before,
            "cleaned": self.inspect(cleaned_data),
            "feature_count": int(features.shape[1]),
            "target_distribution": {
                str(label): int(count) for label, count in target.value_counts().sort_index().items()
            },
            "categorical_features": [
                column for column in CATEGORICAL_COLUMNS if column in features.columns
            ],
            "pe_features": [column for column in PE_FEATURE_COLUMNS if column in features.columns],
            "dropped_non_extractable_features": [
                column for column in NON_EXTRACTABLE_COLUMNS if column in raw_data.columns
            ],
            "dropped_non_pe_features": [
                column
                for column in raw_data.columns
                if column not in PE_FEATURE_COLUMNS
                and column not in LEAKAGE_COLUMNS
                and column != LABEL_SOURCE_COLUMN
            ],
        }

        if self.profile_output_path is not None:
            self.profile_output_path.parent.mkdir(parents=True, exist_ok=True)
            self.profile_output_path.write_text(json.dumps(profile, indent=2), encoding="utf-8")
            logger.info("Wrote dataset profile to %s.", self.profile_output_path)

        return {
            "raw_data": raw_data,
            "cleaned_data": cleaned_data,
            "features": features,
            "target": target,
            "profile": profile,
        }

    def inspect(self, data: pd.DataFrame) -> dict[str, Any]:
        """Return a compact profile for a dataset."""
        target_distribution = {}
        if LABEL_SOURCE_COLUMN in data.columns:
            target_distribution = {
                str(label): int(count)
                for label, count in data[LABEL_SOURCE_COLUMN].value_counts(dropna=False).items()
            }
        elif TARGET_COLUMN in data.columns:
            target_distribution = {
                str(label): int(count)
                for label, count in data[TARGET_COLUMN].value_counts(dropna=False).items()
            }

        missing = data.isna().sum()
        object_columns = data.select_dtypes(include="object")
        return {
            "shape": [int(data.shape[0]), int(data.shape[1])],
            "duplicate_rows": int(data.duplicated().sum()),
            "missing_values": {
                str(column): int(count)
                for column, count in missing[missing > 0].sort_values(ascending=False).items()
            },
            "dtypes": {str(dtype): int(count) for dtype, count in data.dtypes.value_counts().items()},
            "target_distribution": target_distribution,
            "object_cardinality": {
                str(column): int(count)
                for column, count in object_columns.nunique(dropna=False)
                .sort_values(ascending=False)
                .items()
            },
        }

    def _create_target(self, data: pd.DataFrame) -> pd.DataFrame:
        """Create the binary ransomware target column."""
        if TARGET_COLUMN in data.columns:
            data[TARGET_COLUMN] = data[TARGET_COLUMN].astype(int)
            return data

        if LABEL_SOURCE_COLUMN not in data.columns:
            raise ValueError(f"Dataset must contain '{LABEL_SOURCE_COLUMN}' to create target labels.")

        data[TARGET_COLUMN] = data[LABEL_SOURCE_COLUMN].eq("Ransomware").astype(int)
        return data

    def _drop_leakage_columns(self, data: pd.DataFrame) -> pd.DataFrame:
        """Drop labels and unique identifiers that would leak the answer."""
        columns_to_drop = [column for column in LEAKAGE_COLUMNS if column in data.columns]
        return data.drop(columns=columns_to_drop)

    def _drop_non_extractable_columns(self, data: pd.DataFrame) -> pd.DataFrame:
        """Drop runtime behavior fields unavailable to a pre-execution PE extractor."""
        columns_to_drop = [column for column in NON_EXTRACTABLE_COLUMNS if column in data.columns]
        if columns_to_drop:
            logger.info("Dropping non-extractable columns: %s.", columns_to_drop)
        return data.drop(columns=columns_to_drop)

    def _keep_pe_feature_columns(self, data: pd.DataFrame) -> pd.DataFrame:
        """Keep only PE-derived features and the target column."""
        allowed_columns = [column for column in PE_FEATURE_COLUMNS if column in data.columns]
        if TARGET_COLUMN in data.columns:
            allowed_columns.append(TARGET_COLUMN)

        dropped_columns = [column for column in data.columns if column not in allowed_columns]
        if dropped_columns:
            logger.info("Dropping non-PE columns: %s.", dropped_columns)

        return data.loc[:, allowed_columns]

    def _convert_numeric_like_columns(self, data: pd.DataFrame) -> pd.DataFrame:
        """Convert PE numeric fields stored as strings into numeric values."""
        converted = data.copy()
        excluded = set(CATEGORICAL_COLUMNS)

        for column in converted.select_dtypes(include="object").columns:
            if column in excluded:
                continue

            parsed = converted[column].map(_parse_numeric_value)
            if parsed.notna().mean() >= 0.95:
                converted[column] = parsed.fillna(0)

        return converted

    def _add_ratio_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """Add simple PE ratio features that can be reproduced by the extractor."""
        engineered = data.copy()
        engineered["CodeDensity"] = _safe_divide(engineered, "SizeOfCode", "SizeOfImage")
        engineered["HeaderRatio"] = _safe_divide(engineered, "SizeOfHeaders", "SizeOfImage")
        engineered["TextRawToVirtualRatio"] = _safe_divide(
            engineered, "text_SizeOfRawData", "text_VirtualSize"
        )
        engineered["RdataRawToVirtualRatio"] = _safe_divide(
            engineered, "rdata_SizeOfRawData", "rdata_VirtualSize"
        )
        return engineered

    def _drop_constant_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """Remove non-target columns that contain only one value."""
        constant_columns = [
            column
            for column in data.columns
            if column != TARGET_COLUMN and data[column].nunique(dropna=False) <= 1
        ]
        if constant_columns:
            logger.info("Dropping constant columns: %s.", constant_columns)
        return data.drop(columns=constant_columns)


def _parse_numeric_value(value: Any) -> float:
    """Parse decimal or hexadecimal values from messy PE fields."""
    if pd.isna(value):
        return np.nan
    if isinstance(value, (int, float, np.integer, np.floating)):
        return float(value)

    text = str(value).strip()
    if not text:
        return np.nan

    hex_match = HEX_PATTERN.search(text)
    if hex_match:
        return float(int(hex_match.group(0), 16))

    try:
        return float(text)
    except ValueError:
        return np.nan


def _safe_divide(data: pd.DataFrame, numerator: str, denominator: str) -> pd.Series:
    """Return numerator divided by denominator with invalid results replaced by zero."""
    if numerator not in data.columns or denominator not in data.columns:
        return pd.Series(0.0, index=data.index)

    result = pd.to_numeric(data[numerator], errors="coerce") / pd.to_numeric(
        data[denominator], errors="coerce"
    ).replace(0, np.nan)
    return result.replace([np.inf, -np.inf], np.nan).fillna(0.0)


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for dataset preprocessing."""
    parser = argparse.ArgumentParser(description="Inspect and preprocess a ransomware dataset.")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("datasets/Final_Dataset_without_duplicate.csv"),
        help="Path to the input dataset.",
    )
    parser.add_argument(
        "--profile-output",
        type=Path,
        default=Path("reports/dataset_profile.json"),
        help="Path where the dataset profile JSON should be written.",
    )
    return parser


def main() -> None:
    """Run preprocessing from the command line."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    args = build_arg_parser().parse_args()
    result = Preprocessor(args.dataset, args.profile_output).run()
    profile = result["profile"]
    logger.info("Raw shape: %s.", profile["raw"]["shape"])
    logger.info("Cleaned shape: %s.", profile["cleaned"]["shape"])
    logger.info("Target distribution: %s.", profile["target_distribution"])


if __name__ == "__main__":
    main()
