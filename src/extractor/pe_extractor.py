"""Portable Executable feature extraction."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

import pandas as pd

from src.data.preprocess import PE_FEATURE_COLUMNS

logger = logging.getLogger(__name__)

MACHINE_TYPE_NAMES = {
    0x014C: "Intel 386 or later, and compatibles",
    0x8664: "AMD AMD64",
    0x0200: "Intel Itanium",
}
SUBSYSTEM_NAMES = {
    1: "IMAGE_SUBSYSTEM_NATIVE",
    2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    3: "IMAGE_SUBSYSTEM_WINDOWS_CUI",
    5: "IMAGE_SUBSYSTEM_OS2_CUI",
    7: "IMAGE_SUBSYSTEM_POSIX_CUI",
    9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
    10: "IMAGE_SUBSYSTEM_EFI_APPLICATION",
    11: "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
    12: "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
    13: "IMAGE_SUBSYSTEM_EFI_ROM",
    14: "IMAGE_SUBSYSTEM_XBOX",
    16: "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
}
DLL_CHARACTERISTIC_FLAGS = {
    0x0020: "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
    0x0040: "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
    0x0080: "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
    0x0100: "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
    0x0200: "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
    0x0400: "IMAGE_DLLCHARACTERISTICS_NO_SEH",
    0x0800: "IMAGE_DLLCHARACTERISTICS_NO_BIND",
    0x1000: "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
    0x2000: "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
    0x4000: "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
    0x8000: "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE",
}
SECTION_CHARACTERISTIC_FLAGS = {
    0x00000020: "IMAGE_SCN_CNT_CODE",
    0x00000040: "IMAGE_SCN_CNT_INITIALIZED_DATA",
    0x00000080: "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
    0x02000000: "IMAGE_SCN_MEM_DISCARDABLE",
    0x04000000: "IMAGE_SCN_MEM_NOT_CACHED",
    0x08000000: "IMAGE_SCN_MEM_NOT_PAGED",
    0x10000000: "IMAGE_SCN_MEM_SHARED",
    0x20000000: "IMAGE_SCN_MEM_EXECUTE",
    0x40000000: "IMAGE_SCN_MEM_READ",
    0x80000000: "IMAGE_SCN_MEM_WRITE",
}


class PEFeatureExtractor:
    """Extract static features from Windows Portable Executable files."""

    def __init__(self) -> None:
        """Initialize the PE feature extractor."""
        logger.debug("PEFeatureExtractor initialized.")

    def extract(self, file_path: Path) -> dict[str, Any]:
        """Extract static PE features from a file."""
        logger.info("Extracting PE features from %s.", file_path)
        pefile = _import_pefile()
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"PE file not found: {path}")

        pe = pefile.PE(str(path), fast_load=False)
        try:
            features = self._empty_feature_dict()
            self._extract_dos_header(pe, features)
            self._extract_file_header(pe, features)
            self._extract_optional_header(pe, features)
            self._extract_sections(pe, features)
            self._add_ratio_features(features)
            return {column: features.get(column, 0) for column in PE_FEATURE_COLUMNS}
        finally:
            pe.close()

    def validate_file(self, file_path: Path) -> bool:
        """Validate whether a file can be processed as a PE file."""
        logger.info("Validating PE file %s.", file_path)
        pefile = _import_pefile()
        path = Path(file_path)
        if not path.is_file():
            return False

        try:
            pe = pefile.PE(str(path), fast_load=True)
        except pefile.PEFormatError:
            return False
        finally:
            try:
                pe.close()
            except UnboundLocalError:
                pass

        return True

    def to_dataframe(self, file_path: Path) -> pd.DataFrame:
        """Extract PE features and return a one-row dataframe in training order."""
        features = self.extract(file_path)
        return pd.DataFrame([features], columns=list(PE_FEATURE_COLUMNS))

    def _empty_feature_dict(self) -> dict[str, Any]:
        """Return a zero-filled feature dictionary."""
        return {column: 0 for column in PE_FEATURE_COLUMNS}

    def _extract_dos_header(self, pe: Any, features: dict[str, Any]) -> None:
        """Extract DOS header fields."""
        dos_header = pe.DOS_HEADER
        features["magic_number"] = "MZ" if dos_header.e_magic == 0x5A4D else str(dos_header.e_magic)
        features["bytes_on_last_page"] = dos_header.e_cblp
        features["pages_in_file"] = dos_header.e_cp
        features["relocations"] = dos_header.e_crlc
        features["size_of_header"] = dos_header.e_cparhdr
        features["min_extra_paragraphs"] = dos_header.e_minalloc
        features["max_extra_paragraphs"] = dos_header.e_maxalloc
        features["init_ss_value"] = dos_header.e_ss
        features["init_sp_value"] = dos_header.e_sp
        features["init_ip_value"] = dos_header.e_ip
        features["init_cs_value"] = dos_header.e_cs
        features["over_lay_number"] = dos_header.e_ovno
        features["oem_identifier"] = dos_header.e_oemid
        features["address_of_ne_header"] = dos_header.e_lfanew

    def _extract_file_header(self, pe: Any, features: dict[str, Any]) -> None:
        """Extract COFF file header fields."""
        machine = pe.FILE_HEADER.Machine
        features["MachineType"] = MACHINE_TYPE_NAMES.get(machine, str(machine))

    def _extract_optional_header(self, pe: Any, features: dict[str, Any]) -> None:
        """Extract optional header fields."""
        optional_header = pe.OPTIONAL_HEADER
        features["PEType"] = "PE32+" if optional_header.Magic == 0x20B else "PE32"
        features["Magic"] = features["PEType"]
        features["EntryPoint"] = optional_header.AddressOfEntryPoint
        features["SizeOfCode"] = optional_header.SizeOfCode
        features["SizeOfInitializedData"] = optional_header.SizeOfInitializedData
        features["SizeOfUninitializedData"] = optional_header.SizeOfUninitializedData
        features["AddressOfEntryPoint"] = optional_header.AddressOfEntryPoint
        features["BaseOfCode"] = optional_header.BaseOfCode
        features["BaseOfData"] = getattr(optional_header, "BaseOfData", 0)
        features["ImageBase"] = optional_header.ImageBase
        features["SectionAlignment"] = optional_header.SectionAlignment
        features["FileAlignment"] = optional_header.FileAlignment
        features["OperatingSystemVersion"] = _version_to_float(
            optional_header.MajorOperatingSystemVersion,
            optional_header.MinorOperatingSystemVersion,
        )
        features["ImageVersion"] = _version_to_float(
            optional_header.MajorImageVersion,
            optional_header.MinorImageVersion,
        )
        features["SizeOfImage"] = optional_header.SizeOfImage
        features["SizeOfHeaders"] = optional_header.SizeOfHeaders
        features["Checksum"] = optional_header.CheckSum
        features["Subsystem"] = SUBSYSTEM_NAMES.get(optional_header.Subsystem, str(optional_header.Subsystem))
        features["DllCharacteristics"] = _flags_to_list_string(
            optional_header.DllCharacteristics,
            DLL_CHARACTERISTIC_FLAGS,
        )
        features["SizeofStackReserve"] = optional_header.SizeOfStackReserve
        features["SizeofStackCommit"] = optional_header.SizeOfStackCommit
        features["SizeofHeapCommit"] = optional_header.SizeOfHeapCommit
        features["SizeofHeapReserve"] = optional_header.SizeOfHeapReserve
        features["LoaderFlags"] = optional_header.LoaderFlags

    def _extract_sections(self, pe: Any, features: dict[str, Any]) -> None:
        """Extract `.text` and `.rdata` section fields."""
        sections = {_normalize_section_name(section.Name): section for section in pe.sections}
        self._extract_section_features(sections.get(".text"), "text", features)
        self._extract_section_features(sections.get(".rdata"), "rdata", features)

    def _extract_section_features(
        self,
        section: Any | None,
        prefix: str,
        features: dict[str, Any],
    ) -> None:
        """Extract fields for one PE section."""
        if section is None:
            return

        features[f"{prefix}_VirtualSize"] = section.Misc_VirtualSize
        features[f"{prefix}_VirtualAddress"] = section.VirtualAddress
        features[f"{prefix}_SizeOfRawData"] = section.SizeOfRawData
        features[f"{prefix}_PointerToRawData"] = section.PointerToRawData
        features[f"{prefix}_PointerToRelocations"] = section.PointerToRelocations
        features[f"{prefix}_PointerToLineNumbers"] = section.PointerToLinenumbers
        features[f"{prefix}_Characteristics"] = _flags_to_list_string(
            section.Characteristics,
            SECTION_CHARACTERISTIC_FLAGS,
        )

    def _add_ratio_features(self, features: dict[str, Any]) -> None:
        """Add PE ratio features used during training."""
        features["CodeDensity"] = _safe_divide(features["SizeOfCode"], features["SizeOfImage"])
        features["HeaderRatio"] = _safe_divide(features["SizeOfHeaders"], features["SizeOfImage"])
        features["TextRawToVirtualRatio"] = _safe_divide(
            features["text_SizeOfRawData"],
            features["text_VirtualSize"],
        )
        features["RdataRawToVirtualRatio"] = _safe_divide(
            features["rdata_SizeOfRawData"],
            features["rdata_VirtualSize"],
        )


def _import_pefile() -> Any:
    """Import pefile with a clear dependency error."""
    try:
        import pefile
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            "The 'pefile' package is required. Install dependencies with "
            "'pip install -r requirements.txt'."
        ) from exc

    return pefile


def _normalize_section_name(raw_name: bytes) -> str:
    """Decode and normalize a PE section name."""
    return raw_name.rstrip(b"\x00").decode("utf-8", errors="ignore").strip()


def _flags_to_list_string(value: int, flags: dict[int, str]) -> str:
    """Convert bit flags to the list-string format used by the dataset."""
    names = [name for bit, name in flags.items() if value & bit]
    return str(names)


def _version_to_float(major: int, minor: int) -> float:
    """Convert a major/minor version pair to the dataset's float style."""
    return float(f"{major}.{minor}")


def _safe_divide(numerator: float, denominator: float) -> float:
    """Divide two numeric values and return zero for invalid ratios."""
    if denominator == 0:
        return 0.0
    return float(numerator) / float(denominator)


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for PE feature extraction."""
    parser = argparse.ArgumentParser(description="Extract PE features from an executable.")
    parser.add_argument("file", type=Path, help="Path to the PE file.")
    return parser


def main() -> None:
    """Run feature extraction from the command line."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    args = build_arg_parser().parse_args()
    features = PEFeatureExtractor().extract(args.file)
    for key, value in features.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
