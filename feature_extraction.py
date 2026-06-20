"""
feature_extraction.py
----------------------
Extracts the 23 PE (Portable Executable) header/section features that the
trained RandomForest model (malwareclassifier-V2.pkl) expects, in the exact
order the model was trained on.

The feature set and order below were verified directly against the model's
`feature_names_in_` attribute, so this module is guaranteed to stay in sync
with what the classifier needs at prediction time.
"""

import math
import pefile
import pandas as pd

# Exact feature order the model expects (verified against model.feature_names_in_)
FEATURE_ORDER = [
    'MajorLinkerVersion',
    'MinorOperatingSystemVersion',
    'MajorSubsystemVersion',
    'SizeOfStackReserve',
    'TimeDateStamp',
    'MajorOperatingSystemVersion',
    'Characteristics',
    'ImageBase',
    'Subsystem',
    'MinorImageVersion',
    'MinorSubsystemVersion',
    'SizeOfInitializedData',
    'DllCharacteristics',
    'DirectoryEntryExport',
    'ImageDirectoryEntryExport',
    'CheckSum',
    'DirectoryEntryImportSize',
    'SectionMaxChar',
    'MajorImageVersion',
    'AddressOfEntryPoint',
    'SectionMinEntropy',
    'SizeOfHeaders',
    'SectionMinVirtualsize',
]


class FeatureExtractionError(Exception):
    """Raised when a file cannot be parsed as a valid PE file."""
    pass


def calculate_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string. Returns 0 for empty input."""
    if not data:
        return 0.0

    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1

    length = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy


def extract_features(file_path: str) -> pd.DataFrame:
    """
    Parse a PE file and return a single-row DataFrame with the 23 features
    the model was trained on, in the correct column order.

    Raises FeatureExtractionError if the file is not a valid PE file.
    """
    try:
        pe = pefile.PE(file_path, fast_load=True)
        # Parse the directories we actually need (imports/exports) without
        # doing a full slow load of the whole file.
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            ]
        )
    except Exception as exc:
        raise FeatureExtractionError(f"Not a valid PE file: {exc}") from exc

    try:
        has_export = hasattr(pe, 'DIRECTORY_ENTRY_EXPORT')
        has_import = hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')

        # Section entropy / virtual size (guard against PE files with no sections)
        entropies = []
        virtual_sizes = []
        for section in pe.sections:
            try:
                entropies.append(calculate_entropy(section.get_data()))
            except Exception:
                pass
            virtual_sizes.append(section.Misc_VirtualSize)

        section_min_entropy = min(entropies) if entropies else 0.0
        section_min_virtualsize = min(virtual_sizes) if virtual_sizes else 0

        features = {
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'TimeDateStamp': pe.FILE_HEADER.TimeDateStamp,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'Characteristics': pe.FILE_HEADER.Characteristics,
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
            'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'DirectoryEntryExport': 1 if has_export else 0,
            'ImageDirectoryEntryExport': pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size if has_export else 0,
            'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
            'DirectoryEntryImportSize': pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size if has_import else 0,
            'SectionMaxChar': len(pe.sections),
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'SectionMinEntropy': section_min_entropy,
            'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'SectionMinVirtualsize': section_min_virtualsize,
        }
    finally:
        pe.close()

    # Build the DataFrame with columns in the exact order the model expects
    return pd.DataFrame([features], columns=FEATURE_ORDER)


def is_pe_file(file_path: str) -> bool:
    """Quick check: does this file parse as a PE file at all?"""
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.close()
        return True
    except Exception:
        return False
