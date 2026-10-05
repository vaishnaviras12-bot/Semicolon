"""
CBOM Generation & CycloneDX Export Service
==========================================
Wraps ECDAT's CBOM pipeline and CycloneDX 1.6 exporter to produce standardized
Cryptographic Bill of Materials (CBOM) documents and CycloneDX JSON/XML payloads.
"""

import os
import sys
from typing import Any, Dict, List

# Ensure ECDAT-main/cbom is on sys.path
_CBOM_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../ECDAT-main/cbom"))
if _CBOM_DIR not in sys.path:
    sys.path.insert(0, _CBOM_DIR)

from cbom_generator import generate_cbom as _generate_cbom
from cyclonedx_export import cbom_to_cyclonedx as _cbom_to_cyclonedx

class CBOMService:
    def build_cbom(self, raw_artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Runs deduplication, classification, pattern analysis, and recommendation attachment."""
        return _generate_cbom(raw_artifacts)

    def export_cyclonedx(self, cbom_data: Dict[str, Any]) -> Dict[str, Any]:
        """Exports a CBOM structure to CycloneDX 1.6 JSON format."""
        return _cbom_to_cyclonedx(cbom_data)
