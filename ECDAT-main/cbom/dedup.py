"""
ECDAT — Part 2: Duplicate Removal
====================================
Merges duplicate detections of the same artifact while preserving all
original metadata (every file/line it was found at, not just the first).

"Duplicate" here means: same algorithm + same key_size, appearing multiple
times (across one file or many). We do NOT deduplicate away the
occurrences — we collapse them into one CBOM entry with a list of
locations, because "this weak algorithm appears in 14 places" is exactly
the information a security team needs, and CBOM/SBOM tools deliberately
preserve provenance rather than discarding it.
"""

from collections import defaultdict


def _dedup_key(artifact: dict):
    """
    Two detections are 'the same artifact' if they share algorithm + key_size + resolution_status.
    Library-only artifacts are grouped separately by library.
    """
    status = artifact.get("resolution_status", "resolved")
    alg = artifact.get("algorithm", "Unresolved Cryptographic Artifact")
    if status == "library-only" or alg == "UNSPECIFIED":
        return ("library-only", artifact.get("library") or artifact.get("file_path"))
    return (status, alg, artifact.get("key_size"), artifact.get("mode"), artifact.get("curve"))


def merge_duplicates(classified_artifacts: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for a in classified_artifacts:
        groups[_dedup_key(a)].append(a)

    merged = []
    for key, group in groups.items():
        # keep the highest-confidence detection's metadata as the "primary" record
        primary = max(group, key=lambda a: a.get("confidence", 0.5))

        occurrences = [
            {
                "file_path": a.get("file_path"),
                "line_number": a.get("line_number"),
                "code_snippet": a.get("code_snippet"),
                "detection_method": a.get("detection_method", "static_analysis"),
                "confidence": a.get("confidence", 0.5),
            }
            for a in group
        ]

        # Aggregate detection sources across group
        all_sources = set()
        for a in group:
            if isinstance(a.get("detection_sources"), list):
                all_sources.update(a["detection_sources"])
            elif a.get("detection_method"):
                all_sources.add(a["detection_method"])

        merged_entry = {
            "cbom_entry_id": primary.get("artifact_id") or primary.get("id"),
            "algorithm": primary.get("algorithm", "Unresolved Cryptographic Artifact"),
            "key_size": primary.get("key_size"),
            "mode": primary.get("mode"),
            "curve": primary.get("curve"),
            "family": primary.get("family"),
            "purpose": primary.get("purpose", "unknown"),
            "purpose_confidence": primary.get("purpose_confidence", 0.5),
            "purpose_evidence": primary.get("purpose_evidence", []),
            "resolution_status": primary.get("resolution_status", "resolved"),
            "resolution_reason": primary.get("resolution_reason", ""),
            "cbom_category": primary.get("cbom_category", "Algorithm"),
            "library": primary.get("library"),
            "occurrence_count": len(occurrences),
            "occurrences": occurrences,
            "max_confidence": max(a.get("confidence", 0.5) for a in group),
            "files_affected": sorted(set(o["file_path"] for o in occurrences if o.get("file_path"))),
            "detection_sources": sorted(list(all_sources)),
        }

        if primary.get("certificate_details"):
            merged_entry["certificate_details"] = primary["certificate_details"]

        merged.append(merged_entry)

    # sort so the most-repeated (highest impact) artifacts appear first
    merged.sort(key=lambda e: e["occurrence_count"], reverse=True)
    return merged
