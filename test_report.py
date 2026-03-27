"""
test_report.py — End-to-end integration tests for Graham's report aggregator.

Tests cover:
  - Happy path: binary in → report out (JSON + HTML)
  - SHA-256 reconciliation between OSINT and VT
  - Verdict derivation logic across all tiers
  - Overall verdict takes the most severe signal
  - Graceful handling of missing/null LLM data (stub mode)
  - CLI invocation
  - Output file structure validation

Run with:
    python -m pytest test_report.py -v
"""

import json
import pytest
from pathlib import Path
from report import build_report, save_report, _derive_vt_verdict, _overall_verdict


# ---------------------------------------------------------------------------
# Shared fixtures — mirrors the real output shapes from Matt, Mohith, Courtney
# ---------------------------------------------------------------------------

OSINT_STUB = {
    "hashes": {
        "md5":    "d41d8cd98f00b204e9800998ecf8427e",
        "sha1":   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    "file_size": 48200,
    "arch": {
        "machine":    "x86_64",
        "bits":       64,
        "endianness": "little",
        "elf_type":   "ET_EXEC",
    },
    "imports": {
        "count": 12,
        "names": ["socket", "connect", "execve", "fork"],
    },
    "symbols": {"count": 5},
    "sections": [{"name": ".text"}, {"name": ".data"}],
    "strings": ["/bin/sh", "wget", "http://evil.example.com"],
    "security": {"nx": 1, "pie": 0, "canary": 0, "stripped": 1},
    "entropy": {"whole_binary": 6.4, "text": 5.9},
    "static": {},
    "iocs": {
        "verdict":  "HIGH",
        "severity": 0.65,
        "counts": {"ipv4": 1, "url": 1, "shell_cmd": 2},
        "hits": {
            "urls":       ["http://evil.example.com"],
            "shell_cmds": ["wget", "/bin/sh"],
        },
    },
}

VT_STUB = {
    "filename":         "sample.elf",
    "status":           "completed",
    "detection_ratio":  "45/72",
    "malicious_count":  45,
    "suspicious_count": 3,
    "times_submitted":  2,
    "sha256":           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

LLM_STUB = {
    "risk_score":   0.87,
    "threat_class": "backdoor",
    "iocs": ["http://evil.example.com", "execve(/bin/sh)"],
    "reasoning": "Binary exhibits reverse-shell behaviour: socket+connect+execve chain with external URL.",
}


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class TestBuildReport:

    def test_returns_expected_top_level_keys(self):
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        assert set(report.keys()) == {"meta", "binary", "virustotal", "llm", "summary"}

    def test_meta_fields_populated(self):
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        m = report["meta"]
        assert m["sha256"] == OSINT_STUB["hashes"]["sha256"]
        assert m["md5"]    == OSINT_STUB["hashes"]["md5"]
        assert m["filename"] == "sample.elf"
        assert m["schema_version"] == "1.0"
        assert "generated_at" in m

    def test_vt_block_correct(self):
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        vt = report["virustotal"]
        assert vt["detection_ratio"]  == "45/72"
        assert vt["malicious_count"]  == 45
        assert vt["suspicious_count"] == 3
        assert vt["times_submitted"]  == 2

    def test_llm_block_correct(self):
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        llm = report["llm"]
        assert llm["risk_score"]   == 0.87
        assert llm["threat_class"] == "backdoor"
        assert "execve(/bin/sh)" in llm["iocs"]

    def test_binary_elf_iocs_preserved(self):
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        elf_iocs = report["binary"]["elf_iocs"]
        assert elf_iocs["verdict"]  == "HIGH"
        assert elf_iocs["severity"] == 0.65

    def test_summary_overall_verdict_is_critical(self):
        # 45/72 VT + HIGH ELF + 0.87 risk score → CRITICAL
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        assert report["summary"]["overall_verdict"] == "CRITICAL"

    def test_summary_sha256_matches(self):
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        assert report["summary"]["sha256"] == OSINT_STUB["hashes"]["sha256"]


# ---------------------------------------------------------------------------
# SHA-256 reconciliation
# ---------------------------------------------------------------------------

class TestSHA256Reconciliation:

    def test_mismatch_raises_value_error(self):
        vt_bad = {**VT_STUB, "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
        with pytest.raises(ValueError, match="SHA-256 mismatch"):
            build_report(OSINT_STUB, vt_bad, LLM_STUB)

    def test_empty_vt_sha256_falls_back_to_osint(self):
        vt_no_hash = {**VT_STUB, "sha256": ""}
        report = build_report(OSINT_STUB, vt_no_hash, LLM_STUB)
        assert report["meta"]["sha256"] == OSINT_STUB["hashes"]["sha256"]

    def test_empty_osint_sha256_falls_back_to_vt(self):
        osint_no_hash = {
            **OSINT_STUB,
            "hashes": {**OSINT_STUB["hashes"], "sha256": ""},
        }
        report = build_report(osint_no_hash, VT_STUB, LLM_STUB)
        assert report["meta"]["sha256"] == VT_STUB["sha256"]

    def test_case_insensitive_match_passes(self):
        vt_upper = {**VT_STUB, "sha256": VT_STUB["sha256"].upper()}
        report = build_report(OSINT_STUB, vt_upper, LLM_STUB)
        assert report is not None


# ---------------------------------------------------------------------------
# Verdict derivation
# ---------------------------------------------------------------------------

class TestVTVerdict:
    @pytest.mark.parametrize("malicious,total,expected", [
        (0,  72, "CLEAN"),
        (1,  72, "LOW"),        # ~1.4%
        (10, 72, "MEDIUM"),     # ~13.9%
        (25, 72, "HIGH"),       # ~34.7%
        (50, 72, "CRITICAL"),   # ~69.4%
        (0,   0, "UNKNOWN"),
    ])
    def test_vt_verdict_tiers(self, malicious, total, expected):
        assert _derive_vt_verdict(malicious, total) == expected


class TestOverallVerdict:

    def test_takes_most_severe_signal(self):
        # VT=LOW, ELF=MEDIUM, LLM=CRITICAL → CRITICAL
        result = _overall_verdict(5, 72, "MEDIUM", 0.85)
        assert result == "CRITICAL"

    def test_elf_critical_wins_over_clean_vt(self):
        result = _overall_verdict(0, 72, "CRITICAL", 0.05)
        assert result == "CRITICAL"

    def test_all_clean_returns_clean(self):
        result = _overall_verdict(0, 72, "CLEAN", 0.02)
        assert result == "CLEAN"

    def test_none_risk_score_treated_as_unknown(self):
        # UNKNOWN (-1 rank) should not override a real verdict
        result = _overall_verdict(0, 72, "LOW", None)
        assert result == "LOW"


# ---------------------------------------------------------------------------
# Stub / missing Courtney data
# ---------------------------------------------------------------------------

class TestStubLLMData:

    EMPTY_LLM = {"risk_score": None, "threat_class": None, "iocs": [], "reasoning": ""}

    def test_build_succeeds_without_llm(self):
        report = build_report(OSINT_STUB, VT_STUB, self.EMPTY_LLM)
        assert report["llm"]["risk_score"] is None
        assert report["llm"]["iocs"] == []

    def test_overall_verdict_still_works_without_llm(self):
        report = build_report(OSINT_STUB, VT_STUB, self.EMPTY_LLM)
        # Should still produce a verdict from VT + ELF signals
        assert report["summary"]["overall_verdict"] in (
            "CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"
        )


# ---------------------------------------------------------------------------
# Output: JSON save
# ---------------------------------------------------------------------------

class TestSaveJSON:

    def test_json_output_is_valid(self, tmp_path):
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        out = tmp_path / "report.json"
        save_report(report, str(out))
        assert out.exists()
        loaded = json.loads(out.read_text())
        assert loaded["summary"]["overall_verdict"] == "CRITICAL"

    def test_json_contains_all_top_level_keys(self, tmp_path):
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        out = tmp_path / "report.json"
        save_report(report, str(out))
        loaded = json.loads(out.read_text())
        assert set(loaded.keys()) == {"meta", "binary", "virustotal", "llm", "summary"}


# ---------------------------------------------------------------------------
# Output: HTML save
# ---------------------------------------------------------------------------

class TestSaveHTML:

    def test_html_output_created(self, tmp_path):
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        out = tmp_path / "report.html"
        save_report(report, str(out))
        assert out.exists()
        html = out.read_text()
        assert "<!DOCTYPE html>" in html

    def test_html_contains_verdict(self, tmp_path):
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        out = tmp_path / "report.html"
        save_report(report, str(out))
        html = out.read_text()
        assert "CRITICAL" in html

    def test_html_contains_sha256(self, tmp_path):
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        out = tmp_path / "report.html"
        save_report(report, str(out))
        assert OSINT_STUB["hashes"]["sha256"] in out.read_text()

    def test_html_contains_detection_ratio(self, tmp_path):
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        out = tmp_path / "report.html"
        save_report(report, str(out))
        assert "45/72" in out.read_text()


# ---------------------------------------------------------------------------
# End-to-end: binary in → report out (file-based, mirrors CLI flow)
# ---------------------------------------------------------------------------

class TestEndToEnd:

    def test_full_pipeline_json(self, tmp_path):
        """Simulate the full pipeline: write input JSONs, build report, verify output."""
        osint_file = tmp_path / "osint_output.json"
        vt_file    = tmp_path / "vt_output.json"
        llm_file   = tmp_path / "llm_output.json"
        out_file   = tmp_path / "final_report.json"

        osint_file.write_text(json.dumps(OSINT_STUB))
        vt_file.write_text(json.dumps(VT_STUB))
        llm_file.write_text(json.dumps(LLM_STUB))

        # Mirrors what the CLI does
        osint_data = json.loads(osint_file.read_text())
        vt_data    = json.loads(vt_file.read_text())
        llm_data   = json.loads(llm_file.read_text())

        report = build_report(osint_data, vt_data, llm_data)
        save_report(report, str(out_file))

        result = json.loads(out_file.read_text())
        assert result["summary"]["overall_verdict"] == "CRITICAL"
        assert result["summary"]["detection_ratio"] == "45/72"
        assert result["summary"]["threat_class"] == "backdoor"
        assert result["meta"]["sha256"] == OSINT_STUB["hashes"]["sha256"]

    def test_full_pipeline_html(self, tmp_path):
        report = build_report(OSINT_STUB, VT_STUB, LLM_STUB)
        out_file = tmp_path / "final_report.html"
        save_report(report, str(out_file))
        html = out_file.read_text()
        assert "backdoor" in html
        assert "45/72" in html
        assert "ELF Binary Analysis Report" in html

