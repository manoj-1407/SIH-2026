"""
H01/H02/H03 Unit Tests — SIH26149 NTRO Forensic Workstation.

Coverage:
  H02: IEEE 2883-2022 cross-reference emission (DeviceCapability + to_dict)
       per media type (§5.2 SATA SSD, §5.3 NVMe, §5.5 USB/SD, N/A for virtual)
  H03: HPA/DCO 4-field tuple (checked + detected/None) + probe_hpa_dco()
       returns honest checked=False on non-POSIX with advisory commands dict
  H01: get_device_purge_plan() method families ATA_SECURE_ERASE /
       NVME_SANITIZE_BLOCK_ERASE / TCG_OPAL_PSID_REVERT / NONE + HTTP
       /api/sanitization/purge_profile endpoint (7 media type × boot × sed combos)
"""
import os
import sys
import pytest

from app.sanitization.device_detector import (
    detect_media_type,
    evaluate_opal_capability,
    probe_hpa_dco,
    DeviceCapability,
    MediaType,
)
from app.sanitization.purge_commands import get_device_purge_plan


# ═══════════════════════════════════════════════════════════════════════════════
# H02: IEEE 2883-2022 cross-reference per media type
# ═══════════════════════════════════════════════════════════════════════════════

IEEE_BY_TYPE = {
    MediaType.VIRTUAL_DISK_IMAGE: "IEEE 2883 does not apply",
    MediaType.ROTATIONAL_HDD: None,
    MediaType.SATA_SSD: "IEEE 2883-2022 §5.2",
    MediaType.NVME_SSD: "IEEE 2883-2022 §5.3",
    MediaType.USB_FLASH: "IEEE 2883-2022 §5.5",
    MediaType.SD_CARD: "IEEE 2883-2022 §5.5",
    MediaType.UNKNOWN: "IEEE 2883 cross-reference not assignable",
}


@pytest.mark.parametrize(
    "path, expected_media, expected_ieee_contains",
    [
        ("evidence.raw", MediaType.VIRTUAL_DISK_IMAGE, "IEEE 2883 does not apply"),
        ("/dev/disk/ata-rotational-hdd0", MediaType.ROTATIONAL_HDD, "__NONE__"),
        ("/dev/disk/by-path-pci-sata-ssd", MediaType.SATA_SSD, "§5.2"),
        ("/dev/nvme0n1", MediaType.NVME_SSD, "§5.3"),
        ("/dev/disk/by-id/usb-SanDisk_Ultra_Fit", MediaType.USB_FLASH, "§5.5"),
        ("/dev/mmcblk0", MediaType.SD_CARD, "§5.5"),
        ("/dev/weird_unclassified_thing", MediaType.UNKNOWN, "cross-reference not assignable"),
    ],
)
def test_ieee_2883_reference_per_media_type(path, expected_media, expected_ieee_contains):
    cap = detect_media_type(path)
    d = cap.to_dict()

    assert cap.media_type == expected_media, (
        f"detected {cap.media_type.value} != expected {expected_media.value}"
    )
    assert "ieee_2883_reference" in d, "to_dict() missing ieee_2883_reference key"

    ref = d["ieee_2883_reference"]
    if expected_ieee_contains == "__NONE__":
        assert ref is None, (
            f"ROTATIONAL_HDD should yield None IEEE 2883 ref (covered by ATA-8 ACS), got: {ref}"
        )
    else:
        assert isinstance(ref, str) and expected_ieee_contains in ref, (
            f"Expected IEEE 2883 ref containing {expected_ieee_contains!r}, got: {ref!r}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# H03: 4 HPA/DCO fields on every DeviceCapability.to_dict()
# ═══════════════════════════════════════════════════════════════════════════════

def _has_4_hpa_dco_fields(d: dict):
    for key in ("hpa_checked", "hpa_detected", "dco_checked", "dco_detected"):
        assert key in d, f"to_dict() missing {key!r}"


def test_to_dict_always_exposes_4_hpa_dco_fields_all_media_types():
    paths = (
        "disk.img",
        "/dev/sata_hdd",
        "/dev/sata_ssd",
        "/dev/nvme0n1",
        "/dev/usb_flash",
        "/dev/mmcblk0",
        "/dev/unknown_device",
    )
    for p in paths:
        d = detect_media_type(p).to_dict()
        _has_4_hpa_dco_fields(d)
        # Non-virtual physical types → honest checked=False since we lack
        # POSIX-root-hdparm on the test host. Virtual keeps False/None defaults.
        if d["media_type"] == "VIRTUAL_DISK_IMAGE":
            assert d["hpa_checked"] is False
            assert d["hpa_detected"] is None
            assert d["dco_checked"] is False
            assert d["dco_detected"] is None
        else:
            # probe_hpa_dco() ran on physical but returned checked=False on Windows
            assert isinstance(d["hpa_checked"], bool)
            assert d["hpa_detected"] is None or isinstance(d["hpa_detected"], bool)
            assert isinstance(d["dco_checked"], bool)
            assert d["dco_detected"] is None or isinstance(d["dco_detected"], bool)


def test_probe_hpa_dco_returns_valid_dict_and_never_raises():
    # probe_hpa_dco must never raise, even for nonsense paths
    for p in ("", "/dev/null", "C:\\", "????", None):
        try:
            res = probe_hpa_dco(p if p is not None else "/dev/sdx")
        except Exception as e:
            pytest.fail(f"probe_hpa_dco({p!r}) raised {type(e).__name__}: {e}")
        for mandatory in ("hpa_checked", "hpa_detected", "dco_checked",
                          "dco_detected", "commands", "probe_environment"):
            assert mandatory in res, (
                f"probe_hpa_dco() output missing key {mandatory!r}"
            )
        assert "hpa_check" in res["commands"]
        assert "dco_check" in res["commands"]
        # On non-POSIX (this test env = Windows): checked=False, advisory gating reason
        if os.name != "posix":
            assert res["hpa_checked"] is False and res["dco_checked"] is False
            assert res["hpa_detected"] is None and res["dco_detected"] is None
            assert "gating_reason" in res
            assert isinstance(res["gating_reason"], str) and len(res["gating_reason"]) > 20


# ═══════════════════════════════════════════════════════════════════════════════
# H01: get_device_purge_plan() method families + invariants
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "device_path, media_hint, expected_family",
    [
        ("/dev/nvme0n1", MediaType.NVME_SSD, "NVME_SANITIZE_BLOCK_ERASE"),
        ("/dev/sata_ssd", MediaType.SATA_SSD, "ATA_SECURE_ERASE"),
        ("/dev/ata_hdd_rotational", MediaType.ROTATIONAL_HDD, "ATA_SECURE_ERASE"),
        ("/dev/usb_thumb", MediaType.USB_FLASH, "NONE"),
        ("/dev/mmcblk_sdcard", MediaType.SD_CARD, "NONE"),
        ("evidence.img", MediaType.VIRTUAL_DISK_IMAGE, "NONE"),
    ],
)
def test_purge_plan_method_family_default(device_path, media_hint, expected_family):
    cap = detect_media_type(device_path)
    assert cap.media_type == media_hint, (
        f"Precondition: expected {media_hint.value}, got {cap.media_type.value}"
    )
    plan = get_device_purge_plan(cap, boot_drive=False, device_path=device_path)
    for mandatory in (
        "nist_level_requested", "nist_reference", "ieee_2883_reference",
        "method_family", "command_template", "alternate_command", "required_env",
        "current_env_satisfied", "gating_reason_if_unsatisfied", "risks",
        "simulated_execution_result_if_run", "boot_drive_flag",
    ):
        assert mandatory in plan, f"purge_plan missing key {mandatory!r}"

    assert plan["method_family"] == expected_family, (
        f"{media_hint.value}: expected family {expected_family}, got {plan['method_family']}"
    )
    assert plan["boot_drive_flag"] is False
    assert isinstance(plan["risks"], list) and len(plan["risks"]) >= 3
    sim = plan["simulated_execution_result_if_run"]
    for k in ("method_applied", "duration_estimate_s", "expected_status"):
        assert k in sim


def test_purge_plan_boot_drive_gates_every_media_to_none():
    """Boot-drive target must fail-closed to method_family=NONE regardless of media."""
    for path in ("/dev/nvme0n1", "/dev/sata_ssd", "/dev/ata_hdd_rot"):
        cap = detect_media_type(path)
        plan = get_device_purge_plan(cap, boot_drive=True, device_path=path)
        assert plan["method_family"] == "NONE", (
            f"Boot drive {path}: method_family MUST be NONE fail-closed, got {plan['method_family']}"
        )
        assert plan["boot_drive_flag"] is True
        assert plan["current_env_satisfied"] is False
        # Risks should include DO-NOT-EXECUTE language
        any_do_not = any("DO NOT" in r.upper() or "BOOT" in r.upper() for r in plan["risks"])
        assert any_do_not, "Boot drive plan must warn DO NOT EXECUTE against boot disk"


def test_purge_plan_usb_flash_recommends_destroy_in_scope():
    cap = detect_media_type("/dev/disk/by-id/usb-SanDisk")
    plan = get_device_purge_plan(cap, boot_drive=False, device_path="/dev/sdb")
    assert plan["method_family"] == "NONE"
    # USB flash plan must explicitly state NIST-unrecommended for PURGE
    assert "DESTROY" in plan["nist_level_requested"].upper() or \
           any("DESTROY" in r.upper() for r in plan["risks"]), (
               "USB_FLASH plan must include DESTROY recommendation"
           )
    assert plan["gating_reason_if_unsatisfied"] is not None  # honest fail-closed reason exists


def test_tcg_opal_sed_promotes_to_psid_revert():
    """Directly set SED flags on a SATA_SSD cap → plan family is TCG_OPAL_PSID_REVERT."""
    cap = detect_media_type("/dev/sata_enterprise_ssd")
    # Manually stamp SED attributes (equivalent to evaluate_opal_capability() returning valid)
    cap.is_sed_opal_capable = True
    cap.opal_ssc_version = "TCG Opal SSC V2.0"
    cap.crypto_erase_recommended = True
    cap.purge_supported = True

    plan = get_device_purge_plan(cap, boot_drive=False, device_path="/dev/sda")
    assert plan["method_family"] == "TCG_OPAL_PSID_REVERT", (
        f"SED-capable media must produce TCG_OPAL_PSID_REVERT plan, got {plan['method_family']}"
    )
    assert "PSID" in plan["command_template"].upper()


# ═══════════════════════════════════════════════════════════════════════════════
# H01 HTTP endpoint /api/sanitization/purge_profile
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def api_client():
    """Create FastAPI TestClient once for all HTTP endpoint tests."""
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def _check(api_client, params, expected_status=200, method_family=None, ieee_ref_contains=None):
    r = api_client.get("/api/sanitization/purge_profile", params=params)
    assert r.status_code == expected_status, (
        f"HTTP {r.status_code} for params {params}: {r.text[:400]}"
    )
    if expected_status != 200:
        return None
    body = r.json()
    assert "media_type" in body and "device_capability_summary" in body and "purge_plan" in body
    assert body["capability_matrix"]["execution_policy"] == "PREVIEW_ONLY_NO_DESTRUCTIVE_DEVICE_COMMANDS"
    summary = body["device_capability_summary"]
    for key in ("ieee_2883_reference", "hpa_checked", "hpa_detected",
                "dco_checked", "dco_detected"):
        assert key in summary, f"summary missing key {key!r}"
    plan = body["purge_plan"]
    for key in ("method_family", "command_template", "risks", "current_env_satisfied"):
        assert key in plan, f"purge_plan missing key {key!r}"
    if method_family:
        assert plan["method_family"] == method_family, (
            f"expected method_family={method_family}, got {plan['method_family']}"
        )
    if ieee_ref_contains:
        assert ieee_ref_contains in (summary["ieee_2883_reference"] or "")
    return body


def test_api_invalid_media_type_returns_4xx(api_client):
    _check(api_client, {"media_type": "FLOPPY_DISK"}, expected_status=422)


@pytest.mark.parametrize(
    "media, expected_family, ieee",
    [
        ("NVME_SSD", "NVME_SANITIZE_BLOCK_ERASE", "§5.3"),
        ("SATA_SSD", "ATA_SECURE_ERASE", "§5.2"),
        ("ROTATIONAL_HDD", "ATA_SECURE_ERASE", None),
        ("USB_FLASH", "NONE", "§5.5"),
        ("SD_CARD", "NONE", "§5.5"),
        ("VIRTUAL_DISK_IMAGE", "NONE", "IEEE 2883 does not apply"),
        ("UNKNOWN", "NONE", "cross-reference not assignable"),
    ],
)
def test_api_all_media_types(api_client, media, expected_family, ieee):
    _check(api_client,
           {"media_type": media, "boot": "false"},
           method_family=expected_family,
           ieee_ref_contains=ieee)


def test_api_sed_opal_flag_promotes_plan(api_client):
    body = _check(api_client,
                  {"media_type": "SATA_SSD", "boot": "false", "sed_opal": "true"},
                  method_family="TCG_OPAL_PSID_REVERT")
    summary = body["device_capability_summary"]
    # evaluate_opal_capability ran: capability engine must have promoted IEEE ref
    assert summary["ieee_2883_reference"] is not None


def test_api_boot_flag_true_demotes_to_none(api_client):
    for media in ("NVME_SSD", "SATA_SSD", "ROTATIONAL_HDD"):
        body = _check(api_client, {"media_type": media, "boot": "true"},
                      method_family="NONE")
        assert body["purge_plan"]["boot_drive_flag"] is True
        assert body["purge_plan"]["current_env_satisfied"] is False


def test_api_hpa_dco_summary_fields_populated(api_client):
    """Every HTTP response must expose the honest H03 HPA/DCO 4-tuple in summary."""
    body = _check(api_client, {"media_type": "SATA_SSD", "boot": "false"})
    s = body["device_capability_summary"]
    assert isinstance(s["hpa_checked"], bool)
    assert isinstance(s["dco_checked"], bool)
    assert s["hpa_detected"] is None or isinstance(s["hpa_detected"], bool)
    assert s["dco_detected"] is None or isinstance(s["dco_detected"], bool)


def test_system_capabilities_reports_hardware_matrix_without_claiming_device_support(api_client):
    response = api_client.get("/api/system/capabilities")
    assert response.status_code == 200
    matrix = response.json()["sanitization_capability_matrix"]
    assert matrix["execution_policy"] == "PREVIEW_ONLY_NO_DESTRUCTIVE_DEVICE_COMMANDS"
    by_type = {row["media_type"]: row for row in matrix["rows"]}
    assert by_type["NVME_SSD"]["target_capability_status"] == "UNVERIFIED_NOT_PROBED"
    assert by_type["NVME_SSD"]["execution_status"] == "NOT_EXECUTED"
    assert by_type["USB_FLASH"]["purge_status"] == "NOT_SUPPORTED"
