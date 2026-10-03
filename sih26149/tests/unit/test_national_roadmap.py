import hashlib
from types import SimpleNamespace

from app.forensics import filesystem
from app.forensics.benchmark import run_live_forensic_benchmark
from app.forensics.carving import carve_bytes
from app.forensics.proof_loop import execute_forensic_proof_loop
from app.forensics.synthetic import generate_fragmented_jpeg_case
from app.sanitization.device_detector import DeviceCapability, MediaType
from app.sanitization.purge_commands import get_device_purge_plan, get_hardware_capability_matrix


def test_fragmented_jpeg_reconstruction_matches_ground_truth():
    stream, expected = generate_fragmented_jpeg_case()

    candidates = carve_bytes(stream, target_types=["JPEG"])
    reconstructed = next(item for item in candidates if item.is_bifragmented)

    assert reconstructed.reconstruction_strategy == "GAP_RECONSTRUCTED"
    assert reconstructed.recovered_bytes == expected
    assert reconstructed.size == len(expected)
    assert reconstructed.sha256 == hashlib.sha256(expected).hexdigest()
    assert reconstructed.source_extents == [
        {"offset": 0, "length": len(expected) - 2},
        {"offset": len(expected) - 2 + 4096, "length": 2},
    ]
    metadata = reconstructed.to_dict()
    assert metadata["mime_type"] == "image/jpeg"
    assert metadata["structure_validation"] == "BOUNDED_RECONSTRUCTION_MARKERS_VALIDATED"
    assert metadata["fragment_count"] == 2
    assert metadata["provenance"] == "RAW_SIGNATURE_AND_STRUCTURE_SCAN"


def test_hardware_matrix_never_equates_host_tools_with_device_support():
    matrix = get_hardware_capability_matrix()
    rows = {row["media_type"]: row for row in matrix["rows"]}

    assert matrix["execution_policy"] == "PREVIEW_ONLY_NO_DESTRUCTIVE_DEVICE_COMMANDS"
    for media_type in ("ROTATIONAL_HDD", "SATA_SSD", "NVME_SSD"):
        assert rows[media_type]["target_capability_status"] == "UNVERIFIED_NOT_PROBED"
        assert rows[media_type]["purge_status"] == "UNVERIFIED"
        assert rows[media_type]["execution_status"] == "NOT_EXECUTED"
    assert rows["USB_FLASH"]["purge_status"] == "NOT_SUPPORTED"
    assert rows["SD_CARD"]["purge_status"] == "NOT_SUPPORTED"
    assert rows["VIRTUAL_DISK_IMAGE"]["purge_status"] == "NOT_APPLICABLE"


def test_hardware_command_preview_quotes_untrusted_device_path():
    target = "/dev/sda; echo unsafe"
    device = DeviceCapability(
        media_type=MediaType.SATA_SSD,
        clear_supported=True,
        purge_supported=False,
        purge_command=None,
        destroy_recommendation=None,
        scope_statement="test",
        classification_basis=[],
        ieee_2883_reference="IEEE 2883-2022 §5.2",
    )

    plan = get_device_purge_plan(device, device_path=target)

    assert "'/dev/sda; echo unsafe'" in plan["command_template"]


def test_exfat_is_not_misclassified_as_fat32(monkeypatch, tmp_path):
    monkeypatch.setattr(filesystem.shutil, "which", lambda name: "file.exe" if name == "file" else None)
    monkeypatch.setattr(
        filesystem.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="exFAT filesystem", returncode=0),
    )

    capability = filesystem.detect_filesystem(str(tmp_path / "volume.img"))

    assert capability.filesystem == "exfat"
    assert capability.detected is True
    assert capability.recovery_supported is False
    assert capability.carving_fallback is True
    assert capability.recovery_method == "RAW_CARVING_FALLBACK"


def test_ext4_without_sleuthkit_reports_raw_carving_only(monkeypatch, tmp_path):
    monkeypatch.setattr(filesystem.shutil, "which", lambda name: "file.exe" if name == "file" else None)
    monkeypatch.setattr(
        filesystem.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="Linux rev 1.0 ext4 filesystem data", returncode=0),
    )

    capability = filesystem.detect_filesystem(str(tmp_path / "volume.img"))

    assert capability.filesystem == "ext4"
    assert capability.status_label == "EXT4_CARVE_FALLBACK"
    assert capability.recovery_supported is False
    assert capability.recovery_method == "RAW_CARVING_FALLBACK"


def test_live_benchmark_measures_fragmented_ground_truth():
    benchmark = run_live_forensic_benchmark(num_synthetic_runs=1)

    assert benchmark["metrics"]["fragmented_fixtures_tested"] == 1
    assert benchmark["metrics"]["fragmented_fixtures_reconstructed"] == 1
    assert benchmark["metrics"]["fragment_reconstruction_accuracy_percentage"] == 100.0
    assert benchmark["fragmented_fixture_results"][0]["sha256_matches_ground_truth"] is True
    assert benchmark["performance"]["carving_scan_bytes"] > 0


def test_proof_loop_rejects_unknown_method_instead_of_falling_back():
    result = execute_forensic_proof_loop(b"test", method="PURGE-ish")

    assert result["proof_result"]["proof_loop_status"] == "FAILURE"
    assert "Unsupported proof-loop method" in result["proof_result"]["error"]


def test_proof_loop_does_not_claim_erasure_when_no_baseline_was_recovered():
    result = execute_forensic_proof_loop(b"\x00" * 1024, method="CLEAR")
    proof = result["proof_result"]

    assert proof["proof_loop_status"] == "WARNING"
    assert proof["assurance"]["validation"]["status"] == "NO_BASELINE_ARTIFACTS"
    assert proof["assurance"]["validation"]["passed"] is False
    assert proof["differential"]["erasure_percentage"] is None
