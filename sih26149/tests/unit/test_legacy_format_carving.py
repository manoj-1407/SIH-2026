from app.forensics.carving import CarvingConfidence, carve_bytes


OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _ole_fixture(stream_marker: bytes) -> bytes:
    image = bytearray(1024)
    image[:8] = OLE_MAGIC
    image[0x1E:0x20] = (9).to_bytes(2, "little")
    image[0x20:0x22] = (6).to_bytes(2, "little")
    image[0x28:0x2C] = (1).to_bytes(4, "little")
    image[512:512 + len(stream_marker)] = stream_marker
    return bytes(image)


def test_ole_word_document_subtype_is_detected():
    image = _ole_fixture(b"\x00" * 510 + b"\xec\xa5")

    candidate = next(c for c in carve_bytes(image, target_types=["DOC"]) if c.file_type == "DOC")

    assert candidate.confidence == CarvingConfidence.HIGH


def test_ole_biff_workbook_subtype_is_detected():
    image = _ole_fixture(b"\x09\x08\x10\x00")

    candidate = next(c for c in carve_bytes(image, target_types=["XLS"]) if c.file_type == "XLS")

    assert candidate.confidence == CarvingConfidence.HIGH


def test_ole_powerpoint_stream_subtype_is_detected():
    image = _ole_fixture(b"Current User")

    candidate = next(c for c in carve_bytes(image, target_types=["PPT"]) if c.file_type == "PPT")

    assert candidate.confidence == CarvingConfidence.HIGH


def test_ole_outlook_storage_marker_is_detected():
    image = _ole_fixture(b"__recip_version1.0_")

    candidate = next(c for c in carve_bytes(image, target_types=["MSG"]) if c.file_type == "MSG")

    assert candidate.confidence == CarvingConfidence.HIGH


def test_eml_multipart_headers_are_detected_with_high_confidence():
    message = (
        b"Content-Type: multipart/mixed; boundary=case\r\n"
        b"From: examiner@example.test\r\n"
        b"To: recipient@example.test\r\n"
        b"Subject: Evidence\r\n"
        b"\r\n--case\r\nContent-Type: text/plain\r\n\r\nbody\r\n--case--\r\n"
    )

    candidate = next(c for c in carve_bytes(message, target_types=["EML"]) if c.file_type == "EML")

    assert candidate.confidence == CarvingConfidence.HIGH
    assert candidate.size > 0


def test_plain_text_without_mail_signature_is_not_carved_as_eml():
    assert not carve_bytes(b"From: not enough evidence\nordinary text", target_types=["EML"])
