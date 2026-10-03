# National Readiness Capability Status

This document records the implementation boundary for the roadmap additions.
Capability reporting is intentionally separate from claims of successful
hardware sanitization or general-purpose fragmented-file recovery.

## Hardware sanitization

The workstation exposes a per-media capability matrix with distinct fields for
target support, host prerequisites, and execution status. ATA and NVMe target
support remains `UNVERIFIED_NOT_PROBED`; installed command-line utilities do
not prove that a particular controller supports a method. USB flash and SD
report no standard host-level Purge method, and virtual images are explicitly
not physical devices.

The UI provides a command preview and risks only. This application does not
execute hardware Purge commands. Physical-device sanitize execution, completion
polling, and device-level post-operation verification are not implemented.

## Fragmented recovery and classification

The raw carver can reconstruct a bounded two-extent JPEG candidate when a
repeated-byte gap separates the detected JPEG prefix from its EOI marker. The
candidate records source extents, gap size, a reconstructed-byte SHA-256,
structure-marker status, MIME type, sampled entropy, and provenance.

This is a constrained gap-reconstruction heuristic, not arbitrary extent
ordering, a filesystem-allocation-map recovery method, or proof that a JPEG
decoder will accept every result. The benchmark uses a deterministic synthetic
JPEG with a known inserted gap and verifies reconstructed bytes by SHA-256.
Its reported throughput is for the synthetic inputs measured in that run; it
does not represent 1–100 GB media, physical-device performance, or broad
real-world recovery rates.

## Filesystem and proof-loop scope

NTFS and FAT32 have filesystem-aware recovery paths. ext-family inode recovery
is reported only when both Sleuth Kit `fls` and `icat` are available. exFAT is
detected distinctly but currently receives raw-carving fallback only.

The proof loop re-runs carving over an in-memory byte stream and records
pre/post artifact metadata in signed evidence. It does not operate on or certify
physical media. PURGE and DESTROY choices in this validation loop are simulated
in-memory probes only; the evidence states this scope.
