"""
Technical Scope & Limitation definition for sanitization.
Prevents irresponsible claims of universal physical erasure.
"""

SANITIZATION_SCOPE_STATEMENT = (
    "Virtual forensic image / filesystem-level overwrite only. "
    "Confirms zero-fill of accessible file blocks within the specified target container. "
    "DOES NOT ESTABLISH: physical NAND-cell erasure, SSD wear-leveling coverage, "
    "over-provisioned area erasure, controller remapping, hidden firmware storage, "
    "pre-existing unallocated copies, or backups."
)


def get_scope_record() -> dict:
    return {
        'scope_type': 'FILESYSTEM_CONTAINER_OVERWRITE',
        'scope_statement': SANITIZATION_SCOPE_STATEMENT,
        'limitations': [
            'No physical NAND erasure guarantee',
            'Wear-leveling remap blocks not addressable at filesystem level',
            'Over-provisioned flash sectors unreached',
            'External replicas or snapshots outside scope',
        ]
    }
