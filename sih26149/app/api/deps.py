"""Global application state and dependencies."""
import os
import threading
import time
from pathlib import Path
from app.cases.store import CaseStore
from app.cases.audit import AuditLogger
from app.core.trust import TrustRegistry, KeyRecord, KeyStatus, KeyNotFoundError
from app.core.persistence import EvidenceStore
from app.core.signing import generate_keypair

# Data directory is environment-configurable.
# Priority:
# 1. SIH26149_DATA_DIR environment variable (set to /app/data in Docker container)
# 2. /app/data if running inside Docker container
# 3. Local repository data directory (<repo_root>/data) for pytest/local dev
_repo_data = Path(__file__).resolve().parents[2] / 'data'
_default = '/app/data' if Path('/app').is_dir() else str(_repo_data)
DATA_DIR = Path(os.getenv('SIH26149_DATA_DIR', _default))

CASES_DIR = DATA_DIR / 'cases'
AUDIT_DIR = DATA_DIR / 'audit'
EVIDENCE_DIR = DATA_DIR / 'evidence'
KEYS_DIR = DATA_DIR / 'keys'
UPLOADS_DIR = DATA_DIR / 'uploads'

case_store = CaseStore(CASES_DIR)
audit_logger = AuditLogger(AUDIT_DIR)
evidence_store = EvidenceStore(EVIDENCE_DIR)
trust_registry = TrustRegistry(KEYS_DIR / 'trust_registry.json')

SIGNER_KEY_ID = 'KEY-EXAMINER-NTRO-PRIMARY'
SIGNER_KEY_FILE = KEYS_DIR / 'primary_examiner.priv'
# Guards the check-then-generate sequence below. Without it, two concurrent
# first-run calls (e.g. two workers starting at once) can both observe
# SIGNER_KEY_FILE.exists() == False, both generate a *different* Ed25519
# keypair, and race to write it — leaving whichever process holds the
# other's now-stale in-memory key permanently unable to verify its own
# future signatures against what's on disk.
_key_init_lock = threading.Lock()

def get_or_create_primary_key() -> tuple[str, bytes]:
    with _key_init_lock:
        return _get_or_create_primary_key_locked()


def _get_or_create_primary_key_locked() -> tuple[str, bytes]:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    if SIGNER_KEY_FILE.exists():
        priv_bytes = SIGNER_KEY_FILE.read_bytes()
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            priv_obj = (
                serialization.load_pem_private_key(priv_bytes, None)
                if b"BEGIN" in priv_bytes
                else Ed25519PrivateKey.from_private_bytes(priv_bytes)
            )
            pub_bytes = priv_obj.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        except Exception:
            priv_bytes, pub_bytes = generate_keypair()
            SIGNER_KEY_FILE.write_bytes(priv_bytes)
            try:
                SIGNER_KEY_FILE.chmod(0o600)
            except OSError:
                pass
    else:
        priv_bytes, pub_bytes = generate_keypair()
        SIGNER_KEY_FILE.write_bytes(priv_bytes)
        try:
            SIGNER_KEY_FILE.chmod(0o600)
        except OSError:
            pass

    # Ensure matching public key is in the trust registry
    try:
        current_pub = trust_registry.get_public_key(SIGNER_KEY_ID)
        if current_pub != pub_bytes:
            # TrustRegistry.upsert() is the public API for this — it used
            # to be `trust_registry._keys[SIGNER_KEY_ID] = KeyRecord(...)`
            # followed by `trust_registry._save()`, reaching directly into
            # a private field because register() raises on an existing
            # key_id. upsert() does the same thing under the registry's
            # own lock instead of bypassing it.
            trust_registry.upsert(SIGNER_KEY_ID, pub_bytes)
    except KeyNotFoundError:
        try:
            trust_registry.register(SIGNER_KEY_ID, pub_bytes)
        except Exception:
            trust_registry.upsert(SIGNER_KEY_ID, pub_bytes)

    return SIGNER_KEY_ID, priv_bytes