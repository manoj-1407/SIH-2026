"""Unit tests for trust registry / key registry."""
import pytest
from app.core.trust import TrustRegistry, KeyStatus, KeyNotFoundError, TrustRegistryError
from app.core.signing import generate_keypair


@pytest.fixture
def registry(tmp_path):
    return TrustRegistry(str(tmp_path / 'keys.json'))


@pytest.fixture
def keypair():
    return generate_keypair()


def test_register_and_retrieve(registry, keypair):
    _, pub = keypair
    record = registry.register('key-001', pub)
    assert record.status == KeyStatus.ACTIVE
    retrieved = registry.get_public_key('key-001')
    assert retrieved == pub


def test_registry_persists(tmp_path, keypair):
    """Key registered by process A is resolvable by fresh process B."""
    registry_path = str(tmp_path / 'keys.json')
    _, pub = keypair

    # Process A
    reg_a = TrustRegistry(registry_path)
    reg_a.register('key-persistent', pub)

    # Process B (fresh load)
    reg_b = TrustRegistry(registry_path)
    retrieved = reg_b.get_public_key('key-persistent')
    assert retrieved == pub


def test_duplicate_key_raises(registry, keypair):
    _, pub = keypair
    registry.register('key-001', pub)
    with pytest.raises(TrustRegistryError):
        registry.register('key-001', pub)


def test_get_unknown_key_raises(registry):
    with pytest.raises(KeyNotFoundError):
        registry.get_public_key('nonexistent-key')


def test_revoke_key(registry, keypair):
    _, pub = keypair
    registry.register('key-to-revoke', pub)
    registry.revoke('key-to-revoke')

    # Revoked key is NOT accessible
    with pytest.raises(KeyNotFoundError):
        registry.get_public_key('key-to-revoke')


def test_revoked_key_status(registry, keypair):
    _, pub = keypair
    registry.register('key-rev', pub)
    registry.revoke('key-rev')
    keys = registry.list_keys()
    revoked = next(k for k in keys if k['key_id'] == 'key-rev')
    assert revoked['status'] == 'REVOKED'


def test_key_rotation(tmp_path):
    """Old key revoked, new key active — verifier uses new key."""
    from app.core.signing import sign, verify as verify_sig
    registry_path = str(tmp_path / 'keys.json')
    reg = TrustRegistry(registry_path)

    priv_old, pub_old = generate_keypair()
    priv_new, pub_new = generate_keypair()

    reg.register('key-v1', pub_old)
    reg.revoke('key-v1')
    reg.register('key-v2', pub_new)

    data = b'post-rotation evidence'
    sig = sign(priv_new, data)
    pub = reg.get_public_key('key-v2')
    assert verify_sig(pub, data, sig) is True

    with pytest.raises(KeyNotFoundError):
        reg.get_public_key('key-v1')


def test_substituted_key_rejected(registry, keypair):
    """Verifier does not trust key supplied outside registry."""
    from app.core.signing import sign, verify as verify_sig
    priv, pub = keypair
    _, attacker_pub = generate_keypair()

    # Attacker's key is NOT registered
    registry.register('key-001', pub)

    data = b'evidence'
    sig = sign(priv, data)

    # Attacker tries to get verification using their key — but registry knows only pub
    legitimate_pub = registry.get_public_key('key-001')
    assert legitimate_pub == pub  # Registry returns real key, not attacker's

    # If attacker substitutes key_id pointing to attacker_pub: won't be in registry
    with pytest.raises(KeyNotFoundError):
        registry.get_public_key('attacker-key-not-registered')
