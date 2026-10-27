"""Object model (Part II): addresses resolve the way the report says."""
import pytest

from sjvnet.model import ObjectModel


@pytest.fixture(scope="module")
def model():
    return ObjectModel.load()


def test_ten_zones_with_brief_addresses(model):
    assert len(model.zones) == 10
    assert model.zones["Z_HIS"]["subnet"] == "192.168.10.0/24"
    assert model.zones["Z_CLINICAL"]["subnet"] == "192.168.50.0/23"
    assert model.hosts["H_EMR_DB"]["ip"] == "192.168.10.20"


def test_internet_excludes_private_ranges(model):
    inet = model.addrset("internet")
    assert inet.contains("8.8.8.8")
    for ip in ("10.61.0.50", "172.16.5.5", "192.168.10.20"):
        assert not inet.contains(ip)


def test_negated_and_zone_except(model):
    not_his = model.addrset({"not": ["Z_HIS", "H_BASTION"]})
    assert not not_his.contains("192.168.10.21")
    assert not not_his.contains("192.168.90.5")
    assert not_his.contains("192.168.40.100")
    mgmt = model.addrset({"zone": "Z_MGMT", "except": ["H_SIEM"]})
    assert mgmt.contains("192.168.90.5") and not mgmt.contains("192.168.90.10")


def test_zone_of(model):
    assert model.zone_of("192.168.51.10") == "Z_CLINICAL"      # /23 upper half
    assert model.zone_of("10.200.0.10") == "INTERNAL_OTHER"
    assert model.zone_of("8.8.8.8") == "INTERNET"


def test_fqdn_objects_only_resolve_in_simulation(model):
    assert model.addrset("F_EPRESCRIBE", simulate=True).contains("203.0.113.10")
    assert model.addrset("F_EPRESCRIBE", simulate=False).is_empty()


def test_validate_objects_is_clean(model):
    import validate_objects
    assert validate_objects.check(model) == []
