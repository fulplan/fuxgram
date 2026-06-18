"""Offline test for the sysinfo plugin using MockSession."""
from fitnah.sdk.testing import MockSession
from fitnah.plugins.recon.sysinfo import SysInfo


def test_sysinfo_returns_ok():
    plugin = SysInfo()
    session = MockSession(hostname="VICTIMBOX", os="Windows 11", priv_level="admin")
    result = plugin.run(session, {})
    assert result, f"Expected ok result, got {result.error}"
    assert result.data["hostname"] == "VICTIMBOX"
    assert result.data["priv_level"] == "admin"
