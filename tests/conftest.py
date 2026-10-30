import pytest
from fakes import FakeClient, FakeScanner


@pytest.fixture(autouse=True)
def fresh_fakes():
    """Give every test default fake ble backends with no recorded writes."""
    FakeScanner.reset()
    FakeClient.reset()


@pytest.fixture(autouse=True)
def harald_home(tmp_path, monkeypatch):
    """Point HARALD_HOME at a fresh tmp dir so no test touches the real ~/.harald."""
    path = tmp_path / "harald-home"
    path.mkdir()
    monkeypatch.setenv("HARALD_HOME", str(path))
    return path


@pytest.fixture
def home(harald_home):
    return harald_home
