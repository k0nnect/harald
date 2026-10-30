import pytest


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
