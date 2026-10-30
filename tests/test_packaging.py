"""Packaging and ci: what pypi shows, and what every pull request runs."""

import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GITHUB = "https://github.com/k0nnect/harald"


def test_pypi_page_shows_the_readme_and_links_the_repo():
    project = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]
    assert project["readme"] == "README.md"
    assert project["urls"]["homepage"] == GITHUB
    assert project["urls"]["source"] == GITHUB
    assert project["urls"]["issues"] == f"{GITHUB}/issues"


def test_ci_syncs_the_lockfile_on_the_oldest_python_with_a_read_only_token():
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text()
    requires = tomllib.loads((REPO / "pyproject.toml").read_text())["project"][
        "requires-python"
    ]
    oldest = requires.removeprefix(">=")
    assert "uv sync --locked" in ci
    assert f'python: "{oldest}"' in ci  # a matrix entry on the oldest supported
    assert "python-version: ${{ matrix.python }}" in ci
    assert "\npermissions:\n  contents: read\n" in ci  # top level, for every job
