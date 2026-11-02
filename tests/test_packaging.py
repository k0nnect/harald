"""Packaging and ci: what pypi shows, and what every pull request runs."""

import json
import tomllib
from pathlib import Path

import harald

REPO = Path(__file__).resolve().parents[1]
GITHUB = "https://github.com/k0nnect/harald"
SERVER_NAME = "io.github.k0nnect/harald"


def test_pypi_page_shows_the_readme_and_links_the_repo():
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text())
    project = pyproject["project"]
    # the readme comes from a build hook that points its image paths at the repo
    assert "readme" not in project and "readme" in project["dynamic"]
    assert any(
        r.startswith("hatch-fancy-pypi-readme")
        for r in pyproject["build-system"]["requires"]
    )
    hook = pyproject["tool"]["hatch"]["metadata"]["hooks"]["fancy-pypi-readme"]
    assert hook["content-type"] == "text/markdown"
    assert hook["fragments"] == [{"path": "README.md"}]
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


def test_registry_entry_matches_the_release():
    # the official mcp registry lists harald from server.json; each release has to
    # bump both versions there along with harald.__version__
    server = json.loads((REPO / "server.json").read_text())
    assert server["name"] == SERVER_NAME
    assert server["version"] == harald.__version__
    pypi = [p for p in server["packages"] if p["registryType"] == "pypi"]
    assert [p["identifier"] for p in pypi] == ["harald"]
    assert pypi[0]["version"] == harald.__version__


def test_glama_builds_the_mcp_server_from_the_lockfile():
    # glama builds the Dockerfile and starts the server to list its tools
    dockerfile = (REPO / "Dockerfile").read_text()
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text()
    uv = dockerfile.split("ghcr.io/astral-sh/uv:", 1)[1].split()[0]
    assert f'version: "{uv}"' in ci  # the same uv as ci, which wrote uv.lock
    assert "uv sync --locked --no-dev" in dockerfile
    assert 'CMD ["harald", "mcp"]' in dockerfile
    ignored = (REPO / ".dockerignore").read_text().splitlines()
    assert {".superpowers", "docs/superpowers", ".venv"} <= set(ignored)
    glama = json.loads((REPO / "glama.json").read_text())
    assert glama["maintainers"] == ["k0nnect"]


def test_readme_carries_the_registry_ownership_comment():
    # the registry reads the pypi description for this line before it lists harald
    lines = (REPO / "README.md").read_text(encoding="utf-8").splitlines()
    assert f"<!-- mcp-name: {SERVER_NAME} -->" in lines
