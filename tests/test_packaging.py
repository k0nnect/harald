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
