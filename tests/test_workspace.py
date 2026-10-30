from harald.workspace import append_note, driver_target, read_notes, workspace_dir


def test_append_and_read_notes(tmp_path):
    assert read_notes("lamp", root=tmp_path) == ""
    append_note("lamp", "colour writes go to ffe1", root=tmp_path, now=0)
    append_note("lamp", "payload looks encrypted", root=tmp_path, now=90)
    assert read_notes("lamp", root=tmp_path) == (
        "## 1970-01-01T00:00:00+00:00\ncolour writes go to ffe1\n"
        "## 1970-01-01T00:01:30+00:00\npayload looks encrypted\n"
    )
    assert (tmp_path / "lamp" / "notes.md").is_file()
    assert workspace_dir("lamp", root=tmp_path) == tmp_path / "lamp"
    assert driver_target("lamp", root=tmp_path) == tmp_path / "lamp" / "driver.py"


def test_notes_isolated_per_slug(tmp_path):
    append_note("a", "only for a", root=tmp_path, now=0)
    assert "only for a" in read_notes("a", root=tmp_path)
    assert read_notes("b", root=tmp_path) == ""
