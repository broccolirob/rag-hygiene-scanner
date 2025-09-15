from pathlib import Path
from rag_hygiene_scan.scanner import iter_files

def test_iter_files_filters_extensions(tmp_path: Path):
    # Create a mix of files
    (tmp_path / "a.md").write_text("# md")
    (tmp_path / "b.markdown").write_text("# markdown")
    (tmp_path / "c.html").write_text("<p>")
    (tmp_path / "d.txt").write_text("text")
    (tmp_path / "ignore.py").write_text("print()")
    # Nested directory with more files
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "e.htm").write_text("<p>")
    (nested / "f.jpg").write_text("noop")

    names = sorted(p.name for p in iter_files(tmp_path))
    assert names == ["a.md", "b.markdown", "c.html", "d.txt", "e.htm"]

def test_iter_files_accepts_single_file(tmp_path: Path):
    p = tmp_path / "solo.md"
    p.write_text("# ok")
    files = list(iter_files(p))
    assert files == [p]
