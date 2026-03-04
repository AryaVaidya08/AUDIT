from __future__ import annotations

from app.parse.chunkers import chunk_source, chunk_sources
from app.scan.schema import SourceFile


def _make_source(num_lines: int, path: str = "test.py") -> SourceFile:
    text = "\n".join(f"line{i}" for i in range(1, num_lines + 1))
    return SourceFile(path=path, text=text)


def test_chunk_source_no_overlap() -> None:
    source = _make_source(10)
    chunks = chunk_source(source, chunk_size_lines=4, chunk_overlap_lines=0)
    assert len(chunks) == 3
    assert chunks[0].start_line == 1
    assert chunks[0].end_line == 4
    assert chunks[1].start_line == 5
    assert chunks[1].end_line == 8
    assert chunks[2].start_line == 9
    assert chunks[2].end_line == 10
    # No lines shared between consecutive chunks
    for i in range(len(chunks) - 1):
        assert chunks[i].end_line < chunks[i + 1].start_line


def test_chunk_source_with_overlap() -> None:
    source = _make_source(10)
    chunks = chunk_source(source, chunk_size_lines=4, chunk_overlap_lines=2)
    # step = 4 - 2 = 2, so starts at 0, 2, 4, 6; chunk at 6 reaches end_line=10 and breaks
    assert len(chunks) == 4
    assert chunks[0].start_line == 1
    assert chunks[0].end_line == 4
    assert chunks[1].start_line == 3
    assert chunks[1].end_line == 6
    assert chunks[2].start_line == 5
    assert chunks[2].end_line == 8
    assert chunks[3].start_line == 7
    assert chunks[3].end_line == 10
    # Verify overlap: consecutive chunks share 2 lines
    assert chunks[0].end_line >= chunks[1].start_line


def test_chunk_source_overlap_clamped() -> None:
    source = _make_source(10)
    # overlap >= chunk_size should be clamped to chunk_size - 1
    chunks = chunk_source(source, chunk_size_lines=4, chunk_overlap_lines=10)
    # Clamped to 3, step = 1
    assert len(chunks) >= 7  # at least 7 chunks with step=1 on 10 lines
    assert chunks[0].start_line == 1
    assert chunks[1].start_line == 2


def test_chunk_sources_passes_overlap() -> None:
    sources = [_make_source(8, path="a.py"), _make_source(8, path="b.py")]
    chunks_no_overlap = chunk_sources(sources, chunk_size_lines=4, chunk_overlap_lines=0)
    chunks_with_overlap = chunk_sources(sources, chunk_size_lines=4, chunk_overlap_lines=2)
    assert len(chunks_with_overlap) > len(chunks_no_overlap)
    # All chunks from both files present
    paths = {c.file_path for c in chunks_with_overlap}
    assert paths == {"a.py", "b.py"}
