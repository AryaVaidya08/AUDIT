from __future__ import annotations

from app.scan.prefilter import score_chunk, select_candidates
from app.scan.schema import CodeChunk


def test_score_chunk_is_clamped_to_unit_interval() -> None:
    chunk = CodeChunk(file_path="src/app.py", start_line=1, end_line=2, text="print('x')")
    score = score_chunk(chunk=chunk, kb_top_score=5.0, suspicious_hits=99, extension_weight=10.0)
    assert score == 1.0


def test_select_candidates_orders_ties_by_original_index() -> None:
    chunks = [
        CodeChunk(file_path="src/a.py", start_line=1, end_line=1, text="print('a')"),
        CodeChunk(file_path="src/b.py", start_line=1, end_line=1, text="print('b')"),
    ]
    selected = select_candidates(chunks=chunks, kb_scores=[0.4, 0.4], max_candidates=2, min_score=0.0)
    assert selected == [0, 1]


def test_select_candidates_prefers_suspicious_pattern_hits() -> None:
    chunks = [
        CodeChunk(file_path="src/a.py", start_line=1, end_line=1, text="print('ok')"),
        CodeChunk(
            file_path="src/b.py",
            start_line=1,
            end_line=1,
            text='password = "supersecret123"\\nquery = "SELECT * FROM users " + user_input',
        ),
    ]
    selected = select_candidates(chunks=chunks, kb_scores=[0.2, 0.2], max_candidates=1, min_score=0.0)
    assert selected == [1]
