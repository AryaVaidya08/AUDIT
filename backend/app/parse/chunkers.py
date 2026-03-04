from __future__ import annotations

from collections.abc import Sequence

from app.scan.schema import CodeChunk, SourceFile


def chunk_source(source: SourceFile, chunk_size_lines: int = 120, chunk_overlap_lines: int = 0) -> list[CodeChunk]:
    lines = source.text.splitlines()
    if not lines:
        return []

    overlap = min(max(chunk_overlap_lines, 0), chunk_size_lines - 1)
    step = chunk_size_lines - overlap if overlap > 0 else chunk_size_lines

    chunks: list[CodeChunk] = []
    for index in range(0, len(lines), step):
        start_line = index + 1
        end_line = min(index + chunk_size_lines, len(lines))
        chunk_text = "\n".join(lines[index:end_line])
        chunks.append(
            CodeChunk(
                file_path=source.path,
                start_line=start_line,
                end_line=end_line,
                text=chunk_text,
            )
        )
        if end_line >= len(lines):
            break
    return chunks


def chunk_sources(sources: Sequence[SourceFile], chunk_size_lines: int = 120, chunk_overlap_lines: int = 0) -> list[CodeChunk]:
    output: list[CodeChunk] = []
    for source in sources:
        output.extend(chunk_source(source=source, chunk_size_lines=chunk_size_lines, chunk_overlap_lines=chunk_overlap_lines))
    return output
