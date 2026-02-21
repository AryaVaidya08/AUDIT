from __future__ import annotations

from collections.abc import Sequence

from app.scan.schema import CodeChunk, SourceFile


def chunk_source(source: SourceFile, chunk_size_lines: int = 120) -> list[CodeChunk]:
    lines = source.text.splitlines()
    if not lines:
        return []

    chunks: list[CodeChunk] = []
    for index in range(0, len(lines), chunk_size_lines):
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
    return chunks


def chunk_sources(sources: Sequence[SourceFile], chunk_size_lines: int = 120) -> list[CodeChunk]:
    output: list[CodeChunk] = []
    for source in sources:
        output.extend(chunk_source(source=source, chunk_size_lines=chunk_size_lines))
    return output
