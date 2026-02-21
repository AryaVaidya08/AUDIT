from __future__ import annotations

from pathlib import Path

from app.scan.schema import KBDocument

_REQUIRED_FIELDS = ("id", "title", "tags", "severity_guidance")


def _parse_kb_markdown(path: Path) -> KBDocument:
    raw = path.read_text(encoding="utf-8")
    lines = raw.splitlines()

    metadata: dict[str, str] = {}
    content_start_index = None

    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "---":
            content_start_index = index + 1
            break
        if not stripped:
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip()

    if content_start_index is None:
        raise ValueError(f"KB doc missing metadata separator '---': {path}")

    missing = [field for field in _REQUIRED_FIELDS if not metadata.get(field)]
    if missing:
        raise ValueError(f"KB doc missing required metadata ({', '.join(missing)}): {path}")

    tags = [tag.strip() for tag in metadata["tags"].split(",") if tag.strip()]
    content = "\n".join(lines[content_start_index:]).strip()
    if not content:
        raise ValueError(f"KB doc content is empty: {path}")

    return KBDocument(
        id=metadata["id"],
        title=metadata["title"],
        tags=tags,
        severity_guidance=metadata["severity_guidance"],
        content=content,
    )


def load_kb_documents(kb_dir: Path) -> list[KBDocument]:
    if not kb_dir.exists():
        raise FileNotFoundError(f"KB directory not found: {kb_dir}")
    if not kb_dir.is_dir():
        raise NotADirectoryError(f"KB directory is not a directory: {kb_dir}")

    docs: list[KBDocument] = []
    for path in sorted(kb_dir.glob("*.md")):
        docs.append(_parse_kb_markdown(path))

    ids = [doc.id for doc in docs]
    if len(set(ids)) != len(ids):
        raise ValueError(f"Duplicate KB IDs found in {kb_dir}")

    return docs
