from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class SourceFile(BaseModel):
    path: str
    text: str


class CodeChunk(BaseModel):
    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    text: str


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    snippet: str
    description: str


class ScanReport(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    files_scanned: int = 0
    chunks_scanned: int = 0


class ScanRequest(BaseModel):
    local_path: str = Field(min_length=1)


class KBDocument(BaseModel):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)
    severity_guidance: str = Field(min_length=1)
    content: str = Field(min_length=1)


class RetrievalHit(BaseModel):
    id: str
    title: str
    score: float
    severity_guidance: str
    tags: list[str] = Field(default_factory=list)
    preview: str = ""


class RetrievalSample(BaseModel):
    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    hits: list[RetrievalHit] = Field(default_factory=list)


class IndexRequest(BaseModel):
    local_path: str = Field(min_length=1)
    top_k: int | None = Field(default=None, ge=1, le=20)


class IndexReport(BaseModel):
    kb_docs_indexed: int = 0
    code_chunks_indexed: int = 0
    retrieval_samples: list[RetrievalSample] = Field(default_factory=list)
    persist_dir: str
