from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceFile(StrictModel):
    path: str
    text: str


class CodeChunk(StrictModel):
    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    text: str

    @model_validator(mode="after")
    def _validate_line_range(self) -> "CodeChunk":
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        return self


class Finding(StrictModel):
    vuln_type: str = Field(min_length=1)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    references: list[str] = Field(default_factory=list)
    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    message: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_line_range(self) -> "Finding":
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        if "\n" in self.message:
            raise ValueError("message must be a single line")
        return self


class ScanStats(StrictModel):
    files_scanned: int = Field(default=0, ge=0)
    chunks_considered: int = Field(default=0, ge=0)
    llm_calls: int = Field(default=0, ge=0)
    llm_retries: int = Field(default=0, ge=0)
    skipped_low_similarity: int = Field(default=0, ge=0)
    llm_parse_failures: int = Field(default=0, ge=0)
    chunks_skipped_parse_error: int = Field(default=0, ge=0)
    chunks_skipped_exception: int = Field(default=0, ge=0)
    findings_before_dedup: int = Field(default=0, ge=0)
    findings_after_dedup: int = Field(default=0, ge=0)


class ScanMetadata(StrictModel):
    schema_version: str = "1.0.0"
    repo_path: str
    scan_started_at: datetime
    scan_finished_at: datetime
    model: str
    top_k: int = Field(ge=1)
    similarity_threshold: float = Field(ge=0.0, le=1.0)
    max_chunks: int | None = Field(default=None, ge=1)
    chunk_size_lines: int = Field(ge=1)
    repair_retries: int = Field(default=1, ge=0)


class ScanChunkError(StrictModel):
    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    reason: str = Field(min_length=1)


class ScanReport(StrictModel):
    metadata: ScanMetadata
    stats: ScanStats
    findings: list[Finding] = Field(default_factory=list)
    errors: list[ScanChunkError] = Field(default_factory=list)


class ScanRequest(StrictModel):
    local_path: str = Field(min_length=1)


class KBDocument(StrictModel):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)
    severity_guidance: str = Field(min_length=1)
    content: str = Field(min_length=1)


class RetrievalHit(StrictModel):
    id: str
    title: str
    score: float = Field(ge=0.0, le=1.0)
    severity_guidance: str
    tags: list[str] = Field(default_factory=list)
    preview: str = ""


class RetrievalSample(StrictModel):
    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    hits: list[RetrievalHit] = Field(default_factory=list)


class IndexRequest(StrictModel):
    local_path: str = Field(min_length=1)
    top_k: int | None = Field(default=None, ge=1, le=20)


class IndexReport(StrictModel):
    kb_docs_indexed: int = 0
    code_chunks_indexed: int = 0
    retrieval_samples: list[RetrievalSample] = Field(default_factory=list)
    persist_dir: str
