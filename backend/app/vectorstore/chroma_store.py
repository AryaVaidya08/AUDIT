from __future__ import annotations

import logging
from dataclasses import dataclass

try:
    import chromadb
except ImportError:
    chromadb = None

from app.embed.embeddings import TextEmbedder
from app.scan.schema import CodeChunk, KBDocument, RetrievalHit
from app.utils.hash import code_chunk_id
import os

logger = logging.getLogger("audit.vectorstore")

try:
    KB_SCORE_THRESHOLD = float(os.getenv("KB_SCORE_THRESHOLD", 0.2))
except (TypeError, ValueError):
    KB_SCORE_THRESHOLD = 0.2


@dataclass(frozen=True)
class ChromaCollections:
    code_chunks: str
    security_kb: str


class ChromaStore:
    def __init__(self, persist_dir: str, collections: ChromaCollections, embedder: TextEmbedder):
        if chromadb is None:
            raise RuntimeError("chromadb is not installed. Install with: pip install chromadb")

        self._embedder = embedder
        self._client = chromadb.PersistentClient(path=persist_dir)
        self._code_chunks = self._client.get_or_create_collection(name=collections.code_chunks)
        self._security_kb = self._client.get_or_create_collection(name=collections.security_kb)

    def _upsert_with_dimension_recovery(
        self,
        collection_name: str,
        ids: list[str],
        documents: list[str],
        metadatas: list[dict[str, str | int]],
        embeddings: list[list[float]],
    ) -> None:
        collection = self._client.get_collection(name=collection_name)
        try:
            collection.upsert(ids=ids, documents=documents, metadatas=metadatas, embeddings=embeddings)
        except Exception as exc:
            if "dimension" not in str(exc).lower():
                raise
            logger.warning(
                "Embedding dimension mismatch for collection '%s'. "
                "Dropping and recreating the collection (existing data will be lost).",
                collection_name,
            )
            self._client.delete_collection(name=collection_name)
            collection = self._client.get_or_create_collection(name=collection_name)
            collection.upsert(ids=ids, documents=documents, metadatas=metadatas, embeddings=embeddings)

    def upsert_kb_documents(self, docs: list[KBDocument]) -> int:
        if not docs:
            return 0

        payloads = [
            "\n".join(
                line
                for line in [
                    f"id: {doc.id}",
                    f"title: {doc.title}",
                    f"domain: {doc.domain}" if doc.domain else "",
                    f"weakness_type: {doc.weakness_type}" if doc.weakness_type else "",
                    f"cwe: {doc.cwe}" if doc.cwe else "",
                    f"owasp_2021: {doc.owasp_2021}" if doc.owasp_2021 else "",
                    f"exploit_classes: {', '.join(doc.exploit_classes)}" if doc.exploit_classes else "",
                    f"languages: {', '.join(doc.languages)}" if doc.languages else "",
                    f"tags: {', '.join(doc.tags)}",
                    f"severity_guidance: {doc.severity_guidance}",
                    "",
                    doc.content,
                ]
                if line
            )
            for doc in docs
        ]
        embeddings = self._embedder.embed_texts(payloads)
        metadatas = [
            {
                "id": doc.id,
                "title": doc.title,
                "tags": ",".join(doc.tags),
                "severity_guidance": doc.severity_guidance,
                "domain": doc.domain,
                "cwe": doc.cwe,
                "owasp_2021": doc.owasp_2021,
            }
            for doc in docs
        ]
        self._upsert_with_dimension_recovery(
            collection_name=self._security_kb.name,
            ids=[doc.id for doc in docs],
            documents=[doc.content for doc in docs],
            metadatas=metadatas,
            embeddings=embeddings,
        )
        self._security_kb = self._client.get_collection(name=self._security_kb.name)
        return len(docs)

    def upsert_code_chunks(self, chunks: list[CodeChunk]) -> int:
        if not chunks:
            return 0

        embeddings = self._embedder.embed_texts([chunk.text for chunk in chunks])
        ids = [code_chunk_id(chunk.file_path, chunk.start_line, chunk.end_line, chunk.text) for chunk in chunks]
        metadatas = [
            {
                "file_path": chunk.file_path,
                "start_line": chunk.start_line,
                "end_line": chunk.end_line,
            }
            for chunk in chunks
        ]
        self._upsert_with_dimension_recovery(
            collection_name=self._code_chunks.name,
            ids=ids,
            documents=[chunk.text for chunk in chunks],
            metadatas=metadatas,
            embeddings=embeddings,
        )
        self._code_chunks = self._client.get_collection(name=self._code_chunks.name)
        return len(chunks)

    def query_security_kb(self, query_text: str, top_k: int = 5, min_score: float | None = None) -> list[RetrievalHit]:
        if not query_text.strip():
            return []

        query_embedding = self._embedder.embed_texts([query_text])[0]
        result = self._security_kb.query(
            query_embeddings=[query_embedding],
            n_results=max(1, top_k),
            include=["metadatas", "documents", "distances"],
        )

        ids = (result.get("ids") or [[]])[0]
        metadatas = (result.get("metadatas") or [[]])[0]
        documents = (result.get("documents") or [[]])[0]
        distances = (result.get("distances") or [[]])[0]

        threshold = KB_SCORE_THRESHOLD if min_score is None else min(max(min_score, 0.0), 1.0)
        hits: list[RetrievalHit] = []
        for index, doc_id in enumerate(ids):
            metadata = metadatas[index] if index < len(metadatas) else {}
            distance = float(distances[index]) if index < len(distances) else 1.0
            raw_preview = documents[index] if index < len(documents) else ""
            score = 1.0 / (1.0 + max(distance, 0.0))
            if score < threshold:
                continue

            meta = metadata if isinstance(metadata, dict) else {}
            tags_value = meta.get("tags", "")
            tags = [tag.strip() for tag in str(tags_value).split(",") if tag.strip()]
            hits.append(
                RetrievalHit(
                    id=str(doc_id),
                    title=str(meta.get("title", doc_id)),
                    score=score,
                    severity_guidance=str(meta.get("severity_guidance", "medium")),
                    tags=tags,
                    domain=str(meta.get("domain", "")),
                    cwe=str(meta.get("cwe", "")),
                    owasp_2021=str(meta.get("owasp_2021", "")),
                    preview=str(raw_preview)[:240],
                )
            )
        return hits

    def collection_counts(self) -> tuple[int, int]:
        return self._security_kb.count(), self._code_chunks.count()
