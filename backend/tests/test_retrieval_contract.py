from __future__ import annotations

from dataclasses import replace

from app.scan.prompts import build_audit_messages
from app.scan.schema import CodeChunk, KBDocument, RetrievalHit
from app.scan.scan_repo import _fallback_query_kb
import app.vectorstore.chroma_store as chroma_store_module
from app.vectorstore.chroma_store import ChromaStore


class _FakeEmbedder:
    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        return [[0.0, 1.0, 2.0] for _ in texts]


class _FakeCollection:
    def __init__(self, result: dict[str, list[list[object]]]):
        self._result = result

    def query(self, **_: object) -> dict[str, list[list[object]]]:
        return self._result


class _FakeClient:
    def __init__(self) -> None:
        self._collections: dict[str, _FakeCollection] = {}

    def get_or_create_collection(self, name: str) -> _FakeCollection:
        collection = self._collections.get(name)
        if collection is None:
            collection = _FakeCollection({"ids": [[]], "metadatas": [[]], "documents": [[]], "distances": [[]]})
            self._collections[name] = collection
        return collection


def test_chroma_store_disables_anonymized_telemetry_by_default(monkeypatch: object) -> None:
    recorded: dict[str, object] = {}

    class _FakeChromadb:
        @staticmethod
        def Settings(**kwargs: object) -> dict[str, object]:
            recorded["settings_kwargs"] = kwargs
            return dict(kwargs)

        @staticmethod
        def PersistentClient(*, path: str, settings: object) -> _FakeClient:
            recorded["path"] = path
            recorded["settings"] = settings
            return _FakeClient()

    monkeypatch.setattr(chroma_store_module, "chromadb", _FakeChromadb)
    monkeypatch.setattr(
        chroma_store_module,
        "settings",
        replace(chroma_store_module.settings, chroma_anonymized_telemetry=False),
    )

    ChromaStore(
        persist_dir="/tmp/chroma",
        collections=chroma_store_module.ChromaCollections(code_chunks="code", security_kb="kb"),
        embedder=_FakeEmbedder(),
    )

    assert recorded["path"] == "/tmp/chroma"
    assert recorded["settings_kwargs"] == {"anonymized_telemetry": False}
    assert recorded["settings"] == {"anonymized_telemetry": False}


def test_chroma_store_can_enable_anonymized_telemetry(monkeypatch: object) -> None:
    recorded: dict[str, object] = {}

    class _FakeChromadb:
        @staticmethod
        def Settings(**kwargs: object) -> dict[str, object]:
            recorded["settings_kwargs"] = kwargs
            return dict(kwargs)

        @staticmethod
        def PersistentClient(*, path: str, settings: object) -> _FakeClient:
            recorded["path"] = path
            recorded["settings"] = settings
            return _FakeClient()

    monkeypatch.setattr(chroma_store_module, "chromadb", _FakeChromadb)
    monkeypatch.setattr(
        chroma_store_module,
        "settings",
        replace(chroma_store_module.settings, chroma_anonymized_telemetry=True),
    )

    ChromaStore(
        persist_dir="/tmp/chroma",
        collections=chroma_store_module.ChromaCollections(code_chunks="code", security_kb="kb"),
        embedder=_FakeEmbedder(),
    )

    assert recorded["path"] == "/tmp/chroma"
    assert recorded["settings_kwargs"] == {"anonymized_telemetry": True}
    assert recorded["settings"] == {"anonymized_telemetry": True}


def test_chroma_query_security_kb_preserves_weakness_type() -> None:
    store = object.__new__(ChromaStore)
    store._embedder = _FakeEmbedder()
    store._security_kb = _FakeCollection(
        {
            "ids": [["cwe-89-sql-injection"]],
            "metadatas": [[{
                "title": "SQL Injection (OWASP Injection, CWE-89)",
                "severity_guidance": "high",
                "tags": "cwe-89,sqli",
                "domain": "injection",
                "weakness_type": "sql_injection",
                "cwe": "CWE-89",
                "owasp_2021": "A03:Injection",
            }]],
            "documents": [["SQL injection occurs when untrusted input is concatenated into SQL queries."]],
            "distances": [[0.05]],
        }
    )

    hits = store.query_security_kb("query = f\"SELECT * FROM users WHERE id = {user_id}\"", top_k=1, min_score=0.0)

    assert len(hits) == 1
    assert hits[0].weakness_type == "sql_injection"


def test_fallback_kb_hits_preserve_weakness_type() -> None:
    hits = _fallback_query_kb(
        CodeChunk(
            file_path="src/app.py",
            start_line=1,
            end_line=1,
            text='query = f"SELECT * FROM users WHERE id = {user_id}"',
        ),
        top_k=1,
        kb_docs=[
            KBDocument(
                id="cwe-89-sql-injection",
                title="SQL Injection (OWASP Injection, CWE-89)",
                tags=["cwe-89", "sqli"],
                severity_guidance="high",
                weakness_type="sql_injection",
                content="SQL injection occurs when untrusted input is concatenated into SQL queries.",
            )
        ],
    )

    assert len(hits) == 1
    assert hits[0].weakness_type == "sql_injection"


def test_prompt_rendering_includes_weakness_type() -> None:
    _, user_prompt = build_audit_messages(
        chunk=CodeChunk(
            file_path="src/app.py",
            start_line=1,
            end_line=1,
            text='query = f"SELECT * FROM users WHERE id = {user_id}"',
        ),
        kb_hits=[
            RetrievalHit(
                id="cwe-89-sql-injection",
                title="SQL Injection (OWASP Injection, CWE-89)",
                score=0.95,
                severity_guidance="high",
                weakness_type="sql_injection",
                tags=["cwe-89", "sqli"],
                preview="SQL injection occurs when untrusted input is concatenated into SQL queries.",
            )
        ],
    )

    assert '"weakness_type": "sql_injection"' in user_prompt
