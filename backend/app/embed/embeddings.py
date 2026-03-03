from __future__ import annotations

import hashlib
import math
import os
from collections.abc import Iterable

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


def _chunked(values: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def _fallback_embedding(text: str, dimensions: int = 1536) -> list[float]:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    values = [((byte / 255.0) * 2.0) - 1.0 for byte in digest]
    if dimensions <= len(values):
        raw = values[:dimensions]
    else:
        expanded = values.copy()
        while len(expanded) < dimensions:
            expanded.extend(values)
        raw = expanded[:dimensions]
    norm = math.sqrt(sum(v * v for v in raw)) or 1.0
    return [v / norm for v in raw]


class TextEmbedder:
    def __init__(self, model: str, batch_size: int = 64):
        self.model = model
        self.batch_size = max(1, batch_size)
        self.api_key = os.getenv("OPENAI_API_KEY")
        self._fallback_logged = False
        self._client = OpenAI(api_key=self.api_key) if (OpenAI and self.api_key) else None

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []

        normalized = [text if text.strip() else "(empty)" for text in texts]
        if self._client is None:
            if not self._fallback_logged:
                print(
                    "WARN: OPENAI_API_KEY or openai package missing; "
                    "using deterministic fallback embeddings."
                )
                self._fallback_logged = True
            return [_fallback_embedding(text) for text in normalized]

        output: list[list[float]] = []
        for batch in _chunked(normalized, self.batch_size):
            response = self._client.embeddings.create(model=self.model, input=batch)
            output.extend([item.embedding for item in response.data])
        return output
