"""Retrieval layer: dense fallback, BM25, hybrid fusion, and PDF extension."""
from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

try:
    from pypdf import PdfReader
except Exception:  # pragma: no cover
    PdfReader = None


@dataclass
class RetrievedDoc:
    rank: int
    score: float
    id: str
    text: str
    attack_type: str
    rule: str
    source_name: str
    source_url: str


class BM25Retriever:
    def __init__(self, documents: Sequence[str], k1: float = 1.5, b: float = 0.75):
        self.documents = list(documents)
        self.k1 = k1
        self.b = b
        self.tokens = [self._tokenize(doc) for doc in self.documents]
        self.avgdl = sum(len(t) for t in self.tokens) / max(1, len(self.tokens))
        self.df = {}
        for toks in self.tokens:
            for tok in set(toks):
                self.df[tok] = self.df.get(tok, 0) + 1
        self.N = len(self.documents)

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return [t.lower() for t in text.replace("/", " ").replace("_", " ").split() if len(t) > 1]

    def scores(self, query: str) -> np.ndarray:
        q_tokens = self._tokenize(query)
        scores = np.zeros(self.N, dtype=float)
        for i, doc_tokens in enumerate(self.tokens):
            dl = len(doc_tokens) or 1
            freqs = {}
            for tok in doc_tokens:
                freqs[tok] = freqs.get(tok, 0) + 1
            for tok in q_tokens:
                if tok not in self.df:
                    continue
                idf = math.log(1 + (self.N - self.df[tok] + 0.5) / (self.df[tok] + 0.5))
                tf = freqs.get(tok, 0)
                denom = tf + self.k1 * (1 - self.b + self.b * dl / self.avgdl)
                scores[i] += idf * ((tf * (self.k1 + 1)) / denom) if denom else 0.0
        return scores


class SnortKnowledgeBase:
    def __init__(self, dataset_path: Path | str):
        self.dataset_path = Path(dataset_path)
        self.df = pd.read_csv(self.dataset_path)
        self.df = self.df.fillna("")
        self._rebuild()

    @staticmethod
    def _description(row: pd.Series) -> str:
        return str(row.get("description_naturelle") or row.get("description_nl") or "")

    @staticmethod
    def _rule(row: pd.Series) -> str:
        return str(row.get("snort_rule_reference") or row.get("rule") or "")

    @staticmethod
    def _source_name(row: pd.Series) -> str:
        return str(row.get("source_name") or row.get("source_type") or "person1_dataset")

    @staticmethod
    def _source_url(row: pd.Series, dataset_path: Path) -> str:
        return str(row.get("source_url") or dataset_path)

    def _compose_text(self, row: pd.Series) -> str:
        return " ".join([
            self._description(row),
            str(row.get("attack_type", "")),
            str(row.get("attack_family", "")),
            str(row.get("severity", "")),
            self._rule(row),
            str(row.get("log_example", "")),
            str(row.get("false_positive_context", "")),
            str(row.get("expected_explanation", "")),
        ])

    def _rebuild(self) -> None:
        self.texts = [self._compose_text(row) for _, row in self.df.iterrows()]
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=12000)
        self.tfidf = self.vectorizer.fit_transform(self.texts)
        self.bm25 = BM25Retriever(self.texts)

    def _to_docs(self, indices: Sequence[int], scores: Sequence[float]) -> List[RetrievedDoc]:
        docs = []
        for rank, (idx, score) in enumerate(zip(indices, scores), 1):
            row = self.df.iloc[int(idx)]
            docs.append(RetrievedDoc(
                rank=rank,
                score=float(score),
                id=str(row.get("id", idx)),
                text=self._description(row),
                attack_type=str(row.get("attack_type", "")),
                rule=self._rule(row),
                source_name=self._source_name(row),
                source_url=self._source_url(row, self.dataset_path),
            ))
        return docs

    def dense_retrieve(self, query: str, k: int = 5) -> List[RetrievedDoc]:
        qv = self.vectorizer.transform([query])
        sims = cosine_similarity(qv, self.tfidf).ravel()
        idx = np.argsort(sims)[::-1][:k]
        return self._to_docs(idx, sims[idx])

    def bm25_retrieve(self, query: str, k: int = 5) -> List[RetrievedDoc]:
        scores = self.bm25.scores(query)
        idx = np.argsort(scores)[::-1][:k]
        return self._to_docs(idx, scores[idx])

    @staticmethod
    def _normalize(scores: np.ndarray) -> np.ndarray:
        if scores.max() == scores.min():
            return np.zeros_like(scores)
        return (scores - scores.min()) / (scores.max() - scores.min())

    def hybrid_retrieve(self, query: str, k: int = 5, alpha: float = 0.55) -> List[RetrievedDoc]:
        qv = self.vectorizer.transform([query])
        dense = cosine_similarity(qv, self.tfidf).ravel()
        sparse = self.bm25.scores(query)
        fused = alpha * self._normalize(dense) + (1 - alpha) * self._normalize(sparse)
        idx = np.argsort(fused)[::-1][:k]
        return self._to_docs(idx, fused[idx])

    def rerank(self, query: str, docs: List[RetrievedDoc], k: int = 5) -> List[RetrievedDoc]:
        q = query.lower()
        reranked = []
        for doc in docs:
            keyword_bonus = 0.0
            for token in doc.attack_type.replace("_", " ").split():
                if token in q:
                    keyword_bonus += 0.15
            validity_bonus = 0.10 if doc.rule != "NO_RULE_RECOMMENDED" and "sid:" in doc.rule else 0.0
            source_bonus = 0.05 if doc.source_url else 0.0
            score = doc.score + keyword_bonus + validity_bonus + source_bonus
            reranked.append((score, doc))
        reranked.sort(key=lambda x: x[0], reverse=True)
        output = []
        for rank, (score, doc) in enumerate(reranked[:k], 1):
            doc.rank = rank
            doc.score = float(score)
            output.append(doc)
        return output

    def add_pdf_to_kb(self, pdf_path: Path | str, source_name: str = "uploaded_pdf") -> int:
        if PdfReader is None:
            raise RuntimeError("pypdf is not installed")
        path = Path(pdf_path)
        reader = PdfReader(str(path))
        new_rows = []
        for page_no, page in enumerate(reader.pages, 1):
            text = page.extract_text() or ""
            chunks = [text[i:i+1200] for i in range(0, len(text), 1200) if text[i:i+1200].strip()]
            for j, chunk in enumerate(chunks, 1):
                new_rows.append({
                    "id": f"PDF-{path.stem}-{page_no}-{j}",
                    "description_naturelle": chunk,
                    "attack_type": "external_pdf_knowledge",
                    "attack_family": "knowledge_base",
                    "severity": "none",
                    "snort_rule_reference": "NO_RULE_RECOMMENDED",
                    "false_positive_context": "external document chunk",
                    "source_type": "uploaded_pdf",
                    "expected_explanation": "Chunk imported from an uploaded PDF to extend retrieval context.",
                    "source_name": source_name,
                    "source_url": str(path),
                    "log_example": "",
                })
        if new_rows:
            self.df = pd.concat([self.df, pd.DataFrame(new_rows)], ignore_index=True).fillna("")
            self._rebuild()
        return len(new_rows)
