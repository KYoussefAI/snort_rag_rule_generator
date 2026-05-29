"""Implementation of the Devoir 3 RAG architectures for the Snort topic."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from snort_rag.generator import build_generation_result, generate_from_context
from snort_rag.retrieval import RetrievedDoc, SnortKnowledgeBase
from snort_rag.templates import ATTACK_KEYWORDS, detect_attack_type, generate_snort_rule


DEFAULT_DATASET = Path(__file__).resolve().parents[2] / "data" / "processed" / "final_snort_dataset.csv"


class SnortRAGArchitectures:
    def __init__(self, dataset_path: str | Path = DEFAULT_DATASET):
        self.kb = SnortKnowledgeBase(dataset_path)
        self.graph = self._build_graph()

    def _pack(self, architecture: str, result: Dict[str, object], docs: List[RetrievedDoc]) -> Dict[str, object]:
        result = dict(result)
        result["architecture"] = architecture
        result["retrieved_ids"] = [d.id for d in docs]
        result["retrieved_attack_types"] = [d.attack_type for d in docs]
        result["retrieval_scores"] = [round(d.score, 4) for d in docs]
        return result

    def llm_no_rag(self, query: str) -> Dict[str, object]:
        # Baseline: no retrieval, only direct query keywords and template generation.
        attack_type = detect_attack_type(query)
        if attack_type == "benign":
            rule = "NO_RULE_RECOMMENDED"
        else:
            rule = generate_snort_rule(attack_type, query)
        result = build_generation_result(
            query=query,
            attack_type=attack_type,
            rule=rule,
            retrieved_docs=[],
            prompt=f"User request only: {query}",
            explanation="Baseline without retrieval: generated only from query keywords, so context control is weak.",
        )
        return self._pack("baseline_no_rag", result, [])

    def rag_classic(self, query: str, k: int = 5) -> Dict[str, object]:
        docs = self.kb.dense_retrieve(query, k=k)
        return self._pack("rag_classic", generate_from_context(query, docs), docs)

    def rag_rerank(self, query: str, k: int = 8) -> Dict[str, object]:
        initial = self.kb.dense_retrieve(query, k=k)
        docs = self.kb.rerank(query, initial, k=5)
        return self._pack("rag_rerank", generate_from_context(query, docs), docs)

    def rag_hybrid(self, query: str, k: int = 5) -> Dict[str, object]:
        docs = self.kb.hybrid_retrieve(query, k=k)
        return self._pack("rag_hybrid", generate_from_context(query, docs), docs)

    def multi_hop_rag(self, query: str, k: int = 4) -> Dict[str, object]:
        first = self.kb.hybrid_retrieve(query, k=k)
        direct_attack_type = detect_attack_type(query)
        inferred = direct_attack_type if direct_attack_type != "suspicious_user_agent" else (first[0].attack_type if first else direct_attack_type)
        refined_query = query + " " + inferred.replace("_", " ") + " " + " ".join(ATTACK_KEYWORDS.get(inferred, [])[:3])
        second = self.kb.hybrid_retrieve(refined_query, k=k)
        docs = self.kb.rerank(refined_query, first + second, k=5)
        return self._pack("multi_hop_rag", generate_from_context(query, docs, force_attack_type=inferred), docs)

    def _build_graph(self) -> Dict[str, List[RetrievedDoc]]:
        graph: Dict[str, List[RetrievedDoc]] = defaultdict(list)
        for _, row in self.kb.df.iterrows():
            doc = RetrievedDoc(
                rank=0,
                score=1.0,
                id=str(row.get("id", "")),
                text=self.kb._description(row),
                attack_type=str(row.get("attack_type", "")),
                rule=self.kb._rule(row),
                source_name=self.kb._source_name(row),
                source_url=self.kb._source_url(row, self.kb.dataset_path),
            )
            graph[doc.attack_type].append(doc)
        return graph

    def graph_rag(self, query: str, k: int = 5) -> Dict[str, object]:
        attack_type = detect_attack_type(query)
        candidate_docs = self.graph.get(attack_type, [])[:k]
        # If graph node is weak, fallback to hybrid retrieval.
        docs = candidate_docs if candidate_docs else self.kb.hybrid_retrieve(query, k=k)
        for i, doc in enumerate(docs, 1):
            doc.rank = i
            doc.score = max(doc.score, 0.8)
        return self._pack("graph_rag", generate_from_context(query, docs, force_attack_type=attack_type), docs)

    def agentic_rag(self, query: str, k: int = 5) -> Dict[str, object]:
        # Simple agent policy: decide retrieval strategy based on query ambiguity.
        attack_type = detect_attack_type(query)
        specific = any(kw in query.lower() for kw in ATTACK_KEYWORDS.get(attack_type, []))
        if attack_type == "benign":
            docs = self.kb.hybrid_retrieve(query, k=k)
            result = generate_from_context(query, docs, force_attack_type="benign")
        elif specific and len(query.split()) > 7:
            docs = self.kb.hybrid_retrieve(query, k=k)
            docs = self.kb.rerank(query, docs, k=k)
            result = generate_from_context(query, docs, force_attack_type=attack_type)
            result["explanation"] += " Agent decision: direct hybrid retrieval because the query was specific."
        else:
            # Ambiguous request: do a first hop, expand with top category, then rerank.
            first = self.kb.hybrid_retrieve(query, k=k)
            inferred = attack_type if attack_type != "suspicious_user_agent" else (first[0].attack_type if first else attack_type)
            expanded = query + " " + inferred.replace("_", " ")
            second = self.kb.hybrid_retrieve(expanded, k=k)
            docs = self.kb.rerank(expanded, first + second, k=k)
            result = generate_from_context(query, docs, force_attack_type=inferred)
            result["explanation"] += " Agent decision: query was ambiguous, so it used retrieval + query expansion."
        # Agent has lower hallucination if it retrieved valid same-type evidence.
        if docs and any(d.attack_type == result["attack_type"] for d in docs[:3]):
            result["hallucination_risk"] = max(0.0, float(result["hallucination_risk"]) - 0.15)
        return self._pack("agentic_rag", result, docs)

    def run_all(self, query: str) -> Dict[str, Dict[str, object]]:
        return {
            "baseline": self.llm_no_rag(query),
            "rag_classic": self.rag_classic(query),
            "rag_rerank": self.rag_rerank(query),
            "rag_hybrid": self.rag_hybrid(query),
            "multi_hop": self.multi_hop_rag(query),
            "graph_rag": self.graph_rag(query),
            "agentic_rag": self.agentic_rag(query),
        }
