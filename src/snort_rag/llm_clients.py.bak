"""LLM provider abstractions for controlled RAG generation.

The project requires an LLM generation module, but the LLM must be used only
after retrieval and under a strict prompt/validation contract. Tests use the
mock client; local execution can use an Ollama-compatible runtime.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
import time
from typing import Protocol
from urllib import request

from snort_rag.templates import detect_attack_type, generate_snort_rule


@dataclass
class LLMResponse:
    text: str
    model_name: str
    latency_ms: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class BaseLLMClient(Protocol):
    model_name: str

    def generate(
        self,
        prompt: str,
        *,
        temperature: float = 0.0,
        max_new_tokens: int = 512,
    ) -> LLMResponse:
        ...


class MockDeterministicClient:
    """Deterministic client used by tests and offline contract checks."""

    model_name = "mock-deterministic"

    def __init__(self, response_text: str | None = None):
        self.response_text = response_text
        self.prompts: list[str] = []

    def generate(
        self,
        prompt: str,
        *,
        temperature: float = 0.0,
        max_new_tokens: int = 512,
    ) -> LLMResponse:
        start = time.perf_counter()
        self.prompts.append(prompt)
        text = self.response_text or self._response_from_prompt(prompt)
        return LLMResponse(
            text=text,
            model_name=self.model_name,
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    @staticmethod
    def _response_from_prompt(prompt: str) -> str:
        query_match = re.search(r"USER REQUEST:\n(?P<query>.*?)\n\nRETRIEVED CONTEXT:", prompt, re.DOTALL)
        query = query_match.group("query").strip() if query_match else prompt
        attack_type = detect_attack_type(query)
        if attack_type == "benign":
            attack_type = "benign_traffic"
        rule = "NO_RULE_RECOMMENDED" if attack_type == "benign_traffic" else generate_snort_rule(attack_type, query)
        doc_ids = re.findall(r'"id":\s*"([^"]+)"', prompt)[:3]
        return json.dumps({
            "attack_type": attack_type,
            "generated_rule": rule,
            "explanation": f"Mock local client generated a {attack_type} rule from the query and retrieved context.",
            "false_positive_notes": "Offline mock output; final report must benchmark real local LLMs separately.",
            "used_source_doc_ids": doc_ids,
            "confidence": 0.5,
        })


class OllamaClient:
    """Local Ollama-compatible client.

    This does not call a hosted LLM API. It expects a local runtime listening on
    localhost and is therefore suitable for an offline academic setup.
    """

    def __init__(self, model_name: str, endpoint: str = "http://127.0.0.1:11434/api/generate"):
        self.model_name = model_name
        self.endpoint = endpoint

    def generate(
        self,
        prompt: str,
        *,
        temperature: float = 0.0,
        max_new_tokens: int = 512,
    ) -> LLMResponse:
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_new_tokens},
        }
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(self.endpoint, data=data, headers={"Content-Type": "application/json"})
        start = time.perf_counter()
        with request.urlopen(req, timeout=120) as response:  # nosec - local runtime only
            parsed = json.loads(response.read().decode("utf-8"))
        latency_ms = (time.perf_counter() - start) * 1000
        return LLMResponse(
            text=str(parsed.get("response", "")),
            model_name=self.model_name,
            latency_ms=latency_ms,
            prompt_tokens=parsed.get("prompt_eval_count"),
            completion_tokens=parsed.get("eval_count"),
        )


def build_llm_client(model_spec: str) -> BaseLLMClient:
    """Build a client from a CLI/UI model spec."""
    normalized = model_spec.strip()
    if normalized in {"mock", "mock-deterministic"}:
        return MockDeterministicClient()
    if normalized.startswith("ollama:"):
        return OllamaClient(normalized.split(":", 1)[1])
    return OllamaClient(normalized)
