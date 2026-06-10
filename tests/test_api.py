import asyncio

import httpx

from snort_rag.api.main import app


def request(method: str, url: str, **kwargs) -> httpx.Response:
    async def _send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, url, **kwargs)

    return asyncio.run(_send())


def test_health():
    response = request("GET", "/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["educational_defensive"] is True


def test_dataset_stats():
    response = request("GET", "/api/dataset/stats")

    assert response.status_code == 200
    payload = response.json()
    assert payload["rows"] > 0
    assert payload["malicious_rows"] >= 0
    assert payload["benign_rows"] >= 0
    assert "attack_type_counts" in payload


def test_generate_rule_default_mock_mode_requires_no_ollama_or_docker():
    response = request(
        "POST",
        "/api/generate-rule",
        json={
            "query": "Detect SQL injection with UNION SELECT in HTTP URI",
            "architecture": "rag_llm",
            "k": 3,
        },
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["query"] == "Detect SQL injection with UNION SELECT in HTTP URI"
    assert result["generated_rule"]
    assert "syntax_validation" in result
    assert "false_positive_risk" in result
