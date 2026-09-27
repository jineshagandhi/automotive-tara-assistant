"""Optional local LLM through Ollama.

The model runs on the engineer's machine, so architecture data never leaves it.
When Ollama is not running, the assistant falls back to retrieval and templates.
Set TARA_LLM_PROVIDER=none to disable the model, TARA_LLM_MODEL to choose one.
"""

import json
import os
import re

import requests

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
DEFAULT_OLLAMA_MODEL = "qwen2.5:7b"


class LLMUnavailable(RuntimeError):
    pass


class BaseLLM:
    name = "none"
    model = None

    @property
    def available(self):
        return False

    def chat(self, system, user, json_mode=False, temperature=0.1):
        raise LLMUnavailable("No language model is configured")

    def chat_json(self, system, user):
        """Chat and parse the first JSON object in the reply."""
        reply = self.chat(system, user, json_mode=True)
        match = re.search(r"\{.*\}", reply, re.S)
        if not match:
            raise ValueError("The model did not return JSON")
        return json.loads(match.group(0))


class NoLLM(BaseLLM):
    pass


class OllamaLLM(BaseLLM):
    name = "ollama"

    def __init__(self, model=None, url=OLLAMA_URL, timeout=180):
        self.model = model or os.environ.get("TARA_LLM_MODEL", DEFAULT_OLLAMA_MODEL)
        self.url = url.rstrip("/")
        self.timeout = timeout

    @property
    def available(self):
        try:
            tags = requests.get(self.url + "/api/tags", timeout=1).json()
        except (requests.RequestException, ValueError):
            return False
        names = {m.get("name", "") for m in tags.get("models", [])}
        return self.model in names or (self.model + ":latest") in names

    def chat(self, system, user, json_mode=False, temperature=0.1):
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "options": {"temperature": temperature},
        }
        if json_mode:
            payload["format"] = "json"
        try:
            response = requests.post(self.url + "/api/chat", json=payload, timeout=self.timeout)
            response.raise_for_status()
        except requests.RequestException as error:
            raise LLMUnavailable("Ollama request failed: %s" % error) from error
        return response.json()["message"]["content"]


def get_llm():
    if os.environ.get("TARA_LLM_PROVIDER", "auto").lower() == "none":
        return NoLLM()
    ollama = OllamaLLM()
    return ollama if ollama.available else NoLLM()
