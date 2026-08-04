# provider.py
import json
import os
import pathlib
import time
from typing import Any, Dict, List, Optional, Set

import httpx
from dotenv import load_dotenv

# LangChain chat wrappers
from langchain_openai import ChatOpenAI

try:
    from langchain_anthropic import ChatAnthropic

    _HAS_ANTHROPIC = True
except Exception:
    ChatAnthropic = None
    _HAS_ANTHROPIC = False

load_dotenv()  # load .env if present

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
_MODELS_CACHE_PATH = pathlib.Path(
    os.getenv("OPENROUTER_MODELS_CACHE", ".openrouter_models.json")
)
_MODELS_CACHE_TTL_S = 24 * 3600

# In-process cache of {model_id: set(supported_parameters)}
_CAPS: Optional[Dict[str, Set[str]]] = None


def _get(env_key: str, default: str = "") -> str:
    v = os.getenv(env_key)
    return v.strip() if isinstance(v, str) else default


def _select_model(provider: str, role: str) -> str:
    role_upper = role.upper()  # TASKER | CODER | EVALUATOR
    if provider == "openai":
        return _get(f"OPENAI_{role_upper}_MODEL") or _get("OPENAI_MODEL", "gpt-4o")
    if provider == "openrouter":
        return _get(f"OPENROUTER_{role_upper}_MODEL") or _get(
            "OPENROUTER_MODEL", "openai/gpt-5.6-terra"
        )
    if provider == "anthropic":
        return _get(f"ANTHROPIC_{role_upper}_MODEL") or _get(
            "ANTHROPIC_MODEL", "claude-sonnet-5"
        )
    raise ValueError(f"Unsupported provider: {provider}")


# ---------------------------------------------------------------------------
# Model capability discovery
#
# Frontier reasoning models (the whole GPT-5.x family, claude-sonnet-5, ...) do
# NOT expose `temperature`. Sending it anyway is either silently dropped or
# rejected, so we ask OpenRouter what each model actually accepts and only send
# parameters it supports. See README "Sampling configuration".
# ---------------------------------------------------------------------------
def _fetch_model_capabilities() -> Dict[str, Set[str]]:
    """Fetch {model_id: set(supported_parameters)} from OpenRouter, with a disk cache."""
    # Serve from disk cache when fresh
    try:
        if _MODELS_CACHE_PATH.is_file():
            age = time.time() - _MODELS_CACHE_PATH.stat().st_mtime
            if age < _MODELS_CACHE_TTL_S:
                raw = json.loads(_MODELS_CACHE_PATH.read_text(encoding="utf-8"))
                return {k: set(v) for k, v in raw.items()}
    except Exception:
        pass  # cache is best-effort

    try:
        resp = httpx.get(f"{OPENROUTER_BASE_URL}/models", timeout=30)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        caps = {m["id"]: set(m.get("supported_parameters") or []) for m in data}
        try:
            _MODELS_CACHE_PATH.write_text(
                json.dumps({k: sorted(v) for k, v in caps.items()}), encoding="utf-8"
            )
        except Exception:
            pass
        return caps
    except Exception as e:
        print(f"[WARN] Could not fetch OpenRouter model capabilities: {e}")
        return {}


def get_capabilities(model: str) -> Set[str]:
    """Supported parameters for a model id. Empty set means 'unknown'."""
    global _CAPS
    if _CAPS is None:
        _CAPS = _fetch_model_capabilities()
    return _CAPS.get(model, set())


def supports(model: str, param: str) -> bool:
    caps = get_capabilities(model)
    if not caps:
        # Unknown model: fall back to a conservative heuristic. Reasoning-model
        # families do not take temperature; assume everything else does.
        if param in ("temperature", "top_p"):
            return not any(
                tag in model for tag in ("gpt-5", "sonnet-5", "opus-5", "o1", "o3", "o4")
            )
        return True
    return param in caps


def _openrouter_extra_body(model: str) -> Dict[str, Any]:
    """
    OpenRouter-specific request body extensions:
      - reasoning effort (the one exposed sampling/quality knob on reasoning models)
      - provider pinning, so 10 'identical' runs don't silently span backends
        with different quantizations
      - usage accounting, so we get authoritative per-call cost back
    """
    body: Dict[str, Any] = {"usage": {"include": True}}

    effort = _get("OPENROUTER_REASONING_EFFORT")
    if effort and supports(model, "reasoning_effort"):
        body["reasoning"] = {"effort": effort}

    provider_cfg: Dict[str, Any] = {}
    order = [p.strip() for p in _get("OPENROUTER_PROVIDER_ORDER").split(",") if p.strip()]
    if order:
        provider_cfg["order"] = order
        provider_cfg["allow_fallbacks"] = False
    if _get("OPENROUTER_REQUIRE_PARAMETERS", "true").lower() == "true":
        provider_cfg["require_parameters"] = True
    if provider_cfg:
        body["provider"] = provider_cfg

    return body


def _sampling_kwargs(model: str, temperature: Optional[float]) -> Dict[str, Any]:
    """
    Only pass temperature when the model actually accepts it.

    NOTE: we deliberately never send `seed`. Each run is meant to be an
    independent draw from the model's sampling distribution; a fixed seed would
    suppress exactly the between-run variance the experiment measures.
    """
    if temperature is None:
        return {}
    if not supports(model, "temperature"):
        return {}
    return {"temperature": temperature}


def describe_sampling(model: str) -> Dict[str, Any]:
    """Machine-readable record of how this model is being sampled (for the manifest)."""
    temp_env = _get("LLM_TEMPERATURE")
    temp = float(temp_env) if temp_env else None
    return {
        "model": model,
        "temperature": temp if supports(model, "temperature") else None,
        "temperature_supported": supports(model, "temperature"),
        "reasoning_effort": _get("OPENROUTER_REASONING_EFFORT") or None,
        "seed": None,  # never set, by design
        "provider_order": [
            p.strip() for p in _get("OPENROUTER_PROVIDER_ORDER").split(",") if p.strip()
        ]
        or None,
    }


def make_llm(role: str, temperature: Optional[float] = None):
    """
    Create a chat model for a given role: 'tasker' | 'coder' | 'evaluator'.
    Respects LLM_PROVIDER and provider-specific keys in .env.

    `temperature` is applied only if the target model supports it; frontier
    reasoning models sample at a fixed internal temperature instead.
    """
    provider = _get("LLM_PROVIDER", "openai").lower()
    model = _select_model(provider, role)

    if temperature is None:
        temp_env = _get("LLM_TEMPERATURE")
        temperature = float(temp_env) if temp_env else None

    timeout = float(_get("LLM_TIMEOUT_S", "900"))
    # Retries are handled by app.utils.io.safe_invoke so they are logged and
    # backed off consistently across providers.
    max_retries = 0

    if provider == "openai":
        api_key = _get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("Missing OPENAI_API_KEY for provider=openai")
        return ChatOpenAI(
            model=model,
            api_key=api_key,
            timeout=timeout,
            max_retries=max_retries,
            **_sampling_kwargs(model, temperature),
        )

    if provider == "openrouter":
        api_key = _get("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError("Missing OPENROUTER_API_KEY for provider=openrouter")
        default_headers = {}
        referer = _get("OPENROUTER_REFERER")
        site = _get("OPENROUTER_SITE_NAME")
        if referer:
            default_headers["HTTP-Referer"] = referer
        if site:
            default_headers["X-Title"] = site

        return ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url=OPENROUTER_BASE_URL,
            default_headers=default_headers or None,
            timeout=timeout,
            max_retries=max_retries,
            extra_body=_openrouter_extra_body(model),
            **_sampling_kwargs(model, temperature),
        )

    if provider == "anthropic":
        if not _HAS_ANTHROPIC:
            raise RuntimeError(
                "langchain-anthropic is not installed. Run: uv add langchain-anthropic"
            )
        api_key = _get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("Missing ANTHROPIC_API_KEY for provider=anthropic")
        return ChatAnthropic(
            model=model,
            api_key=api_key,
            timeout=timeout,
            max_retries=max_retries,
            **_sampling_kwargs(model, temperature),
        )

    raise ValueError(f"Unknown LLM_PROVIDER: {provider}")


def make_three_llms(temperature: Optional[float] = None):
    """
    Convenience helper to create (tasker, coder, evaluator) models at once.
    """
    return (
        make_llm("tasker", temperature=temperature),
        make_llm("coder", temperature=temperature),
        make_llm("evaluator", temperature=temperature),
    )


def resolved_models() -> List[Dict[str, Any]]:
    """Per-role sampling description, recorded in each run's tokens_summary.json."""
    provider = _get("LLM_PROVIDER", "openai").lower()
    out = []
    for role in ("tasker", "coder", "evaluator"):
        model = _select_model(provider, role)
        entry = describe_sampling(model)
        entry["role"] = role
        entry["llm_provider"] = provider
        out.append(entry)
    return out
