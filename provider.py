# provider.py
import os
from typing import Tuple
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


def _get(env_key: str, default: str = "") -> str:
    v = os.getenv(env_key)
    return v.strip() if isinstance(v, str) else default


def _select_model(provider: str, role: str) -> str:
    role_upper = role.upper()  # TASKER | CODER | EVALUATOR
    if provider == "openai":
        return _get(f"OPENAI_{role_upper}_MODEL") or _get("OPENAI_MODEL", "gpt-4o")
    if provider == "openrouter":
        return _get(f"OPENROUTER_{role_upper}_MODEL") or _get(
            "OPENROUTER_MODEL", "openai/gpt-4o"
        )
    if provider == "anthropic":
        return _get(f"ANTHROPIC_{role_upper}_MODEL") or _get(
            "ANTHROPIC_MODEL", "claude-3-5-sonnet-latest"
        )
    raise ValueError(f"Unsupported provider: {provider}")


def make_llm(role: str, temperature: float = 0.0):
    """
    Create a chat model for a given role: 'tasker' | 'coder' | 'evaluator'.
    Respects LLM_PROVIDER and provider-specific keys in .env.
    """
    provider = _get("LLM_PROVIDER", "openai").lower()
    model = _select_model(provider, role)

    if provider == "openai":
        api_key = _get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("Missing OPENAI_API_KEY for provider=openai")
        # ChatOpenAI picks up env var, but pass explicitly for clarity
        return ChatOpenAI(
            model=model,
            temperature=temperature,
            api_key=api_key,
            timeout=60,
            max_retries=1,
        )

    if provider == "openrouter":
        api_key = _get("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError("Missing OPENROUTER_API_KEY for provider=openrouter")
        # OpenRouter uses OpenAI-compatible API at a different base_url
        # Optional headers recommended by OpenRouter
        default_headers = {}
        referer = _get("OPENROUTER_REFERER")
        site = _get("OPENROUTER_SITE_NAME")
        if referer:
            default_headers["HTTP-Referer"] = referer
        if site:
            default_headers["X-Title"] = site

        return ChatOpenAI(
            model=model,
            temperature=temperature,
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
            default_headers=default_headers or None,
            timeout=60,
            max_retries=1,
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
            temperature=temperature,
            api_key=api_key,
            timeout=60,
            max_retries=1,
        )

    raise ValueError(f"Unknown LLM_PROVIDER: {provider}")


def make_three_llms(temperature: float = 0.0):
    """
    Convenience helper to create (tasker, coder, evaluator) models at once.
    """
    return (
        make_llm("tasker", temperature=temperature),
        make_llm("coder", temperature=temperature),
        make_llm("evaluator", temperature=temperature),
    )
