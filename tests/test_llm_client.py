"""Live connectivity check: makes one real OpenRouter call. Excluded from the
offline test run (`--ignore=tests/test_llm_client.py`); needs OPENROUTER_API_KEY.
"""

from core.llm.client import LLMClient


def test_openrouter_connection():

    llm = LLMClient()

    response = llm.generate(
        system_prompt="You are a helpful assistant.",
        user_prompt="Reply with exactly: PromptRed connection successful.",
    )

    print("\nLLM RESPONSE:")
    print(response)

    assert response