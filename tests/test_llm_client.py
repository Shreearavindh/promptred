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