"""Token budget enforcement — prevents runaway LLM costs."""
from ..core.config import settings


class BudgetGovernor:
    def __init__(self):
        self.calls = 0
        self.tokens = 0

    def can_call(self) -> bool:
        return (self.calls < settings.MAX_LLM_CALLS_PER_INVESTIGATION
                and self.tokens < settings.MAX_TOKENS_PER_INVESTIGATION)

    def record(self, tokens: int):
        self.calls += 1
        self.tokens += tokens

    def stats(self) -> dict:
        return {
            "llm_calls": self.calls,
            "tokens_used": self.tokens,
            "calls_remaining": max(0, settings.MAX_LLM_CALLS_PER_INVESTIGATION - self.calls),
            "tokens_remaining": max(0, settings.MAX_TOKENS_PER_INVESTIGATION - self.tokens),
        }
