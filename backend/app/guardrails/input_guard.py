"""
Input Guardrails — Safety checks BEFORE data reaches the LLM.
"""
import re

INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)ignore\s+(all\s+)?prior\s+instructions",
    r"(?i)disregard\s+(all\s+)?previous",
    r"(?i)you\s+are\s+now\s+a",
    r"(?i)new\s+instructions?\s*:",
    r"(?i)system\s*(prompt|override|message)\s*:",
    r"(?i)forget\s+(everything|all|your)",
    r"(?i)\[SYSTEM[^\]]*\]",
    r"(?i)admin\s+override",
    r"(?i)do\s+not\s+(classify|flag|report|alert)",
    r"(?i)classify\s+(this\s+)?as\s+(benign|safe|false.positive)",
    r"(?i)jailbreak",
]

PII_PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
}

MAX_INPUT_CHARS = 20_000


class InputGuard:
    def check(self, text: str) -> tuple[bool, str]:
        for pat in INJECTION_PATTERNS:
            if re.search(pat, text):
                return False, "Prompt injection pattern detected"
        if len(text) > MAX_INPUT_CHARS:
            return False, f"Input too long ({len(text)} chars, max {MAX_INPUT_CHARS})"
        return True, "passed"

    def sanitize(self, text: str) -> str:
        out = text
        for pat in INJECTION_PATTERNS:
            out = re.sub(pat, "[REDACTED]", out)
        return out

    def detect_pii(self, text: str) -> list[str]:
        found = []
        for pii_type, pat in PII_PATTERNS.items():
            if re.search(pat, text):
                found.append(pii_type)
        return found
