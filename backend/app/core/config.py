"""
Application configuration loaded from environment variables.
"""
import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass
class Settings:
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "demo-key")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gpt-4")
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.0"))
    MAX_TOKENS_PER_INVESTIGATION: int = int(os.getenv("MAX_TOKENS_PER_INVESTIGATION", "5000"))
    MAX_LLM_CALLS_PER_INVESTIGATION: int = int(os.getenv("MAX_LLM_CALLS_PER_INVESTIGATION", "15"))
    MAX_TOOL_CALLS_PER_INVESTIGATION: int = int(os.getenv("MAX_TOOL_CALLS_PER_INVESTIGATION", "20"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    DB_PATH: str = os.getenv("DB_PATH", "investigations.db")

    @property
    def is_demo_mode(self) -> bool:
        return self.OPENAI_API_KEY == "demo-key"


settings = Settings()
