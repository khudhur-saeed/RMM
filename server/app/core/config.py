from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

class Settings(BaseSettings):
    """
    Central application configuration management.
    Parses environment variables with fail-fast type validation.
    """
    PROJECT_NAME: str = "Tactical RMM Core"
    API_V1_STR: str = "/api/v1" 

    # PostgreSQL Connection Credentials
    POSTGRES_USER: str = "rmm_user"
    POSTGRES_PASSWORD: str = "rmm_secure_dev_pass_2026"
    POSTGRES_DB: str = "tactical_rmm"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5433

    # Redis Configuration
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379

    @property
    def async_database_url(self) -> str:
        """Constructs the asynchronous PostgreSQL connection URL for asyncpg."""
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

@lru_cache
def get_settings() -> Settings:
    """
    Returns a cached singleton instance of the Settings object.
    Avoids redundant disk I/O when reading environment files.
    """
    return Settings()

settings = get_settings()