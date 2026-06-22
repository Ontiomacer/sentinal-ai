from pydantic_settings import BaseSettings
from pathlib import Path
from typing import Optional


class Settings(BaseSettings):
    """Application configuration settings."""
    
    # Application
    app_name: str = "APK Analysis Backend"
    app_version: str = "1.0.0"
    debug: bool = True
    DEBUG: bool = True
    
    # Database
    database_url: str = "sqlite+aiosqlite:///./apk_analysis.db"
    
    # File Upload
    max_upload_size: int = 104857600  # 100MB
    upload_dir: Path = Path("./uploads")
    storage_dir: Path = Path("./storage")
    STORAGE_DIR: str = "./storage"
    allowed_extensions: str = ".apk"
    
    # Ollama / Neural Engine
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3:4b"
    ollama_timeout: float = 300.0
    ollama_max_tokens: int = 2048
    
    # Neural Analysis
    neural_storage_dir: Path = Path("./storage/neural_analysis")
    
    # YARA
    yara_rules_dir: Path = Path("./storage/yara_rules")
    
    # Clerk
    clerk_secret_key: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()

# Ensure directories exist
settings.upload_dir.mkdir(exist_ok=True)
settings.storage_dir.mkdir(exist_ok=True)
settings.neural_storage_dir.mkdir(parents=True, exist_ok=True)
settings.yara_rules_dir.mkdir(parents=True, exist_ok=True)
