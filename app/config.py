import os

class Settings:
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres_password@db:5432/ngfw_db")
    
    NGFW_URL = os.getenv(“NGFW_URL”)
    NGFW_USER = os.getenv("NGFW_USER")
    NGFW_PASSWORD = os.getenv("NGFW_PASSWORD")

SETTINGS = Settings()
