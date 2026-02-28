from pydantic_settings import BaseSettings, SettingsConfigDict
import os


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    
    # Default to local sqlite db if no D1 settings are provided
    database_url: str = "sqlite://db.sqlite3"
    models: list[str] = ["veridevice.models.tortoise_models", "aerich.models"]

    # Cloudflare D1 settings
    cf_account_id: str | None = None
    cf_api_token: str | None = None
    
    # D1 database IDs
    prod_database_id: str = "prod-veridevice"
    test_database_id: str = "test-veridevice"

    @property
    def db_url(self) -> str:
        if self.cf_account_id and self.cf_api_token:
            db_id = self.prod_database_id
            if os.getenv("PYTEST_RUNNING"):
                db_id = self.test_database_id
            return f"d1://{self.cf_account_id}/{db_id}?token={self.cf_api_token}"
        return self.database_url


settings = Settings()
