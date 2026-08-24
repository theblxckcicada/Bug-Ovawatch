"""
config.py — centralised settings loaded from environment / .env file.
"""
from __future__ import annotations
import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Server ──────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    # The UI uses bearer tokens rather than cookie credentials. A wildcard
    # permits VM, LAN, and reverse-proxy addresses by default. Public deployments
    # should set CORS_ORIGINS to a comma-separated allowlist.
    cors_origins: str = "*"

    # ── Storage ─────────────────────────────────────────
    output_dir: str = "/app/output"
    data_dir:   str = "/app/data"
    database_dir: str = "/app/data/database"

    # ── Scan engine ─────────────────────────────────────
    max_concurrent_tool_groups: int = 4   # groups run in parallel
    max_tools_per_scan: int = 40
    default_dns_wordlist: str = "/app/data/wordlists/dns.txt"
    default_resolvers:   str = "/app/data/resolvers.txt"

    @property
    def output_path(self) -> Path:
        return Path(self.output_dir)

    @property
    def data_path(self) -> Path:
        return Path(self.data_dir)

    @property
    def database_path(self) -> Path:
        return Path(self.database_dir)


settings = Settings()
