"""
models/asset.py — Core data schema for all discovered assets.
Sab kuch isi model me normalize hota hai. Raw output dump nahi hota.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class PortInfo(BaseModel):
    port: int
    protocol: str = "tcp"
    service: str | None = None
    version: str | None = None
    state: str = "open"


class VulnInfo(BaseModel):
    name: str
    severity: str = "info"          # info | low | medium | high | critical
    template_id: str | None = None
    description: str | None = None
    matched_at: str | None = None
    cvss_score: float | None = None
    tags: list[str] = []


class Asset(BaseModel):
    domain: str
    ip: str | None = None
    is_live: bool = False
    http_status: int | None = None
    http_url: str | None = None
    technologies: list[str] = []
    ports: list[PortInfo] = []
    vulns: list[VulnInfo] = []
    cnames: list[str] = []
    discovered_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

    def summary(self) -> dict:
        return {
            "domain": self.domain,
            "ip": self.ip,
            "live": self.is_live,
            "ports": [p.port for p in self.ports],
            "vulns_count": len(self.vulns),
            "critical": sum(1 for v in self.vulns if v.severity == "critical"),
            "high": sum(1 for v in self.vulns if v.severity == "high"),
        }
