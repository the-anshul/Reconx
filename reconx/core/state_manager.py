"""
core/state_manager.py — Resume/checkpoint system.
Saves completed phases to JSON so scans can be resumed after interruption.
"""

import json
import os
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("reconx.state")


class StateManager:
    def __init__(self, domain: str, output_dir: str = "output"):
        safe_domain = domain.replace(".", "_").replace("*", "wildcard")
        self.state_file = Path(output_dir) / f"{safe_domain}_state.json"
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state = self._load()

    def _load(self) -> dict:
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    data = json.load(f)
                logger.info(f"[state] Loaded existing state from {self.state_file}")
                return data
            except Exception as e:
                logger.warning(f"[state] Could not load state file: {e} — starting fresh")
        return {
            "completed": [],
            "pending": [],
            "results": {},
            "started_at": datetime.utcnow().isoformat(),
            "last_updated": None,
        }

    def _save(self):
        self._state["last_updated"] = datetime.utcnow().isoformat()
        with open(self.state_file, "w") as f:
            json.dump(self._state, f, indent=2)

    def is_done(self, phase: str) -> bool:
        return phase in self._state["completed"]

    def mark_done(self, phase: str, result=None):
        if phase not in self._state["completed"]:
            self._state["completed"].append(phase)
        if phase in self._state.get("pending", []):
            self._state["pending"].remove(phase)
        if result is not None:
            self._state["results"][phase] = result
        self._save()
        logger.info(f"[state] Phase '{phase}' marked complete")

    def get_result(self, phase: str):
        return self._state["results"].get(phase)

    def set_pending(self, phases: list[str]):
        self._state["pending"] = [p for p in phases if p not in self._state["completed"]]
        self._save()

    def get_status(self) -> dict:
        return {
            "completed": self._state["completed"],
            "pending": self._state["pending"],
            "started_at": self._state.get("started_at"),
            "last_updated": self._state.get("last_updated"),
        }

    def reset(self):
        self._state = {
            "completed": [],
            "pending": [],
            "results": {},
            "started_at": datetime.utcnow().isoformat(),
            "last_updated": None,
        }
        self._save()
        logger.info("[state] State reset")
