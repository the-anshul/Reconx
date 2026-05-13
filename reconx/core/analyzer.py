"""
core/analyzer.py — AI-powered security analysis for ReconX.

API Key Priority (highest to lowest):
  1. RECONX_AI_KEY environment variable
  2. .env file in the reconx directory
  3. Interactive prompt (saved to .env for future runs)
"""

import logging
import json
import asyncio
import os
from pathlib import Path
from typing import List

from models.asset import Asset

logger = logging.getLogger("reconx.analyzer")

ENV_FILE = Path(__file__).parent.parent / ".env"


# ── .env helpers ─────────────────────────────────────────────────────────────

def _load_env_file() -> dict:
    """Parse key=value pairs from .env file."""
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def _save_key_to_env(key_name: str, key_value: str):
    """Append or update a key in .env file."""
    lines = []
    found = False
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if line.startswith(f"{key_name}="):
                lines.append(f'{key_name}="{key_value}"')
                found = True
            else:
                lines.append(line)
    if not found:
        lines.append(f'{key_name}="{key_value}"')
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _resolve_api_key(provider: str, config_key: str) -> str:
    """
    Resolve the API key using priority order:
    1. OS environment variable (RECONX_AI_KEY)
    2. .env file
    3. config.yaml (if set and not placeholder)
    4. Interactive prompt → saved to .env
    """
    env_var = "RECONX_AI_KEY"

    # 1. OS environment variable
    key = os.environ.get(env_var, "")
    if key:
        logger.debug("API key loaded from environment variable.")
        return key

    # 2. .env file
    env_data = _load_env_file()
    key = env_data.get(env_var, "")
    if key:
        logger.debug("API key loaded from .env file.")
        return key

    # 3. config.yaml (if not placeholder)
    if config_key and config_key not in ("YOUR_API_KEY_HERE", ""):
        logger.debug("API key loaded from config.yaml.")
        return config_key

    # 4. Interactive prompt
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    provider_urls = {
        "google": "https://aistudio.google.com  (bilkul free!)",
        "openai": "https://platform.openai.com/api-keys",
    }
    url = provider_urls.get(provider, "provider website")

    console.print(Panel(
        f"[bold yellow]AI Analysis ke liye API key chahiye![/]\n\n"
        f"[dim]Key yahan se milegi:[/] [cyan]{url}[/]\n\n"
        f"[dim]Key ek baar daalne ke baad [bold].env[/] file mein save ho jayegi.\n"
        f"Dobara nahi maangega.[/]",
        title="[bold magenta]🤖 ReconX AI Setup[/]",
        border_style="magenta",
    ))

    key = console.input("[bold cyan]API Key daalo: [/]").strip()
    if key:
        _save_key_to_env(env_var, key)
        console.print("[green]✅ Key save ho gayi (.env)[/]\n")
    return key


# ── Main Analyzer Class ───────────────────────────────────────────────────────

class AIAnalyzer:
    def __init__(self, config: dict):
        self.ai_cfg    = config.get("ai_analysis", {})
        self.enabled   = self.ai_cfg.get("enabled", False)
        self.provider  = self.ai_cfg.get("provider", "google")
        self.model_name = self.ai_cfg.get("model", "gemini-1.5-flash")
        # api_key is resolved lazily on first analyze() call
        self._config_key = self.ai_cfg.get("api_key", "")
        self.api_key   = ""

    def _prepare_prompt(self, assets: List[Asset]) -> str:
        """Create a compact JSON summary of assets for the LLM."""
        summary_data = []
        for asset in assets:
            if not asset.is_live and not asset.vulns and not asset.ports:
                continue
            summary_data.append({
                "domain": asset.domain,
                "ip": asset.ip,
                "techs": asset.technologies[:5],
                "ports": [p.port for p in asset.ports],
                "vulns": [{"name": v.name, "severity": v.severity} for v in asset.vulns],
            })

        return f"""
You are an expert Cybersecurity Reconnaissance Analyzer.
Below is the reconnaissance data for a target domain in JSON format.

DATA:
{json.dumps(summary_data, indent=2)}

TASK:
1. Provide a concise "Executive Summary" of the overall security posture.
2. List the top 3 most critical risks found with brief explanation.
3. Suggest immediate remediation steps for any vulnerabilities found.
4. If no critical vulns exist, suggest areas for deeper manual testing based on
   the technologies and open ports discovered.

Keep the response professional and formatted in Markdown with clear headings.
"""

    async def analyze(self, assets: List[Asset]) -> str:
        if not self.enabled:
            return ""

        # Resolve key (prompts user if needed)
        self.api_key = _resolve_api_key(self.provider, self._config_key)
        if not self.api_key:
            return "⚠ AI Analysis skipped: No API key provided."

        prompt = self._prepare_prompt(assets)

        try:
            if self.provider == "google":
                return await self._call_gemini(prompt)
            elif self.provider == "openai":
                return await self._call_openai(prompt)
            else:
                return f"⚠ Unsupported AI provider: `{self.provider}`"
        except Exception as e:
            logger.error(f"AI Analysis failed: {e}")
            return f"⚠ AI Analysis error: {e}"

    async def _call_gemini(self, prompt: str) -> str:
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel(self.model_name)
            response = await asyncio.to_thread(model.generate_content, prompt)
            return response.text
        except ImportError:
            return "⚠ `google-generativeai` not installed. Run: `pip install google-generativeai`"

    async def _call_openai(self, prompt: str) -> str:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)
            response = await asyncio.to_thread(
                client.chat.completions.create,
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.choices[0].message.content
        except ImportError:
            return "⚠ `openai` not installed. Run: `pip install openai`"
