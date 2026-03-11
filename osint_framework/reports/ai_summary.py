import json
import os
from typing import Any, Dict

import httpx

from osint_framework.core.logger import logger


class AIReportGenerator:
    """Generates natural language executive summaries using local LLM via Ollama."""

    def __init__(self):
        self.ollama_url = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/generate")
        self.model = os.getenv("LLM_MODEL", "llama3")  # default to llama3 or mistral

    async def generate_summary(self, job_data: Dict[str, Any]) -> str:
        """Takes raw OSINT data and returns a human-readable summary via local Ollama instance."""

        # Prepare a condensed version of the data to avoid exceeding context limits
        condensed_data = {
            "target": job_data.get("target"),
            "target_type": job_data.get("target_type"),
            "status": job_data.get("status"),
            "correlations": job_data.get("correlated_intel", {}).get("correlations", {}),
            "modules_executed": len(job_data.get("results", [])),
        }

        # Append highly-relevant findings
        key_findings = {}
        for res in job_data.get("results", []):
            mod_name = res.get("module")
            data = res.get("data", {})
            if "error" in data:
                continue

            # Filter huge outputs or focus on key metrics
            if mod_name == "Subdomain_Scanner":
                key_findings[mod_name] = f"Found {data.get('total_found', 0)} subdomains"
            elif mod_name == "Username_Checker":
                key_findings[mod_name] = f"Found on {data.get('found_on', 0)} platforms"
            elif mod_name == "Vision_Image_OSINT":
                key_findings[mod_name] = (
                    f"Faces: {data.get('faces_detected', 0)}, "
                    f"Similarity matches: {data.get('similarity_matches_total', 0)}, "
                    f"Reverse links: {data.get('reverse_image_results_total', 0)}, "
                    f"Entities: {len(data.get('entities', []))}"
                )
            elif mod_name == "GeoIP":
                key_findings[mod_name] = (
                    f"{data.get('city')}, {data.get('country')} (ISP: {data.get('isp')})"
                )
            else:
                # Truncate strings if too long
                string_data = str(data)[:200]
                key_findings[mod_name] = string_data

        condensed_data["key_findings"] = key_findings

        prompt = f"""
        You are an expert Cyber Intelligence Analyst.
        Review the following OSINT (Open Source Intelligence) scan results and provide a professional, concise Executive Summary.
        Highlight critical risks, interesting correlations, and general findings.
        Do not use markdown, keep it as clean text.

        Raw Data:
        {json.dumps(condensed_data, indent=2)}
        """

        payload = {"model": self.model, "prompt": prompt, "stream": False}

        logger.info(
            "Generating AI Summary for target %s via Ollama (%s)",
            condensed_data["target"],
            self.model,
        )

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(self.ollama_url, json=payload, timeout=60)
                if resp.status_code == 200:
                    data = resp.json()
                    summary = data.get("response", "")
                    return summary.strip()
                logger.error("Ollama API Error: %s", resp.text)
                return f"Failed to generate summary: HTTP {resp.status_code}"
            except httpx.ConnectError:
                logger.error(
                    "Could not connect to Ollama. Ensure Ollama is running locally on port 11434."
                )
                return "AI Summary is disabled. Ollama is not running."
            except Exception as exc:
                logger.error("AI Generation failed: %s", exc)
                return f"Error during AI Generation: {str(exc)}"


ai_reporter = AIReportGenerator()
