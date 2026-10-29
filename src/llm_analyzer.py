import os
import json
import time
from google import genai
from google.genai import types


class LLMAnalyzer:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")

        if api_key:
            self.client = genai.Client(api_key=api_key)
        else:
            raise ValueError(
                "[-] Gemini API Key not found! Please set DIRECT_API_KEY at the top of src/llm_analyzer.py"
            )

    def analyze_findings(self, scored_findings):
        if not scored_findings:
            return scored_findings

        prompt = f"""
        You are an expert Application Security and Software Supply Chain AI Architect.
        You are given an unsorted list of transitive dependency vulnerabilities extracted from a Java build manifest.

        Each finding includes its base metrics, calculated TRPS score, graph depth, and full hierarchical dependency path array (e.g., ["root-app", "spring-boot-starter", "snakeyaml"]).

        Unsorted Findings Data:
        {json.dumps(scored_findings, indent=2)}

        CRITICAL TASK:
        Perform a path-aware and depth-weighted cognitive risk ranking. Do not blindly trust numerical scores. 
        Evaluate the dependency graph blast radius:
        1. Analyze the exact 'path' array and graph 'depth' for each item. 
        2. Transitive dependencies sitting deeper in critical application pathways or sharing high-risk parent nodes must be cognitively evaluated for real-world exploitation likelihood.
        3. Re-rank the findings autonomously based on this deep path-contextual reasoning.

        Return a valid JSON array containing the prioritized list of vulnerabilities.
        For each entry, provide:
        1. "rank": integer order (1 to N based on your cognitive path-aware ranking)
        2. "library": library name and version
        3. "cve": CVE identifier
        4. "trps_score": the numerical score
        5. "plain_language_explanation": clear, deep explanation detailing how the dependency's graph depth and specific 'path' vector impact the application's risk surface.
        6. "remediation_step": step-by-step developer instruction to fix it safely.
        """

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.client.models.generate_content(
                    model='gemini-3.8-flash',
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.1,
                    ),
                )
                return json.loads(response.text)
            except Exception as e:
                err_str = str(e)
                if "503" in err_str or "UNAVAILABLE" in err_str or "high demand" in err_str:
                    if attempt < max_retries - 1:
                        sleep_time = (attempt + 1) * 2 # 2s, 4s backoff
                        print(f"[-] Gemini API 503 Unavailable (Attempt {attempt+1}/{max_retries}). Retrying in {sleep_time}s...")
                        time.sleep(sleep_time)
                        continue

                print(f"[-] Gemini API Warning during cognitive ranking: {e}")
                break

        # Fallback path-aware sort if all retries fail
        print("[-] Falling back to algorithmic depth-weighted sort.")
        fallback_sorted = sorted(
            scored_findings,
            key=lambda x: (x.get("trps_score", 0.0) / (x.get("depth", 1) * 0.1 + 1.0)),
            reverse=True
        )

        fallback_results = []
        for i, f in enumerate(fallback_sorted, 1):
            lib_name = f.get("name", "Unknown Library")
            lib_ver = f.get("version", "Latest")
            depth = f.get("depth", 1)
            fallback_results.append({
                "rank": i,
                "library": f"{lib_name} (v{lib_ver})",
                "cve": f.get("cve", "GHSA-Vulnerability-Match"),
                "trps_score": f.get("trps_score", 0.0),
                "plain_language_explanation": f"Path-aware fallback analysis: Identified vulnerability in {lib_name} at graph depth {depth} along path {f.get('path', [])}.",
                "remediation_step": f"Upgrade {lib_name} to a secure, vendor-patched version in your build configuration."
            })
        return fallback_results