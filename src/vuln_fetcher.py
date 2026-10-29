import json
import os
import time

import requests


class VulnerabilityFetcher:
    """
    Stage 3: map each library version to known vulnerabilities (OSV.dev) and
    enrich every finding with CVSS (NVD), EPSS (FIRST) and KEV (CISA).

    Changes compared with the earlier version:
      * NVD API key is read from the environment variable NVD_API_KEY.
      * NVD requests are retried with a pause (HTTP 403 / 429 / 5xx or timeout).
      * Successful NVD scores are cached in data/nvd_cache.json so a re-run does
        not ask the NVD again for the same CVE.
      * Nodes without a resolved version are skipped (OSV would otherwise return
        vulnerabilities of every version of the library).
      * Each finding now carries its dependency "path".
      * The provenance records when the default CVSS value had to be used.
    """

    DEFAULT_CVSS = 6.5
    DEFAULT_EPSS = 0.05
    CACHE_PATH = os.path.join("data", "nvd_cache.json")

    def __init__(self):
        self.osv_api_url = "https://api.osv.dev/v1/query"
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.epss_api_url = "https://api.first.org/data/v1/epss"
        self.nvd_key = os.getenv("NVD_API_KEY")
        self.nvd_pause = 0.7 if self.nvd_key else 6.5   # stay under the NVD rate limit
        self.nvd_cache = self._load_cache()
        self._cisa_kev_cache, self._cisa_kev_metadata = self._load_cisa_kev()
        self.stats = {"cvss_default": 0, "cvss_nvd": 0, "cvss_cached": 0}
        if not self.nvd_key:
            print("[-] NVD_API_KEY is not set: NVD lookups will be slow and may fail.")

    # ------------------------------------------------------------------ cache
    def _load_cache(self):
        try:
            with open(self.CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_cache(self):
        try:
            os.makedirs("data", exist_ok=True)
            with open(self.CACHE_PATH, "w", encoding="utf-8") as f:
                json.dump(self.nvd_cache, f, indent=2)
        except Exception:
            pass

    # -------------------------------------------------------------------- KEV
    def _load_cisa_kev(self):
        kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        cve_map = {}
        try:
            response = requests.get(kev_url, timeout=15)
            if response.status_code == 200:
                for vuln in response.json().get("vulnerabilities", []):
                    cve_id = vuln.get("cveID")
                    if cve_id:
                        cve_map[cve_id] = {
                            "dateAdded": vuln.get("dateAdded", "Unknown"),
                            "reference": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}",
                        }
        except Exception:
            pass
        return cve_map, kev_url

    # ------------------------------------------------------------------ ids
    @staticmethod
    def _extract_cve_alias(vuln_data):
        vuln_id = vuln_data.get("id", "")
        if vuln_id.startswith("CVE-"):
            return vuln_id
        for alias in vuln_data.get("aliases", []):
            if alias.startswith("CVE-"):
                return alias
        return vuln_id

    # -------------------------------------------------------------------- NVD
    def _fetch_nvd_cvss(self, cve_id, retries=3):
        """Return (score, source_url) or (None, reason)."""
        if not cve_id or not cve_id.startswith("CVE-"):
            return None, "N/A (non-CVE advisory)"

        if cve_id in self.nvd_cache:
            self.stats["cvss_cached"] += 1
            score, link = self.nvd_cache[cve_id]
            return score, link

        headers = {"User-Agent": "AcademicSCA-Pipeline/1.0"}
        if self.nvd_key:
            headers["apiKey"] = self.nvd_key

        reason = "NVD request failed"
        for attempt in range(retries):
            try:
                response = requests.get(
                    f"{self.nvd_api_url}?cveId={cve_id}", headers=headers, timeout=20
                )
                if response.status_code == 200:
                    vulns = response.json().get("vulnerabilities", [])
                    if vulns:
                        metrics = vulns[0].get("cve", {}).get("metrics", {})
                        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                            if metrics.get(key):
                                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                                if score is not None:
                                    link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                                    self.nvd_cache[cve_id] = [float(score), link]
                                    self.stats["cvss_nvd"] += 1
                                    return float(score), link
                    reason = "NVD returned no CVSS score for this CVE"
                    break                      # definitive answer, no retry
                reason = f"NVD HTTP {response.status_code}"
            except Exception as e:
                reason = f"NVD error: {type(e).__name__}"
            time.sleep((attempt + 1) * 6)      # back off before the next attempt
        return None, reason

    # ------------------------------------------------------------------- EPSS
    def _fetch_epss(self, cve_id):
        if not cve_id or not cve_id.startswith("CVE-"):
            return self.DEFAULT_EPSS, "N/A (non-CVE baseline)"
        for attempt in range(2):
            try:
                response = requests.get(f"{self.epss_api_url}?cve={cve_id}", timeout=10)
                if response.status_code == 200:
                    data = response.json().get("data", [])
                    if data:
                        return float(data[0].get("epss", 0.0)), f"https://api.first.org/data/v1/epss?cve={cve_id}"
            except Exception:
                pass
            time.sleep(2)
        return self.DEFAULT_EPSS, "FIRST.org API unreachable (baseline fallback)"

    # --------------------------------------------------------------- findings
    def fetch_vulnerabilities(self, node):
        if not node.get("version"):
            return []                          # unresolved version: do not guess

        payload = {
            "version": node["version"],
            "package": {"ecosystem": node["ecosystem"], "name": node["name"]},
        }
        findings = []
        try:
            response = requests.post(self.osv_api_url, json=payload, timeout=20)
            if response.status_code != 200:
                return findings
            for vuln in response.json().get("vulns", []):
                cve_id = self._extract_cve_alias(vuln)

                cvss, cvss_source = self._fetch_nvd_cvss(cve_id)
                if cvss is None:
                    cvss = self.DEFAULT_CVSS
                    cvss_source = f"DEFAULT {self.DEFAULT_CVSS} used ({cvss_source}); OSV advisory {vuln.get('id')}"
                    self.stats["cvss_default"] += 1
                    time.sleep(self.nvd_pause)

                epss, epss_source = self._fetch_epss(cve_id)

                is_kev = cve_id in self._cisa_kev_cache
                kev_source = (self._cisa_kev_cache[cve_id]["reference"]
                              if is_kev else "CISA KEV catalogue (not listed)")

                findings.append({
                    "name": node["name"],
                    "version": node["version"],
                    "depth": node["depth"],
                    "path": node.get("path", []),
                    "cve": cve_id,
                    "cvss": cvss,
                    "epss": epss,
                    "kev": is_kev,
                    "provenance": {
                        "cvss_source_url": cvss_source,
                        "epss_source_url": epss_source,
                        "kev_source_url": kev_source,
                        "osv_advisory_id": vuln.get("id", "Unknown"),
                    },
                    "summary": vuln.get("details", "No summary provided.")[:180],
                })
                self._save_cache()
        except Exception as e:
            print(f"[-] Error querying OSV.dev for {node['name']}: {e}")
        return findings