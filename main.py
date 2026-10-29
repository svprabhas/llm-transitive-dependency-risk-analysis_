import os
import sys
import json
import subprocess
import tempfile
import shutil
from src.parser import DependencyParser
from src.vuln_fetcher import VulnerabilityFetcher
from src.scorer import RiskScorer
from src.llm_analyzer import LLMAnalyzer
from src.validator import ReportValidator

def resolve_pom_target(target_arg):
    """
    Intelligently resolves user input:
    1. If a Git URL is provided, clones it into a secure unique temp directory and finds pom.xml.
    2. If a local directory path is provided, searches for pom.xml inside it.
    3. If a direct pom.xml file path is provided, uses it.
    4. If nothing is provided, falls back to the pre-existing default sample pom.xml.
    """
    if not target_arg:
        default_path = os.path.join("target_project", "pom.xml")
        print(f"[+] No target provided. Using pre-existing default manifest: {default_path}")
        return default_path

    # Check if input is a remote Git repository URL
    if target_arg.startswith("http://") or target_arg.startswith("https://") or target_arg.endswith(".git"):
        clone_dir = tempfile.mkdtemp(prefix="java_sca_repo_")
        print(f"[+] Cloning remote repository into temporary workspace...")
        try:
            subprocess.run(["git", "clone", "--depth", "1", target_arg, clone_dir], check=True, capture_output=True)
            target_arg = clone_dir
        except subprocess.CalledProcessError as e:
            print(f"[-] Git clone failed: {e.stderr.decode('utf-8', errors='ignore')}")
            sys.exit(1)
        except FileNotFoundError:
            print("[-] Error: 'git' command not found. Please ensure Git is installed on your system.")
            sys.exit(1)

    # If input is a directory, search for pom.xml recursively inside it
    if os.path.isdir(target_arg):
        pom_found = None
        for root, dirs, files in os.walk(target_arg):
            if "pom.xml" in files:
                pom_found = os.path.join(root, "pom.xml")
                break
        if pom_found:
            print(f"[+] Located build manifest: {pom_found}")
            return pom_found
        else:
            raise FileNotFoundError(f"[-] No 'pom.xml' found inside directory: {target_arg}")

    # If input is a direct file path
    if os.path.isfile(target_arg):
        return target_arg

    raise FileNotFoundError(f"[-] Could not resolve target path or URL: {target_arg}")

def run_pipeline(target_arg=None):
    print("[+] Starting LLM-Driven Transitive Dependency Risk Analysis Pipeline...")

    # Resolve target pom.xml dynamically
    pom_path = resolve_pom_target(target_arg)

    # Stage 1 & 2: Parse build manifest & resolve graph
    print(f"[+] Stage 1 & 2: Parsing build file and resolving graph from {pom_path}...")
    parser = DependencyParser(pom_path)
    dependency_graph = parser.resolve_transitive_graph()
    print(f"[+] Resolved {len(dependency_graph)} dependency nodes in tree.")

    # Stage 3: Fetch vulnerabilities & enrich data (OSV, NVD, FIRST.org EPSS, CISA KEV with provenance)
    print("[+] Stage 3: Querying OSV.dev / NVD APIs and enriching threat telemetry with provenance...")
    fetcher = VulnerabilityFetcher()
    all_findings = []
    for node in dependency_graph:
        vulns = fetcher.fetch_vulnerabilities(node)
        all_findings.extend(vulns)

    print(f"[+] Discovered {len(all_findings)} raw vulnerability matches.")

    # Stage 4A: Apply Custom TRPS Mathematical Formula (Without pre-sorting)
    print("[+] Stage 4A: Computing custom Transitive Risk Priority Scores (TRPS)...")
    scored_findings = []
    for finding in all_findings:
        score = RiskScorer.calculate_trps(
            cvss=finding["cvss"],
            epss=finding["epss"],
            kev=finding["kev"],
            depth=finding["depth"]
        )
        finding["trps_score"] = score
        scored_findings.append(finding)

    # Stage 4B: LLM Cognitive Layer Analysis (Unsorted findings passed to LLM for path-aware/depth-weighted cognitive re-ranking)
    print("[+] Stage 4B: Invoking Google Gemini API for path-aware cognitive risk ranking and triage...")
    llm = LLMAnalyzer()
    llm_results = llm.analyze_findings(scored_findings)

    # --- Export Raw Outputs for Auditability & Submission ---
    os.makedirs("data", exist_ok=True)

    findings_store_path = os.path.join("data", "raw_findings.json")
    with open(findings_store_path, "w", encoding="utf-8") as f:
        json.dump(scored_findings, f, indent=2)

    llm_response_path = os.path.join("data", "raw_llm_response.json")
    with open(llm_response_path, "w", encoding="utf-8") as f:
        json.dump(llm_results, f, indent=2)
    # ---------------------------------------------------------

    # Stage 5: Validation & Report Generation
    print("[+] Stage 5: Validating assertions and compiling final output report...")
    final_report_markdown = ReportValidator.validate_and_render(llm_results, scored_findings)

    report_path = os.path.join("data", "final_risk_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(final_report_markdown)

    print(f"[+] Pipeline completed successfully! Report generated at: {report_path}")

if __name__ == "__main__":
    user_target = sys.argv[1] if len(sys.argv) > 1 else None
    run_pipeline(user_target)