
# LLM-Driven Transitive Dependency Risk Analysis for Java Applications

A functional prototype implementing an autonomous, path-aware Software Composition Analysis (SCA) pipeline that combines transitive dependency graph resolution, live vulnerability intelligence, a custom mathematical prioritization formula, and Google Gemini cognitive explanations.

## Project Structure
```text
JavaSCA_Analyzer/
│
├── target_project/          # Sample Java build manifest (pom.xml)
│   └── pom.xml
│
├── src/                     # Core pipeline modules
│   ├── __init__.py
│   ├── parser.py            # Manifest parsing & graph depth extraction
│   ├── vuln_fetcher.py      # Live OSV.dev API & threat enrichment
│   ├── scorer.py            # Custom TRPS mathematical risk formula
│   ├── llm_analyzer.py      # Google Gemini API integration (JSON mode)
│   └── validator.py         # Validation engine & report renderer
│
├── data/                    # Generated output reports
│   └── final_risk_report.md
│
├── main.py                  # End-to-end pipeline orchestrator
└── requirements.txt         # Project dependencies