import collections
import datetime
import json
import os

FIND = os.path.join("data", "raw_findings.json")
LLM = os.path.join("data", "raw_llm_response.json")


def stamp(path):
    t = datetime.datetime.fromtimestamp(os.path.getmtime(path))
    return t.strftime("%d-%m-%Y %H:%M:%S")


d = json.load(open(FIND, encoding="utf-8"))
print("raw_findings.json last written:", stamp(FIND), "| now:", datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S"))
print("findings:", len(d))
print("distinct CVEs:", len({f["cve"] for f in d}))
print("distinct libraries with a finding:", len({f["name"] for f in d}))
print("depth -> findings:", sorted(collections.Counter(f["depth"] for f in d).items()))
print("default CVSS used:", sum("DEFAULT" in f["provenance"]["cvss_source_url"] for f in d))
print("default EPSS used:", sum("baseline" in f["provenance"]["epss_source_url"].lower() for f in d))
print("KEV-listed findings:", sum(bool(f["kev"]) for f in d))
print("with path:", sum(bool(f.get("path")) for f in d))
print("null version:", sum(f.get("version") is None for f in d))

print("\nTop 10 by TRPS (name, CVE, depth, TRPS, default-CVSS?):")
top = sorted(d, key=lambda x: -x["trps_score"])[:10]
for i, f in enumerate(top, 1):
    flag = "DEFAULT CVSS" if "DEFAULT" in f["provenance"]["cvss_source_url"] else ""
    print(i, f["name"].split(":")[-1], f["cve"], f["depth"], f["trps_score"], flag)

print("\n--- LLM output ---")
if not os.path.exists(LLM):
    print("raw_llm_response.json not found")
else:
    r = json.load(open(LLM, encoding="utf-8"))
    print("raw_llm_response.json last written:", stamp(LLM))
    print("entries:", len(r) if isinstance(r, list) else "not a list")
    if isinstance(r, list) and r:
        fallback = sum("fallback" in str(x.get("plain_language_explanation", "")).lower() for x in r)
        print("entries that look like the offline fallback template:", fallback)
        scores = [x.get("trps_score", 0) for x in r]
        same = all(scores[i] >= scores[i + 1] for i in range(len(scores) - 1))
        print("LLM order is non-increasing in TRPS (i.e. same as TRPS order):", same)
        if not same:
            print("LLM order (rank, CVE, TRPS) where it differs from TRPS order:")
            ideal = sorted(range(len(r)), key=lambda i: -scores[i])
            for pos, i in enumerate(ideal):
                if i != pos:
                    print("  ", r[pos].get("rank"), r[pos].get("cve"), r[pos].get("trps_score"))
        paths_in_text = sum("path" in str(x.get("plain_language_explanation", "")).lower() for x in r)
        print("explanations that mention the path:", paths_in_text)