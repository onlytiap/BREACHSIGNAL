#!/usr/bin/env python3
"""Build derived artefacts from data/incidents.json (the single source of truth).

Generates:
  data/stats.json      aggregates + external benchmarks
  data/incidents.csv   flat export
  data/feed.xml        RSS 2.0
  site/data.js         inline payload for the static site
  docs/SOURCES.md      every source URL, grouped by incident

Run after any edit to data/incidents.json:   python3 build.py
"""
from __future__ import annotations

import csv
import io
import json
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
SITE = ROOT / "site"
DOCS = ROOT / "docs"
CLI = ROOT / "cli" / "bsignal.py"

BASE_URL = "https://onlytiap.github.io/BREACHSIGNAL"

# --------------------------------------------------------------------- benchmarks
# Figures from published, fixed-methodology reports. These are NOT derived from
# incidents.json; they are the external context the site cites alongside it.
BENCHMARKS = {
    "itrc": {
        "source": "Identity Theft Resource Center, Annual Data Breach Report 2025 (published Jan 2026)",
        "url": "https://www.idtheftcenter.org/",
        "compromises": {"2023": 3205, "2024": 3158, "2025": 3322},
        "victim_notices_2024": 1350000000,
        "individuals_compromised_2024_us": 1700000000,
        "growth_2025_vs_2024_pct": 5,
        "growth_2025_vs_5yr_prior_pct": 79,
        "top_victim_notices_2025": [
            {"org": "PowerSchool", "notices": 71900000},
            {"org": "AT&T (2021 data, 2025 repo)", "notices": 43989219},
            {"org": "Aflac", "notices": 22650000},
            {"org": "Prosper Funding", "notices": 17600000},
            {"org": "Conduent Business Services", "notices": 14791500},
        ],
        "note": "ITRC counts only publicly reported US compromises. 2025 was the largest annual total in the ITRC's 20-year history.",
    },
    "ibm": {
        "source": "IBM Cost of a Data Breach Report 2025 (Ponemon Institute; 600 organisations, 17 industries, 16 countries)",
        "url": "https://www.ibm.com/reports/data-breach",
        "g2024": 4880000, "g2025": 4440000,
        "us2024": 9360000, "us2025": 10220000,
        "healthcare": 7420000, "healthcare_years": 14,
        "financial_services": 5560000,
        "lifecycle_2024": 258, "lifecycle_2025": 241,
        "identify_days": 181, "contain_days": 60,
        "cost_per_record_2025": 160,
        "phishing_pct": 16, "phishing_cost": 4800000,
        "insider_cost": 4920000,
        "shadow_ai_pct": 20, "shadow_ai_cost": 670000, "shadow_ai_pii_pct": 65,
        "increase_spend_pct": 49, "increase_spend_prior": 63,
        "note": "Global average fell 9% in 2025, the first decline in five years, while the US average rose 9.2% to a fifteenth consecutive record.",
    },
    "verizon": {
        "source": "Verizon Data Breach Investigations Report 2025",
        "url": "https://www.verizon.com/business/resources/reports/dbir/",
        "incidents": 22052, "breaches": 12195,
        "third_party_pct": 30, "ransomware_pct": 44,
    },
    "wiz": {
        "source": "Wiz Research, 'AI companies are leaking secrets on GitHub' (Nov 2025)",
        "url": "https://www.itpro.com/security/github-is-awash-with-leaked-ai-company-secrets-api-keys-tokens-and-credentials-were-all-found-out-in-the-open",
        "companies": 50, "pct_leaked": 65, "pct_no_response": 50,
        "valuation": 400000000000,
        "notable": "One AI-50 company leaked a Hugging Face token inside a DELETED FORK granting access to ~1,000 private models, plus Weights & Biases keys exposing private-model training data.",
    },
    "palo_alto": {
        "source": "Palo Alto Networks research (early 2025)",
        "genai_dataloss_growth": "more than doubled in early 2025",
        "ai_share_of_saas_dataloss_pct": 14,
    },
    "wayback_copilot": {
        "source": "'Wayback Copilot' research (Feb 2025)",
        "url": "https://thehackernews.com/2025-02-12000-api-keys-and-passwords-found-in.html",
        "live_secrets": 11946, "archived_repos": 20580, "organisations": 16290,
        "private_tokens": 300,
    },
}

CSV_FIELDS = ["id", "title", "org", "sector", "date", "year", "category", "confidence",
              "attack_vector", "records_affected", "records_note", "orgs_affected",
              "data_types", "cve", "threat_actor", "disclosed", "disclosure_delay_days",
              "financial_impact_usd", "ai_angle", "why_it_matters", "in_window", "sources"]


def flatten(v):
    if isinstance(v, list):
        return "; ".join(str(x) for x in v)
    if v is None:
        return ""
    return str(v).replace("\n", " ").strip()


def build():
    db = json.loads((DATA / "incidents.json").read_text(encoding="utf-8"))
    inc = db["incidents"]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    db["generated_at"] = today

    # ---- validate first; refuse to publish a broken ledger
    rc = subprocess.run([sys.executable, str(CLI), "validate"], cwd=ROOT).returncode
    if rc != 0:
        sys.exit("validation failed — fix data/incidents.json before building")

    inw = [i for i in inc if i.get("in_window", True)]

    # ---- stats.json
    by_year = Counter(i["year"] for i in inw)
    rec_year = defaultdict(int)
    COMPILE = {"moab-2024", "rockyou2024", "credential-crisis-2025", "credential-dump-24b-2026"}
    for i in inw:
        if i["id"] not in COMPILE:
            rec_year[i["year"]] += i.get("records_affected") or 0

    stats = {
        "dataset": "BREACHSIGNAL / stats",
        "generated_at": today,
        "coverage": db["coverage"],
        "derived_from": "data/incidents.json — regenerate with `python3 build.py`",
        "totals": {
            "incidents": len(inc),
            "incidents_in_window": len(inw),
            "incidents_with_ai_angle": sum(1 for i in inc if i.get("ai_angle")),
            "incidents_ai_category": sum(1 for i in inc if i["category"] == "ai_specific"),
            "never_publicly_disclosed": sum(1 for i in inc if i.get("disclosed") is False),
            "attacker_claimed": sum(1 for i in inc if i["confidence"] == "attacker_claim"),
            "distinct_source_urls": len({u for i in inc for u in i["sources"]}),
            "total_citations": sum(len(i["sources"]) for i in inc),
            "records_affected_sum": sum(i.get("records_affected") or 0 for i in inc),
            "records_sum_warning": (
                "MEANINGLESS AS A TOTAL. Credential compilations (MOAB, RockYou2024, the 2025 "
                "credential crisis, the June 2026 dump) repackage each other and the primary "
                "breaches they were built from. Use per-year or per-incident figures. "
                "See docs/METHODOLOGY.md section 3."),
            "records_by_year_excluding_compilations": {str(k): v for k, v in sorted(rec_year.items())},
            "priced_financial_impact_usd": sum(i.get("financial_impact_usd") or 0 for i in inc),
        },
        "by_year": dict(sorted(by_year.items())),
        "by_category": dict(Counter(i["category"] for i in inc).most_common()),
        "by_confidence": dict(Counter(i["confidence"] for i in inc).most_common()),
        "by_sector": dict(Counter(i["sector"].split("/")[0].strip() for i in inc).most_common()),
        "by_threat_actor": dict(Counter(
            i["threat_actor"] for i in inc
            if not i["threat_actor"].startswith(("unattributed", "n/a"))
        ).most_common()),
        "top_15_by_records": [
            {"id": i["id"], "title": i["title"], "org": i["org"], "year": i["year"],
             "records": i["records_affected"], "confidence": i["confidence"]}
            for i in sorted([x for x in inc if x.get("records_affected")],
                            key=lambda x: -x["records_affected"])[:15]
        ],
        "longest_disclosure_delays": [
            {"id": i["id"], "org": i["org"], "days": i["disclosure_delay_days"]}
            for i in sorted([x for x in inc if x.get("disclosure_delay_days")],
                            key=lambda x: -x["disclosure_delay_days"])
        ],
        "largest_financial_impacts": [
            {"id": i["id"], "title": i["title"], "usd": i["financial_impact_usd"]}
            for i in sorted([x for x in inc if x.get("financial_impact_usd")],
                            key=lambda x: -x["financial_impact_usd"])
        ],
        "never_disclosed": [
            {"id": i["id"], "title": i["title"], "org": i["org"], "confidence": i["confidence"]}
            for i in inc if i.get("disclosed") is False
        ],
        "ai_relevant": [i["id"] for i in inc if i.get("ai_angle") or i["category"] == "ai_specific"],
        "benchmarks": BENCHMARKS,
    }
    (DATA / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")

    # ---- incidents.csv
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_FIELDS)
    for i in sorted(inc, key=lambda x: x["date"]):
        w.writerow([flatten(i.get(f)) for f in CSV_FIELDS])
    (DATA / "incidents.csv").write_text(buf.getvalue(), encoding="utf-8")

    # ---- feed.xml
    subprocess.run([sys.executable, str(CLI), "feed", "--limit", "200",
                    "--base", BASE_URL, "--out", str(DATA / "feed.xml")],
                   cwd=ROOT, check=True)

    # ---- site/data.js
    payload = {
        "dataset": "BREACHSIGNAL",
        "version": db.get("version", "1.0.0"),
        "generated_at": today,
        "coverage": db["coverage"],
        "confidence_levels": db["confidence_levels"],
        "incidents": inc,
        "benchmarks": BENCHMARKS,
    }
    js = ("// BREACHSIGNAL — generated from data/incidents.json by build.py. Do not edit by hand.\n"
          "window.BREACHSIGNAL_DATA = " + json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + ";\n")
    (SITE / "data.js").write_text(js, encoding="utf-8")

    # ---- docs/SOURCES.md
    urls, seen = [], set()
    for i in inc:
        for s in i["sources"]:
            urls.append((i["id"], s)); seen.add(s)
    lines = [
        "# Sources",
        "",
        f"**{len(seen)} distinct URLs · {len(urls)} citations across {len(inc)} incidents.**",
        "",
        "Every URL below was used to construct at least one record in `data/incidents.json`.",
        "Entries are grouped by incident id. If a source dies or goes behind a paywall, the",
        "incident stays only if another source still supports it.",
        "",
    ]
    cur = None
    for iid, s in urls:
        if iid != cur:
            lines.append(f"\n## `{iid}`"); cur = iid
        lines.append(f"- {s}" + (" _(also cited elsewhere)_" if urls.count((iid, s)) else ""))
    lines += [
        "", "---", "",
        "## Primary / institutional sources used repeatedly",
        "",
        "| Source | What it provides | URL |",
        "|---|---|---|",
        "| Identity Theft Resource Center | Annual US compromise counts and victim-notice tallies — the only genuinely additive measure in this field | https://www.idtheftcenter.org/ |",
        "| IBM / Ponemon | Cost of a Data Breach, annual, fixed methodology | https://www.ibm.com/reports/data-breach |",
        "| Verizon DBIR | Attack-vector breakdown across ~22k incidents | https://www.verizon.com/business/resources/reports/dbir/ |",
        "| CISA | Advisories and IOCs for the mass-exploitation campaigns | https://www.cisa.gov/news-events/cybersecurity-advisories |",
        "| HHS OCR breach portal | Statutory healthcare breach notifications | https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf |",
        "| Have I Been Pwned | Independent breach index; used by `cli/bsignal.py check-email` | https://haveibeenpwned.com/ |",
        "| UK ICO | Enforcement actions and reprimands | https://ico.org.uk/action-weve-taken/enforcement-and-regulatory-action/ |",
        "| Garante (Italy) | OpenAI €15M sanction; DeepSeek data-handling inquiry | https://www.garanteprivacy.it/ |",
        "| CNIL (France) | Clearview AI sanction | https://www.cnil.fr/en |",
        "| Wiz Research | DeepSeek exposure, AI-50 secrets study, Hugging Face token research | https://www.wiz.io/blog |",
        "| Mandiant / Google Threat Intelligence | UNC5537, UNC6240 attribution | https://www.mandiant.com/ |",
        "| OpenAI / Hugging Face | Joint disclosure of the July 2026 agent incident | https://openai.com/index/hugging-face-incident-and-the-road-ahead/ |",
        "",
        "## Why some sources are secondary",
        "",
        "There is no primary source for most of these events. Companies do not publish breach",
        "postmortems; regulators publish notices without narrative; attackers publish claims",
        "without evidence. Where a first-party document exists — an SEC 8-K, an HHS OCR filing,",
        "a Garante sanction, a company's own incident blog post — it is cited first and the",
        "incident's `confidence` reflects it. Where it does not, the confidence field says so.",
        "",
        "## Correction policy",
        "",
        "This dataset is wrong somewhere. That is unavoidable at this scale. If you find an error —",
        "a wrong date, an inflated record count, a mis-attributed threat actor, a dead link — open",
        "an issue or a pull request with a source. Corrections merge on evidence, not on reputation.",
        "See `docs/METHODOLOGY.md`.",
        "",
    ]
    (DOCS / "SOURCES.md").write_text("\n".join(lines), encoding="utf-8")

    (DATA / "incidents.json").write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"built {today}:")
    print(f"  data/stats.json      {len(inc)} incidents, {stats['totals']['distinct_source_urls']} sources")
    print(f"  data/incidents.csv   {len(inc)+1} rows")
    print(f"  data/feed.xml")
    print(f"  site/data.js         {len(js)//1024} KB")
    print(f"  docs/SOURCES.md      {len(seen)} URLs")


if __name__ == "__main__":
    build()
