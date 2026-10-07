#!/usr/bin/env python3
"""
bsignal — the BREACHSIGNAL command line.

A ledger of data breaches, AI industry secrecy failures and training-data theft,
2023 to present.

  python3 cli/bsignal.py stats
  python3 cli/bsignal.py list --year 2025 --category supply_chain
  python3 cli/bsignal.py list --min-records 100000000
  python3 cli/bsignal.py show deepseek-clickhouse-2025
  python3 cli/bsignal.py search "snowflake"
  python3 cli/bsignal.py ai
  python3 cli/bsignal.py timeline
  python3 cli/bsignal.py validate
  python3 cli/bsignal.py export --format csv
  python3 cli/bsignal.py check-email you@example.com          # Have I Been Pwned
  python3 cli/bsignal.py pwned-search openai                 # HIBP breach search
  python3 cli/bsignal.py feed > data/feed.xml                # regenerate the RSS feed

No dependencies beyond the standard library. Python 3.8+.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------- paths

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
INCIDENTS = DATA / "incidents.json"
STATS = DATA / "stats.json"

VERSION = "1.0.0"

# --------------------------------------------------------------------------- style

class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GRN = "\033[32m"; YEL = "\033[33m"
    BLU = "\033[34m"; MAG = "\033[35m"; CYN = "\033[36m"
    GRAY = "\033[90m"

    @classmethod
    def disable(cls):
        for k in list(vars(cls)):
            if k.isupper():
                setattr(cls, k, "")


def _tty() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"


if not _tty():
    C.disable()

CONF_COLOUR = {
    "regulatory_filing": C.GRN,
    "victim_disclosure": C.GRN,
    "security_research": C.BLU,
    "journalism": C.YEL,
    "attacker_claim": C.RED,
}
CONF_MARK = {
    "regulatory_filing": "REG",
    "victim_disclosure": "DIS",
    "security_research": "RES",
    "journalism": "PRS",
    "attacker_claim": "CLM",
}

# --------------------------------------------------------------------------- data

def load():
    if not INCIDENTS.exists():
        sys.exit(f"error: {INCIDENTS} not found")
    return json.loads(INCIDENTS.read_text(encoding="utf-8"))


def incidents(db, **filters):
    out = db["incidents"]
    if filters.get("year"):
        out = [i for i in out if i["year"] in filters["year"]]
    if filters.get("category"):
        out = [i for i in out if i["category"] in filters["category"]]
    if filters.get("confidence"):
        out = [i for i in out if i["confidence"] in filters["confidence"]]
    if filters.get("sector"):
        s = filters["sector"].lower()
        out = [i for i in out if s in i["sector"].lower()]
    if filters.get("q"):
        q = filters["q"].lower()
        out = [i for i in out if q in json.dumps(i, ensure_ascii=False).lower()]
    if filters.get("ai"):
        out = [i for i in out if i.get("ai_angle") or i["category"] == "ai_specific"]
    if filters.get("min_records") is not None:
        out = [i for i in out if (i.get("records_affected") or 0) >= filters["min_records"]]
    if filters.get("undisclosed"):
        out = [i for i in out if i.get("disclosed") is False]
    if filters.get("in_window_only"):
        out = [i for i in out if i.get("in_window", True)]
    return out


def human(n):
    """1500000000 -> '1.5B'"""
    if n is None:
        return "—"
    n = float(n)
    for div, suf in ((1e12, "T"), (1e9, "B"), (1e6, "M"), (1e3, "K")):
        if abs(n) >= div:
            v = n / div
            return f"{v:.1f}{suf}".replace(".0", "")
    return str(int(n))


def money(n):
    if n is None:
        return "—"
    if n >= 1e9:
        return f"${n/1e9:.2f}B"
    if n >= 1e6:
        return f"${n/1e6:.1f}M"
    if n >= 1e3:
        return f"${n/1e3:.0f}K"
    return f"${n}"


def wrap(text, width=100, indent=""):
    return textwrap.fill(text, width=width, initial_indent=indent,
                         subsequent_indent=indent, break_long_words=False)


# --------------------------------------------------------------------------- commands

def cmd_list(db, a):
    rows = incidents(
        db,
        year=a.year, category=a.category, confidence=a.confidence,
        sector=a.sector, q=a.query, ai=a.ai, min_records=a.min_records,
        undisclosed=a.undisclosed,
    )
    sort = a.sort
    rows.sort(key=lambda i: {
        "records": -(i.get("records_affected") or 0),
        "date": i["date"],
        "year": (i["year"], i["date"]),
        "impact": -(i.get("financial_impact_usd") or 0),
        "org": i["org"].lower(),
    }[sort])
    if a.limit:
        rows = rows[: a.limit]

    if a.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return

    if not rows:
        print("no incidents match those filters.")
        return

    hdr = f"{'DATE':<11}{'RECORDS':>9}  {'CNF':<4}{'ORGANISATION':<38}{'CATEGORY':<15}TITLE"
    print(f"\n{C.BOLD}{hdr}{C.RESET}")
    print(C.GRAY + "─" * min(len(hdr) + 30, 150) + C.RESET)
    for i in rows:
        cnf = CONF_MARK[i["confidence"]]
        ccol = CONF_COLOUR[i["confidence"]]
        org = (i["org"][:36] + "…") if len(i["org"]) > 37 else i["org"]
        title = i["title"][:52]
        flag = f" {C.RED}⚑{C.RESET}" if i["confidence"] == "attacker_claim" else ""
        nd = f" {C.YEL}◌{C.RESET}" if i.get("disclosed") is False else ""
        ai = f" {C.MAG}✦{C.RESET}" if (i.get("ai_angle") or i["category"] == "ai_specific") else ""
        print(f"{C.DIM}{i['date']:<11}{C.RESET}{C.BOLD}{human(i.get('records_affected')):>9}{C.RESET}  "
              f"{ccol}{cnf:<4}{C.RESET}{org:<38}{i['category']:<15}{title}{flag}{nd}{ai}")

    print(C.GRAY + f"\n{len(rows)} incident(s)   "
                   f"⚑ attacker-claimed   ◌ never publicly disclosed   ✦ AI-relevant   "
                   f"CNF: REG=regulatory DIS=disclosure RES=research PRS=press CLM=claim"
                   + C.RESET + "\n")


def cmd_show(db, a):
    want = a.id.lower()
    hit = [i for i in db["incidents"]
           if i["id"].lower() == want or want in i["id"].lower()
           or want in i["title"].lower() or want in i["org"].lower()]
    if not hit:
        sys.exit(f"error: no incident matching '{a.id}'. Try: bsignal.py search {a.id}")
    if len(hit) > 1 and not a.first:
        print("multiple matches — be more specific, or pass --first:")
        for i in hit:
            print(f"  {i['id']:<38}{i['title']}")
        return
    i = hit[0]

    if a.json:
        print(json.dumps(i, indent=2, ensure_ascii=False))
        return

    W = 100
    print()
    print(C.BOLD + "═" * W + C.RESET)
    print(C.BOLD + f" {i['title']}" + C.RESET)
    print(C.GRAY + f" id: {i['id']}" + C.RESET)
    print(C.BOLD + "═" * W + C.RESET)

    def row(k, v):
        if v in (None, "", [], {}):
            return
        print(f"{C.CYN}{k:<18}{C.RESET}{v}")

    row("Organisation", i["org"])
    row("Sector", i["sector"])
    row("Date", i["date"] + ("" if i.get("in_window", True) else f"  {C.YEL}(outside 2023+ window){C.RESET}"))
    row("Category", i["category"])
    cc = CONF_COLOUR[i["confidence"]]
    row("Confidence", f"{cc}{i['confidence']}{C.RESET}  {C.GRAY}{db['confidence_levels'][i['confidence']]}{C.RESET}")
    row("Records", (f"{C.BOLD}{human(i.get('records_affected'))}{C.RESET} "
                   f"{C.GRAY}({i['records_affected']:,}){C.RESET}") if i.get("records_affected") else None)
    if i.get("records_note"):
        print(wrap(i["records_note"], W - 2, C.GRAY + "                   " + C.RESET))
    row("Organisations", i.get("orgs_affected"))
    row("Threat actor", i["threat_actor"])
    row("CVE", ", ".join(i["cve"]) if i.get("cve") else None)
    row("Financial impact", money(i.get("financial_impact_usd")) if i.get("financial_impact_usd") else None)
    if i.get("disclosure_delay_days"):
        row("Disclosure delay", f"{i['disclosure_delay_days']} days")
    row("Publicly disclosed", {True: "yes", False: f"{C.RED}NO — never publicly disclosed{C.RESET}"}.get(i.get("disclosed")))

    print()
    print(f"{C.BOLD}Attack vector{C.RESET}")
    print(wrap(i["attack_vector"], W - 2, "  "))

    print()
    print(f"{C.BOLD}Data exposed{C.RESET}")
    print(wrap("· " + "  · ".join(i["data_types"]), W - 2, "  "))

    if i.get("aftermath"):
        print()
        print(f"{C.BOLD}Aftermath{C.RESET}")
        for x in i["aftermath"]:
            print(wrap(x, W - 5, f"  {C.GRAY}▸{C.RESET} "))

    if i.get("ai_angle"):
        print()
        print(f"{C.BOLD}{C.MAG}The AI angle{C.RESET}")
        print(wrap(i["ai_angle"], W - 2, f"  {C.MAG}✦{C.RESET} "))

    print()
    print(f"{C.BOLD}Why it matters{C.RESET}")
    print(wrap(i["why_it_matters"], W - 2, "  "))

    if i.get("why_context"):
        print()
        print(wrap(i["why_context"], W - 2, f"  {C.GRAY}↳ {C.RESET}"))

    print()
    print(f"{C.BOLD}Sources{C.RESET}")
    for s in i["sources"]:
        print(f"  {C.BLU}{s}{C.RESET}")
    print()


def cmd_search(db, a):
    rows = incidents(db, q=a.term)
    if not rows:
        print(f"nothing matches '{a.term}'.")
        return
    print(f"\n{len(rows)} incident(s) matching '{a.term}':\n")
    for i in sorted(rows, key=lambda x: x["date"]):
        ai = f" {C.MAG}✦{C.RESET}" if (i.get("ai_angle") or i["category"] == "ai_specific") else ""
        print(f"  {C.DIM}{i['date']}{C.RESET}  {C.BOLD}{i['id']:<40}{C.RESET}{i['title'][:48]}{ai}")
    print(C.GRAY + "\n  → bsignal.py show <id> for the full record\n" + C.RESET)


def cmd_stats(db, a):
    s = json.loads(STATS.read_text(encoding="utf-8")) if STATS.exists() else None
    inc = db["incidents"]
    W = 78
    print()
    print(C.BOLD + "═" * W + C.RESET)
    print(C.BOLD + " BREACHSIGNAL — dataset statistics" + C.RESET)
    print(C.GRAY + f" coverage {db['coverage']['from']} → {db['coverage']['to']}   "
                   f"built {db['generated_at']}   v{db.get('version', VERSION)}" + C.RESET)
    print(C.BOLD + "═" * W + C.RESET)

    inw = [i for i in inc if i.get("in_window", True)]
    print(f"\n{C.BOLD}The ledger{C.RESET}")
    print(f"  incidents catalogued          {len(inc):>6}")
    print(f"  ...inside 2023+ window        {len(inw):>6}")
    print(f"  ...with a documented AI angle {sum(1 for i in inc if i.get('ai_angle')):>6}")
    print(f"  ...never publicly disclosed   {sum(1 for i in inc if i.get('disclosed') is False):>6}")
    print(f"  distinct source URLs          {len({u for i in inc for u in i['sources']}):>6}")

    print(f"\n{C.BOLD}By year{C.RESET}")
    yrs = sorted({i["year"] for i in inw})
    mx = max(sum(1 for i in inw if i["year"] == y) for y in yrs)
    for y in yrs:
        n = sum(1 for i in inw if i["year"] == y)
        rec = sum(i.get("records_affected") or 0 for i in inw if i["year"] == y)
        bar = "█" * max(1, int(n * 40 / mx))
        print(f"  {y}  {C.CYN}{bar:<42}{C.RESET}{n:>4}  {C.GRAY}{human(rec):>8} records{C.RESET}")

    print(f"\n{C.BOLD}By category{C.RESET}")
    cats = {}
    for i in inc:
        cats[i["category"]] = cats.get(i["category"], 0) + 1
    mx = max(cats.values())
    for k, v in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"  {k:<17}{C.MAG}{'█' * int(v * 34 / mx):<34}{C.RESET}{v:>4}")

    print(f"\n{C.BOLD}By confidence  {C.RESET}{C.GRAY}(why you should not trust every number here){C.RESET}")
    conf = {}
    for i in inc:
        conf[i["confidence"]] = conf.get(i["confidence"], 0) + 1
    for k in ("regulatory_filing", "victim_disclosure", "security_research", "journalism", "attacker_claim"):
        v = conf.get(k, 0)
        print(f"  {CONF_COLOUR[k]}{CONF_MARK[k]}{C.RESET} {k:<20}{v:>4}  {C.GRAY}{100*v/len(inc):.0f}%{C.RESET}")

    print(f"\n{C.BOLD}Largest by records affected{C.RESET}")
    for i in sorted([x for x in inc if x.get("records_affected")],
                    key=lambda x: -x["records_affected"])[:10]:
        fl = f" {C.RED}⚑{C.RESET}" if i["confidence"] == "attacker_claim" else ""
        print(f"  {C.BOLD}{human(i['records_affected']):>8}{C.RESET}  {i['date'][:4]}  "
              f"{i['title'][:52]}{fl}")

    print(f"\n{C.BOLD}Priced consequences{C.RESET}")
    fin = sorted([x for x in inc if x.get("financial_impact_usd")],
                 key=lambda x: -x["financial_impact_usd"])
    for i in fin[:10]:
        print(f"  {C.BOLD}{money(i['financial_impact_usd']):>10}{C.RESET}  {i['title'][:58]}")
    if fin:
        print(f"  {C.GRAY}{'':>10}  ── total priced in this ledger: "
              f"{money(sum(x['financial_impact_usd'] for x in fin))}{C.RESET}")

    if s and s.get("external_benchmarks"):
        b = s["external_benchmarks"]
        print(f"\n{C.BOLD}External benchmarks{C.RESET}")
        it = b["itrc_us_data_compromises"]
        print(f"  ITRC US data compromises   " + "   ".join(f"{y}: {n:,}" for y, n in it.items()))
        print(f"  ITRC individuals hit, 2024  {human(b['itrc_individuals_compromised_2024_us'])} (US only)")
        ib = b["ibm_cost_of_data_breach"]
        print(f"  IBM avg breach cost        {money(ib['2024']['global_avg_usd'])} (2024) → "
              f"{money(ib['2025']['global_avg_usd'])} (2025), first decline in 5 years")
        print(f"  IBM US avg breach cost     {money(ib['2024']['us_avg_usd'])} → "
              f"{money(ib['2025']['us_avg_usd'])}, a 15th consecutive record")
        print(f"  Breach lifecycle           {ib['2024']['lifecycle_days']}d → "
              f"{ib['2025']['lifecycle_days']}d  ({ib['2025']['identify_days']}d to identify, "
              f"{ib['2025']['contain_days']}d to contain)")
        print(f"  Shadow AI                  factor in {ib['2025']['shadow_ai_share_of_breaches_pct']}% of "
              f"breaches, +{money(ib['2025']['shadow_ai_added_cost_usd'])} each, "
              f"{ib['2025']['shadow_ai_breaches_exposing_pii_pct']}% exposed PII")
        w = b["wiz_ai50_2025"]
        print(f"  Wiz AI-50 secrets study    {w['pct_with_verified_leaked_secrets']}% of {w['companies_examined']} "
              f"leading AI firms had verified secrets in public")
        print(f"                             combined valuation {money(w['combined_valuation_usd'])}; "
              f"{w['pct_of_disclosures_with_no_response']}% could not be reached to be told")
        print(f"  Verizon DBIR 2025          {b['verizon_dbir_2025']['confirmed_breaches']:,} confirmed breaches; "
              f"{b['verizon_dbir_2025']['third_party_involvement_pct']}% involved a third party")
        print(f"  Anthropic authors payout   {money(b['anthropic_settlement_usd'])} "
              f"({b['anthropic_books_covered']:,} pirated books)")
        print(f"  Coupang fine (South Korea) {money(b['coupang_fine_usd'])} — a national record")
        print(f"  OpenAI Garante fine        €{b['openai_garante_fine_eur']:,}")

    print(f"\n{C.GRAY}" + "─" * W + C.RESET)
    print(C.GRAY + wrap("Summing records_affected across this dataset is meaningless: credential "
                        "compilations repackage the same underlying breaches. Use per-year or "
                        "per-incident figures. See docs/METHODOLOGY.md §3.", W, "  ") + C.RESET)
    print()


def cmd_timeline(db, a):
    rows = incidents(db, year=a.year, ai=a.ai)
    rows.sort(key=lambda i: i["date"])
    print()
    cur = None
    for i in rows:
        if i["year"] != cur:
            cur = i["year"]
            n = sum(1 for x in rows if x["year"] == cur)
            rec = sum(x.get("records_affected") or 0 for x in rows if x["year"] == cur)
            print(f"\n{C.BOLD}{C.CYN}── {cur} " + "─" * 60 + C.RESET)
            print(f"{C.GRAY}   {n} incidents · {human(rec)} records · "
                  f"{sum(1 for x in rows if x['year']==cur and (x.get('ai_angle') or x['category']=='ai_specific'))} AI-relevant{C.RESET}")
        ai = f"{C.MAG}✦{C.RESET}" if (i.get("ai_angle") or i["category"] == "ai_specific") else " "
        fl = f"{C.RED}⚑{C.RESET}" if i["confidence"] == "attacker_claim" else " "
        print(f"  {C.DIM}{i['date']}{C.RESET} {ai}{fl} {C.BOLD}{human(i.get('records_affected')):>7}{C.RESET}  "
              f"{i['title'][:62]}")
    print()


def cmd_ai(db, a):
    rows = incidents(db, ai=True)
    rows.sort(key=lambda i: i["date"])
    W = 100
    print()
    print(C.BOLD + C.MAG + "═" * W + C.RESET)
    print(C.BOLD + C.MAG + " THE AI ANGLE — every incident in this ledger that says something" + C.RESET)
    print(C.BOLD + C.MAG + " specific about artificial intelligence" + C.RESET)
    print(C.BOLD + C.MAG + "═" * W + C.RESET)
    print(C.GRAY + wrap("Three kinds of failure are mixed together in most AI-security writing. "
                        "They are separated here. (1) AI companies failing at ordinary security. "
                        "(2) AI as a mechanism for making leaked data permanent. "
                        "(3) AI as the attacker.", W - 2, "  ") + C.RESET)

    groups = {
        "AI companies failing at ordinary security": lambda i: i["category"] == "ai_specific"
            and i["threat_actor"] in ("n/a (research disclosure)", "n/a (research)", "unattributed",
                                      "n/a (software defect)", "n/a"),
        "AI as a laundering mechanism — the corpus problem": lambda i: i["id"] in
            ("wayback-copilot-2025", "moab-2024", "credential-dump-24b-2026", "shadow-ai-ibm-2025",
             "palo-alto-ai-dataloss-2025", "rockyou2024", "under-armour-mfp-2025"),
        "AI as the attacker": lambda i: i["id"] == "openai-huggingface-agent-2026",
        "The price of ingesting other people's work": lambda i: i["category"] == "legal"
            or i["id"] in ("openai-garante-fine-2024", "clearview-ai-fines"),
    }
    used = set()
    for name, pred in groups.items():
        sel = [i for i in rows if pred(i) and i["id"] not in used]
        if not sel:
            continue
        for i in sel:
            used.add(i["id"])
        print(f"\n{C.BOLD}{C.MAG}▌ {name}{C.RESET}")
        for i in sel:
            print(f"\n  {C.DIM}{i['date']}{C.RESET}  {C.BOLD}{i['title']}{C.RESET}")
            print(f"  {C.GRAY}{i['org'][:94]}{C.RESET}")
            if i.get("records_affected"):
                print(f"  scale: {C.BOLD}{human(i['records_affected'])}{C.RESET}"
                      + (f"  {C.GRAY}{i.get('orgs_affected','')} orgs{C.RESET}" if i.get('orgs_affected') else ""))
            if i.get("ai_angle"):
                print(wrap(i["ai_angle"], W - 6, f"  {C.MAG}✦{C.RESET}   "))
            print(wrap(i["why_it_matters"], W - 6, f"  {C.GRAY}→{C.RESET}   "))

    leftover = [i for i in rows if i["id"] not in used]
    if leftover:
        print(f"\n{C.BOLD}{C.MAG}▌ Also carrying an AI angle{C.RESET}")
        for i in leftover:
            print(f"  {C.DIM}{i['date']}{C.RESET}  {i['title'][:70]}")
    print(f"\n{C.GRAY}  {len(rows)} AI-relevant incidents of {len(db['incidents'])} total. "
          f"Full records: bsignal.py show <id>{C.RESET}\n")


def cmd_validate(db, a):
    errs, warns = [], []
    req = ["id", "title", "org", "sector", "date", "year", "category", "attack_vector",
           "data_types", "confidence", "sources", "why_it_matters"]
    ids = set()
    cats = {"supply_chain", "ransomware", "credential", "misconfiguration", "ai_specific",
            "legal", "data_broker", "scraping", "insider", "state_actor"}
    confs = set(db["confidence_levels"])
    for i in db["incidents"]:
        iid = i.get("id", "<no id>")
        for k in req:
            if k not in i or i[k] in (None, "", []):
                errs.append(f"{iid}: missing required field '{k}'")
        if iid in ids:
            errs.append(f"{iid}: duplicate id")
        ids.add(iid)
        if i.get("category") not in cats:
            errs.append(f"{iid}: unknown category '{i.get('category')}'")
        if i.get("confidence") not in confs:
            errs.append(f"{iid}: unknown confidence '{i.get('confidence')}'")
        try:
            datetime.strptime(i["date"], "%Y-%m-%d")
        except Exception:
            errs.append(f"{iid}: bad date '{i.get('date')}'")
        if str(i.get("year")) != i.get("date", "")[:4]:
            warns.append(f"{iid}: year {i.get('year')} != date year {i.get('date','')[:4]} "
                         f"(ok if in_window=false)")
        if not i.get("sources"):
            errs.append(f"{iid}: no sources")
        for s in i.get("sources", []):
            if not s.startswith(("http://", "https://")):
                errs.append(f"{iid}: source is not a URL: {s}")
        if i.get("records_affected") is not None and not isinstance(i["records_affected"], int):
            errs.append(f"{iid}: records_affected must be an integer or null")
        if not i.get("records_note") and i.get("records_affected") and i["records_affected"] > 1e9:
            warns.append(f"{iid}: >1B records with no records_note explaining the spread")

    print()
    if errs:
        print(f"{C.RED}{C.BOLD}✗ {len(errs)} error(s){C.RESET}")
        for e in errs:
            print(f"  {C.RED}•{C.RESET} {e}")
    if warns:
        print(f"{C.YEL}{C.BOLD}⚠ {len(warns)} warning(s){C.RESET}")
        for w in warns:
            print(f"  {C.YEL}•{C.RESET} {w}")
    if not errs:
        print(f"{C.GRN}{C.BOLD}✓ schema valid{C.RESET} — {len(db['incidents'])} incidents, "
              f"{len(ids)} unique ids, {len({u for i in db['incidents'] for u in i['sources']})} distinct sources")
    print()
    return 1 if errs else 0


CSV_FIELDS = ["id", "title", "org", "sector", "date", "year", "category", "confidence",
              "attack_vector", "records_affected", "records_note", "orgs_affected",
              "data_types", "cve", "threat_actor", "disclosed", "disclosure_delay_days",
              "financial_impact_usd", "ai_angle", "why_it_matters", "in_window", "sources"]


def cmd_export(db, a):
    rows = incidents(db, year=a.year, category=a.category, ai=a.ai, q=a.query)
    rows.sort(key=lambda i: i["date"])
    fmt = a.format
    if fmt == "csv":
        w = csv.writer(sys.stdout, lineterminator="\n")
        w.writerow(CSV_FIELDS)
        for i in rows:
            w.writerow([
                "; ".join(i[f]) if isinstance(i.get(f), list) else i.get(f, "")
                for f in CSV_FIELDS
            ])
    elif fmt == "tsv":
        print("\t".join(CSV_FIELDS))
        for i in rows:
            print("\t".join(str((", ".join(i[f]) if isinstance(i.get(f), list) else i.get(f, "")))
                            .replace("\t", " ").replace("\n", " ") for f in CSV_FIELDS))
    elif fmt == "ndjson":
        for i in rows:
            print(json.dumps(i, ensure_ascii=False))
    else:
        print(json.dumps(rows, indent=2, ensure_ascii=False))


# --------------------------------------------------------------------------- network

def _get(url, headers=None, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": f"bsignal/{VERSION}", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:                                   # noqa: BLE001
        return None, str(e).encode()


def cmd_check_email(db, a):
    """Have I Been Pwned — unauthenticated v2 breach list for an account.

    HIBP's v3 API needs a paid key. This uses the free public breach list and
    reports which catalogued breaches your domain appears in. Set HIBP_API_KEY
    for the full authenticated lookup.
    """
    email = a.email
    key = os.environ.get("HIBP_API_KEY")
    print()
    if key:
        st, body = _get(f"https://haveibeenpwned.com/api/v3/breachedaccount/"
                        f"{urllib.parse.quote(email)}?truncateResponse=false",
                        {"hibp-api-key": key})
        if st == 200:
            data = json.loads(body)
            print(f"{C.RED}{C.BOLD}✗ PWNED{C.RESET} — {email} appears in {len(data)} breach(es)\n")
            for b in sorted(data, key=lambda x: x.get("AddedDate", "")):
                print(f"  {C.DIM}{b.get('BreachDate','?'):<12}{C.RESET}{C.BOLD}{b['Name']:<34}{C.RESET}"
                      f"{human(b.get('PwnCount')):>9} records")
                if b.get("DataClasses"):
                    print(f"  {'':<12}{C.GRAY}{', '.join(b['DataClasses'])[:88]}{C.RESET}")
        elif st == 404:
            print(f"{C.GRN}{C.BOLD}✓ GOOD NEWS{C.RESET} — {email} not found in any HIBP breach.\n")
        elif st == 429:
            print("rate limited by HIBP. wait and retry.")
        else:
            print(f"HIBP returned HTTP {st}. {body[:200].decode(errors='replace')}")
    else:
        print(f"{C.YEL}No HIBP_API_KEY set.{C.RESET} Falling back to the free public breach "
              f"index — this reports breaches your DOMAIN appears in, not your address.\n")
        st, body = _get("https://haveibeenpwned.com/api/v3/breaches")
        if st != 200:
            print(f"could not reach HIBP (HTTP {st}).")
            print("Set HIBP_API_KEY for authenticated per-account lookups: https://haveibeenpwned.com/API/Key")
            return
        dom = email.split("@")[-1].lower()
        breaches = json.loads(body)
        hits = [b for b in breaches if dom in (b.get("Domain") or "").lower()]
        if not hits:
            print(f"no HIBP breach is registered against the domain {C.BOLD}{dom}{C.RESET}.")
            print("That says nothing about your specific address — get a key for that.")
        else:
            print(f"{C.RED}{C.BOLD}✗{C.RESET} the domain {C.BOLD}{dom}{C.RESET} appears in "
                  f"{len(hits)} catalogued breach(es):\n")
            for b in sorted(hits, key=lambda x: x.get("AddedDate", "")):
                print(f"  {C.DIM}{b.get('BreachDate','?'):<12}{C.RESET}{C.BOLD}{b['Name']:<32}{C.RESET}"
                      f"{human(b.get('PwnCount')):>10}")
        print(f"\n{C.GRAY}  For per-account results: export HIBP_API_KEY=... "
              f"(https://haveibeenpwned.com/API/Key){C.RESET}")
    print()


def cmd_pwned_search(db, a):
    st, body = _get("https://haveibeenpwned.com/api/v3/breaches")
    if st != 200:
        sys.exit(f"could not reach HIBP (HTTP {st})")
    q = a.term.lower()
    hits = [b for b in json.loads(body)
            if q in b["Name"].lower() or q in (b.get("Domain") or "").lower()
            or q in (b.get("Description") or "").lower()]
    print(f"\n{len(hits)} HIBP breach(es) matching '{a.term}':\n")
    for b in sorted(hits, key=lambda x: x.get("AddedDate", ""), reverse=True)[:40]:
        print(f"  {C.DIM}{b.get('BreachDate','?'):<12}{C.RESET}{C.BOLD}{b['Name']:<32}{C.RESET}"
              f"{human(b.get('PwnCount')):>12}  {C.GRAY}{(b.get('Domain') or '')[:24]}{C.RESET}")
    print()


def cmd_feed(db, a):
    """Emit an RSS 2.0 feed of the ledger, newest first."""
    from xml.sax.saxutils import escape
    rows = sorted(db["incidents"], key=lambda i: i["date"], reverse=True)[: a.limit]
    base = a.base.rstrip("/")
    now = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    out = io.StringIO()
    out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    out.write('<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n<channel>\n')
    out.write(f"  <title>BREACHSIGNAL</title>\n")
    out.write(f"  <link>{escape(base)}</link>\n")
    out.write("  <description>Data breaches, AI industry secrecy failures and training-data "
              "theft, catalogued with sources.</description>\n")
    out.write("  <language>en</language>\n")
    out.write(f"  <lastBuildDate>{now}</lastBuildDate>\n")
    out.write(f'  <atom:link href="{escape(base)}/data/feed.xml" rel="self" '
              f'type="application/rss+xml"/>\n')
    for i in rows:
        d = datetime.strptime(i["date"], "%Y-%m-%d").strftime("%a, %d %b %Y 12:00:00 +0000")
        desc = (f"{i['org']} — {i['attack_vector'][:300]}\n\n"
                f"Records: {human(i.get('records_affected'))}  |  Confidence: {i['confidence']}\n\n"
                f"{i['why_it_matters']}\n\nSources:\n" + "\n".join(i["sources"]))
        out.write("  <item>\n")
        out.write(f"    <title>{escape(i['title'])}</title>\n")
        out.write(f"    <link>{escape(base)}/#{escape(i['id'])}</link>\n")
        out.write(f"    <guid isPermaLink=\"false\">{escape(i['id'])}</guid>\n")
        out.write(f"    <pubDate>{d}</pubDate>\n")
        out.write(f"    <category>{escape(i['category'])}</category>\n")
        out.write(f"    <category>{escape(i['confidence'])}</category>\n")
        out.write(f"    <description>{escape(desc)}</description>\n")
        out.write("  </item>\n")
    out.write("</channel>\n</rss>\n")
    txt = out.getvalue()
    if a.out and a.out != "-":
        Path(a.out).write_text(txt, encoding="utf-8")
        print(f"wrote {a.out} ({len(rows)} items)")
    else:
        sys.stdout.write(txt)


# --------------------------------------------------------------------------- main

def build_parser():
    p = argparse.ArgumentParser(
        prog="bsignal",
        description="BREACHSIGNAL — a sourced ledger of data breaches and AI secrecy failures.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              bsignal.py stats
              bsignal.py list --year 2025 --sort records --limit 15
              bsignal.py list --category supply_chain --min-records 1000000
              bsignal.py list --confidence attacker_claim
              bsignal.py show deepseek-clickhouse-2025
              bsignal.py search snowflake
              bsignal.py ai
              bsignal.py timeline --ai
              bsignal.py export --format csv > breaches.csv
              bsignal.py check-email you@example.com
              HIBP_API_KEY=... bsignal.py check-email you@example.com
        """),
    )
    p.add_argument("--version", action="version", version=f"bsignal {VERSION}")
    sub = p.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("--year", type=int, action="append", help="filter by year (repeatable)")
        sp.add_argument("--category", action="append", help="filter by category (repeatable)")
        sp.add_argument("--sector", help="substring match on sector")
        sp.add_argument("--query", "-q", help="full-text substring match")
        sp.add_argument("--ai", action="store_true", help="only incidents with an AI angle")
        sp.add_argument("--json", action="store_true", help="emit raw JSON")

    sp = sub.add_parser("list", help="list incidents"); common(sp)
    sp.add_argument("--confidence", action="append",
                    choices=["regulatory_filing", "victim_disclosure", "security_research",
                             "journalism", "attacker_claim"])
    sp.add_argument("--min-records", type=int, help="only incidents at or above N records")
    sp.add_argument("--undisclosed", action="store_true", help="only never-disclosed incidents")
    sp.add_argument("--sort", default="records",
                    choices=["records", "date", "year", "impact", "org"])
    sp.add_argument("--limit", type=int)

    sp = sub.add_parser("show", help="full record for one incident")
    sp.add_argument("id"); sp.add_argument("--json", action="store_true")
    sp.add_argument("--first", action="store_true", help="take the first match")

    sp = sub.add_parser("search", help="full-text search"); sp.add_argument("term")
    sp = sub.add_parser("stats", help="dataset statistics")
    sp = sub.add_parser("ai", help="every incident with an AI angle, grouped")
    sp = sub.add_parser("timeline", help="chronological timeline")
    sp.add_argument("--year", type=int, action="append"); sp.add_argument("--ai", action="store_true")
    sp = sub.add_parser("validate", help="schema and referential validation")
    sp = sub.add_parser("export", help="export filtered rows")
    common(sp)
    sp.add_argument("--format", default="json", choices=["json", "csv", "tsv", "ndjson"])

    sp = sub.add_parser("check-email", help="check an address against Have I Been Pwned")
    sp.add_argument("email")
    sp = sub.add_parser("pwned-search", help="search the HIBP breach index")
    sp.add_argument("term")

    sp = sub.add_parser("feed", help="emit an RSS feed of the ledger")
    sp.add_argument("--limit", type=int, default=30)
    sp.add_argument("--base", default="https://onlytiap.github.io/BREACHSIGNAL")
    sp.add_argument("--out", default="-")
    return p


def main(argv=None):
    p = build_parser()
    a = p.parse_args(argv)
    if not a.cmd:
        p.print_help()
        return 0
    db = load()
    fn = {
        "list": cmd_list, "show": cmd_show, "search": cmd_search, "stats": cmd_stats,
        "ai": cmd_ai, "timeline": cmd_timeline, "validate": cmd_validate,
        "export": cmd_export, "check-email": cmd_check_email,
        "pwned-search": cmd_pwned_search, "feed": cmd_feed,
    }[a.cmd]
    return fn(db, a) or 0


def _main_guard():
    """Exit cleanly when the reader closes the pipe early (`... | head`)."""
    try:
        return main()
    except BrokenPipeError:
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(_main_guard())
