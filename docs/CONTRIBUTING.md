# Contributing

This dataset is a public record. It is meant to be corrected, extended and argued with.

**Corrections merge on evidence, not on reputation.** A first-time contributor with a link to
an SEC filing outranks a maintainer with an opinion. If you have a source, you have standing.

---

## Correcting an incident

Fastest path: open an issue using the **Correction** template with the incident `id`, the field,
and a URL.

Or send a pull request against `data/incidents.json` directly:

```bash
git clone https://github.com/onlytiap/BREACHSIGNAL
cd BREACHSIGNAL
# edit data/incidents.json
python3 build.py          # regenerates stats.json, incidents.csv, feed.xml, site/data.js, SOURCES.md
python3 cli/bsignal.py validate
git commit -am "fix(deepseek-clickhouse-2025): correct disclosure date per Wiz postmortem"
```

`build.py` **refuses to run if validation fails**, and CI runs the same validation on every PR.
Do not hand-edit the derived files — they are regenerated and CI checks that they are current.

## Adding an incident

An event qualifies if **all** of these hold (full rules in [`METHODOLOGY.md`](METHODOLOGY.md) §1):

1. It concerns the confidentiality of personal data, credentials, trade secrets, or copyrighted
   works obtained without consent.
2. It happened in 2023 or later — **or** earlier, if its consequences dominated this period
   (then set `"in_window": false` and add a `why_context` field).
3. **At least one source URL supports it.** No source, no entry. This is enforced in CI.

An event does **not** qualify if its only support is an anonymous forum post, an unattributed
social-media claim, or a rumour with no named origin.

### Required fields

```json
{
  "id":               "kebab-case-unique-slug-with-year",
  "title":            "Organisation — what happened, in plain words",
  "org":              "who was compromised, or whose conduct is at issue",
  "sector":           "Healthcare / Hospital systems",
  "date":             "YYYY-MM-DD",
  "year":             2025,
  "category":         "supply_chain | ransomware | credential | misconfiguration | ai_specific | legal | data_broker | scraping | insider | state_actor",
  "attack_vector":    "how the attacker actually got in. Be specific — 'a vulnerability' is not an answer.",
  "records_affected": 1000000,
  "data_types":       ["names", "email addresses"],
  "cve":              [],
  "threat_actor":     "named group, or 'unattributed', or 'n/a' for research/legal entries",
  "disclosed":        true,
  "confidence":       "regulatory_filing | victim_disclosure | security_research | journalism | attacker_claim",
  "why_it_matters":   "one paragraph: what this incident proves that the others do not",
  "sources":          ["https://..."]
}
```

Optional but strongly encouraged: `records_note` (explain the spread when sources disagree),
`orgs_affected`, `financial_impact_usd`, `aftermath` (array), `ai_angle`,
`disclosure_delay_days`, `in_window`, `why_context`.

### Getting `confidence` right

This is the field most contributors get wrong, and the one that matters most.

| Use | When |
|---|---|
| `regulatory_filing` | A regulator, a court, or a statutory notification confirms it. HHS OCR, ICO, CNIL, Garante, SEC 8-K, a fine, a ruling. |
| `victim_disclosure` | The affected organisation confirmed it publicly itself. |
| `security_research` | An independent vendor or researcher **directly observed** the exposure. |
| `journalism` | Named reputable outlets citing named sources, with no first-party confirmation. |
| `attacker_claim` | The scale or the existence rests on the attacker's own statement. |

When in doubt, **downgrade**. An `attacker_claim` label is not a criticism of the entry — it is
what makes the entry safe to publish. Five incidents in this dataset carry it and all five stay
in, because excluding them would understate the period.

### Getting `records_affected` right

- Use the **highest credible figure**, and explain the spread in `records_note`.
- Distinguish people, records, accounts and credentials. Say which one you are counting.
  National Public Data is 2.9B *records*; Change Healthcare is 192.7M *people*.
- If the confirmed population is much smaller than the claimed one, **record both**. Ticketmaster
  is the canonical case: 560M claimed, ~1,000 confirmed in Maine filings.
- Never leave a >1B figure without a `records_note`. Validation warns.

### Writing `why_it_matters`

One paragraph. It must say something this incident proves that no other entry in the dataset
proves. If you cannot write that sentence, the incident may be a duplicate of an existing
pattern — consider adding it to that incident's `aftermath` instead.

This project's editorial voice is direct and unsentimental, but it is **not** adversarial toward
the facts. Strong claims are permitted only where the evidence is strong. If the record is
ambiguous, say it is ambiguous.

### Writing `ai_angle`

Populate it only when the incident says something specific about AI that it would not say if AI
did not exist. It is not a keyword tag. 25 of 83 incidents carry one. See
[`METHODOLOGY.md`](METHODOLOGY.md) §5 for the three categories and the test for each.

---

## Style

- British or American spelling, consistently, within one entry. Mixed across the dataset is fine.
- Numbers: full digits in JSON, human-readable in prose.
- Dates: ISO 8601, `YYYY-MM-DD`. Use the date of the **intrusion** where known, not the date of
  disclosure; put the disclosure date in `aftermath`.
- No editorialising inside factual fields. `attack_vector` describes mechanics; opinion goes in
  `why_it_matters`.
- Every claim in `aftermath` should be traceable to one of the entry's `sources`.

## Testing your change

```bash
python3 cli/bsignal.py validate          # schema + referential checks
python3 build.py                          # runs validate, then regenerates everything
python3 cli/bsignal.py show <your-new-id> # read your own entry the way a reader will
python3 cli/bsignal.py stats              # confirm your entry did not break the aggregates
```

To see it on the site locally:

```bash
cd site && python3 -m http.server 8080
# http://localhost:8080  (data.js is generated into site/ by build.py)
```

## What will get a PR rejected

- No source URL.
- An accusation presented as fact where the only evidence is an attacker's claim and the entry
  is not labelled `attacker_claim`.
- Hand-edits to `data/stats.json`, `data/incidents.csv`, `data/feed.xml` or `site/data.js`
  instead of running `build.py`.
- A record count with no stated unit (people? records? accounts? credentials?).
- Removing an incident because a named organisation objects, without a source showing the
  original entry was wrong. **This is a public record. Discomfort is not a correction.**

## Non-data contributions

Bug reports and improvements to the CLI, the site and the build are all welcome under the same
rules. The site deliberately has **no external dependencies** — no CDN, no web fonts, no
analytics, no network requests at all. Please keep it that way; it is what makes it work
offline and what makes it trustworthy to load.

---

## Licence

By contributing, you agree your contribution is licensed under the repository's dual licence:
[MIT](../LICENSE) for code, [CC-BY-4.0](../LICENSE-data) for data and documentation.
