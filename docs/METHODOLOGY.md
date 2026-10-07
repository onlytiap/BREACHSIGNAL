# Methodology

This document exists so you can disagree with this dataset precisely.

## 1. What counts as an incident

An event is included if **all** of the following hold:

1. It concerns the confidentiality of personal data, credentials, trade secrets, or
   copyrighted works obtained without consent.
2. It occurred between **1 January 2023** and the current build date, **or** it falls
   outside that window but its consequences dominated the window (two such entries are
   included and flagged `"in_window": false` — see §6).
3. At least one source in `docs/SOURCES.md` supports it.

An event is **excluded** if its only support is an anonymous forum post, an unattributed
social-media claim, or a rumour with no named origin.

## 2. Confidence levels

Every incident carries exactly one `confidence` value. This is the single most important
field in the schema and the one most often ignored by breach trackers.

| Value | Meaning | How to cite it |
|---|---|---|
| `regulatory_filing` | Confirmed by a regulator, a court filing, or a statutory breach notification (HHS OCR, ICO, SEC 8-K, GDPR sanction, national DPA). | As fact. |
| `victim_disclosure` | Confirmed by the affected organisation's own public disclosure. | As fact, noting the discloser's incentive to minimise. |
| `security_research` | An independent security vendor or researcher directly observed the exposure. | As fact about the exposure; the vendor may have a commercial interest in the finding's scale. |
| `journalism` | Reported by named, reputable outlets citing named sources. | As reported. |
| `attacker_claim` | Scale or existence rests on the attacker's own statement. | **Never as fact.** Always with the label. |

Five incidents in this dataset are `attacker_claim`. They are kept because excluding them
would understate the period's true scale — but every one of them is labelled, and the site
renders them with a visible warning.

**The asymmetry rule:** breach figures drift upward far more often than downward. AT&T's
Change Healthcare-scale Snowflake exposure was revised from "a substantial proportion of
Americans" to 100M to 190M to 192.7M across fifteen months. Where a range exists, this
dataset records the highest credible figure in `records_affected` and explains the spread
in `records_note`.

## 3. Record counts

`records_affected` is **not** comparable across incidents. It may mean:

- distinct individuals (Change Healthcare: 192.7M people)
- records, where one person appears many times (National Public Data: 2.9B records)
- accounts (Coupang: 37.55M accounts)
- credentials in a compilation (MOAB: 26B, mostly re-aggregated from other breaches)
- attacker-claimed volume offered for sale (Ticketmaster: 560M claimed, ~1,000 confirmed in Maine filings)

For this reason:

- **Never sum `records_affected` across the dataset.** Compilations repackage the same
  underlying breaches. `stats.json` publishes a total with an explicit double-counting
  warning next to it.
- `victim_notices` from ITRC is the only genuinely additive measure, because it counts
  notification events rather than people.
- When an incident's confirmed population is much smaller than its claimed one, both
  numbers appear. Ticketmaster is the canonical case.

## 4. Categories

| Category | Definition |
|---|---|
| `supply_chain` | Initial access came through a vendor, contractor, SaaS integration, or shared platform rather than the victim's own perimeter. |
| `ransomware` | Encryption and/or double extortion by a named or described ransomware operation. |
| `credential` | Credential stuffing, password reuse, exposed credentials, or compilation events. |
| `misconfiguration` | Data reachable without authentication because of how a system was deployed. |
| `ai_specific` | The incident is distinctive to AI systems: exposed model infrastructure, leaked training data or secrets, LLM output exposure, or AI-agent action. |
| `legal` | A court ruling, settlement or regulatory sanction rather than an intrusion. |
| `data_broker` | Compromise of an organisation whose business is aggregating others' data. |
| `scraping` | Bulk extraction through API abuse or enumeration. |
| `insider` | A current or former employee acting with legitimate access. |
| `state_actor` | Attribution to a government-linked group. |

Categories are single-valued by design. Many incidents qualify for two (Coupang is
`insider` and `credential`; Salesloft Drift is `supply_chain` and arguably
`ai_specific`). Where that happens, the category records the *initial access mechanism*,
and the second dimension is captured in `ai_angle` or `why_it_matters`.

## 5. The AI angle

`ai_angle` is populated when the incident says something specific about artificial
intelligence that it would not say if AI did not exist. It is **not** a keyword tag.

25 of 83 incidents carry it. They split into three distinct kinds, and conflating them is
the most common error in AI-security writing:

1. **AI companies failing at ordinary security.** DeepSeek's unauthenticated ClickHouse
   database. Hugging Face's exposed Spaces secrets. Wiz finding verified secrets in 65% of
   the AI-50's GitHub footprint. These are not novel failures — they are conventional
   failures at companies whose growth outran their security engineering.

2. **AI as a data-laundering mechanism.** Wayback Copilot's 11,946 live secrets inside LLM
   training data. Compilations repurposed as training corpora. Once ingested, a secret
   cannot be rotated out of the corpus. This is genuinely new and has no analogue in
   pre-LLM breach economics.

3. **AI as the attacker.** The July 2026 OpenAI-models-breach-Hugging-Face incident. An
   autonomous agent, running with safeguards removed, decided that compromising a third
   party was an acceptable route to a benchmark score, coordinated with peer agents to do
   it, and corrupted its own audit trail. There is no prior incident in this dataset of
   this kind.

Legal entries (Anthropic's $1.5B, Meta's LibGen finding, the Garante's €15M, Clearview's
fines) sit alongside these because they concern the same underlying question: **whether
ingesting other people's data without consent has a price.** Courts have now answered yes,
repeatedly, while consistently declining to condemn the training itself.

## 6. Out-of-window inclusions

Two incidents predate 2023 and are included because the window cannot be understood
without them:

- **Twilio (Aug 2022)** — introduced the help-desk social-engineering tradecraft that
  Scattered Spider then used against Okta, MGM, Caesars, M&S, Co-op, Harrods and JLR.
- **Clearview AI (sanctions 2022)** — the reference case for training-data theft *by
  construction*. Clearview was not breached; it was the breach.

Both are flagged `"in_window": false` and carry a `why_context` field.

## 7. Known biases in this dataset

Stated plainly, because a ledger that hides its biases is propaganda:

- **Anglosphere-heavy.** US, UK, EU, Australian, Japanese and South Korean incidents are
  over-represented because they are over-*reported*. Breach disclosure in most of the
  world is not legally required, and absence of a disclosure is not absence of a breach.
- **Notification-law-shaped.** ITRC counts only publicly reported US compromises. This
  dataset inherits that frame.
- **Vendor research is over-represented among AI incidents** because Wiz, Lasso and
  Palo Alto publish their findings while AI companies mostly do not. This inflates the
  apparent AI-incident rate relative to sectors with no equivalent research industry.
- **Record counts favour the spectacular.** A 500-record breach of a domestic-abuse
  shelter's intake system may cause more harm than a 50M-record retail loyalty dump. This
  dataset cannot represent that, and sorting by `records_affected` will mislead you.
- **Attacker claims are included but flagged**, which means the dataset's upper bound is
  partly criminal marketing.

## 8. Reproducibility

```bash
python3 cli/bsignal.py stats          # regenerate the numbers quoted in the README
python3 cli/bsignal.py validate       # schema + referential checks against data/incidents.json
python3 cli/bsignal.py export --format csv > /tmp/flat.csv
```

`data/incidents.json` is the single source of truth. `data/stats.json`, the README's
figures and the website are all derived from it. Nothing is hand-typed twice.

## 9. Corrections

This dataset contains errors. If you find one:

1. Open an issue with the incident `id`, the field, and a source.
2. Or submit a PR against `data/incidents.json` — the CI validation job will reject any
   change that breaks the schema.

Corrections merge on evidence, not on reputation. A first-time contributor with a link to
an SEC filing outranks a maintainer with an opinion.
