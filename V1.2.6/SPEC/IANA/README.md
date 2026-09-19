# IANA URI Scheme Registrations — pointer index

> ⚠️ **This directory does not hold the registration requests.**
> The **authoritative dossiers live in `Aicent_Empire_v125_Shipyard/aicent-docs/`**,
> next to the two submissions IANA already holds. Send from there.
> This directory holds only this index.

---

## 1. The two scheme names

| Scheme name | Where it is used | Status | Dossier |
| :--- | :--- | :--- | :--- |
| **`rttp`** | rttp.com spec · `/open/` | **submitted 2026-09-16** — ticket **`[IANA #1459939]`**, state **`Validating Request`** (2026-09-19; was `Expert Review` on 09-17/18); **name approved**, CRI number `0–999` under review (requested 2026-09-17) | `aicent-docs/RTTP_IANA_URI_SCHEME_REGISTRATION.md` (**status glossary: §0.3**) |
| **`iqa`** | iqa.org spec · `/open/` | **submitted 2026-09-17** — ticket **`[IANA #1459963]`**, state **`Expert Review`** (entered 2026-09-18); CRI number `0–999` requested 2026-09-18 | `aicent-docs/IQA_IANA_URI_SCHEME_REGISTRATION.md` |

Two scheme names. Two registrations. That is the whole list.

> **As-sent CRI reply (verbatim):** `aicent-docs/IQA_IANA_URI_SCHEME_REGISTRATION.md` **§0.2.1** — the only
> verbatim copy of the `iqa` CRI answer (sent **2026-09-18 13:39 Beijing**, thread `[IANA #1459963]`,
> requested `0–999`, `Well-Known URI Support` never asked by IANA).
> ⚠️ **Discipline:** an earlier note in that dossier claimed *"no byte-economy argument was made"* — that was
> **wrong** and is corrected there. **Read the as-sent text before describing what we argued.** A decision
> draft is not the sent mail.

> **`iqa` name sign-off — ⏳ OPEN (2026-09-19):** the reviewer **suggested a longer name (`identityqa`)**.
> We **declined to change the name** and offered three remedies that do not rename the scheme (a registry
> `Notes` disclaimer · a plainer `Applications` paragraph · a stronger naming note in the specification);
> we stated that **if `iqa` cannot be approved we would rather withdraw the request**. IANA forwarded our
> answer to the reviewer on **2026-09-19 07:54** — the decision now rests with the reviewer.
> Both directions, verbatim: `aicent-docs/IQA_IANA_URI_SCHEME_REGISTRATION.md` **§0.3**.
> ⚠️ Still **not registered**: never write "approved" for `iqa`.

> **`rpki` — NOT applied for (decision, 2026-09-19):** the name **is** free in the registry (verified 2026-09-19:
> 0 hits across all three registry formats; `prov/rpki` → 404) and FCFS would allow a grab — **we will not file it.**
> Three reasons, all verified: (1) **we never use `rpki://`** anywhere (0 hits in both trees) — the security layer is
> **in-band** (RFC-002 §10.5), so there is no addressing use to declare; (2) the collision is with a **live IETF
> standard in the same domain** — an order of magnitude harder than `iqa`'s academic-field collision, which is
> *still* contested; (3) a third ticket would **contaminate `iqa`** in front of the same reviewer pool.
> Full record (counter-argument · revisit triggers · reproduction commands): `aicent-docs/RPKI_IANA_URI_SCHEME_DECISION.md`.
> ⚠️ **Never write a `rpki` URI scheme**, and never claim one.

> **Landscape — who else is in this layer (2026-09-19):** this layer is **not empty and not ours alone**.
> Verified the same day: new URI-scheme drafts for agents exist (`draft-narvaneni-agent-uri-03` requests
> IANA **Provisional `agent`**; `draft-sogomonian-ai-uri-scheme-01` defines `ai:`), DNS-centric directories are
> running (`draft-narajala-ans-00`, Linux Foundation **DNS-AID**), and the IETF is **chartering DAWN**
> (*Discovery of Agents With Names*) — currently **Proposed**, charter in IESG review with **2 BLOCKs**, but
> **12 drafts already attached**. Registered names in this space today: `did` (CRI 5), `interaction` /
> `web+interaction` (W3C VC WG, 1023/1024), `mdoc` (ISO/IEC JTC1 SC17, 1013), `agtp` (individual, 1006).
> **`agent` / `ai` / `a2a` / `mcp` are still free** in the registry.
> Our position: **minority architecture** (we are the only design that **rejects DNS**). Data, sources,
> verification levels and open items: `aicent-docs/AGENT_LAYER_LANDSCAPE.md`.

---

## 2. `web+` is not a scheme of this project, and will not be filed

**Decision, 2026-09-17, permanent: no `web+` name will ever be submitted to IANA.**
`web+rttp` and `web+iqa` are not registered, are not to be called schemes, and do
not appear in either specification.

What `web+` actually is: a constraint of **one browser API**.
`navigator.registerProtocolHandler()` accepts only a scheme on its safelisted set
(24 entries), or a scheme beginning `web+`. `rttp` and `iqa` are on neither — so a
web page cannot register a handler for the real scheme, and reaching one from a
page requires the browser's own reserved prefix. That is a fact about the
**browser**, not about either protocol. IANA approval would not change it: the
registry and the browser safelist are separate systems.

Consequences, all verified:

* The as-sent requests for `rttp` and `iqa` never mentioned a second name — so
  there is nothing to retract, and no clarification is owed to IANA.
* Neither `References:` document mentions `web+`. `RFC-002` and `RFC-009` were
  both cleaned on 2026-09-17 (production, prose, and the registration-status
  tables); live occurrence count is **0** on all four URLs, byte-verified.
* On the two sites, `web+` survives only as **mechanism** — the `href` on the
  enable chip and the `registerProtocolHandler()` call. No visible string on
  `rttp.com`, `iqa.org` or either `/open/` resolver displays it.

---

## 3. Files in this directory

| File | What it is |
| :--- | :--- |
| `README.md` | this index |

The two `web+` pointer files that used to sit here were **deleted on 2026-09-17**
under the decision above. They pointed at dossiers
(`aicent-docs/*_IANA_WEB_SCHEME_REGISTRATION.md`) that were **never written**, so
nothing was lost — and keeping a "how to send this request" checklist for a
request that will never be sent is how a stale document turns into a wrong one.

**Do not copy request text out of this directory.** An earlier draft here was written from
RFC 7595 alone and differed from the as-sent emails in six respects — recipient
(`iana@iana.org` vs the correct **`iana-prot-param@iana.org`**), Subject line, opening
paragraph, field name, the separate `Scheme syntax:` field, the two-line
`Contact:` / `Author/Change controller:` convention, the three-entry `References:` list,
and the closing signature. The dossiers in `aicent-docs/` reproduce the as-sent format.

---

## 4. Before sending anything (any future request)

1. **Recipient is `iana-prot-param@iana.org`** — the protocol-parameter queue. Not
   `iana@iana.org`.
2. **Do not CC `uri-review@ietf.org`.** That list is for the **Permanent** procedure;
   IANA notifies it itself after a Provisional registration.
3. **Give the full name in `Contact`.** IANA already required this on the `rttp` ticket
   (*"Please provide a full name (first and last) for the contact."*), so
   `ShaoBao Li <lee@rttp.com>` / `lee@iqa.org` is pre-filled.
4. **The `References` URL must resolve.** Both were **verified live 2026-09-17**:
   `https://rttp.com/RFC-002/` and `https://iqa.org/RFC-009/` → **200**.
   ⚠️ `/spec/RFC-002/` and `/spec/RFC-009/` → **404**; do not use them.
5. **Never describe either name as "registered".** The registry contains neither.

---

## 5. Verified facts (2026-09-17)

| Check | Result |
| :--- | :--- |
| `rttp` and `iqa` in the registry | **neither present** |
| Registry size | ~434 entries (Last Updated 2026-09-15) |
| Registration template | RFC 7595 **§7.4**, six fields |
| Provisional policy | **First Come First Served** — **but** `rttp`'s actual experience was **`Expert Review`** (the IESG-designated naming expert). Do not expect same-day listing. |
| `https://rttp.com/RFC-002/` | **200** ✅ |
| `https://iqa.org/RFC-009/` | **200** ✅ |
| `https://rttp.com/spec/RFC-002/` | **404** ❌ |
| `https://iqa.org/spec/RFC-009/` | **404** ❌ |
| `https://rttp.com/handler/` · `https://iqa.org/handler/` | **404** — by design; `handler/` is a local install kit, not a deployed path |
| `web+` occurrences in either spec | **0** — all four URLs, byte-verified 2026-09-17 |

---

## 6. Spec-side items

| Spec-side item | Status |
| :--- | :--- |
| **One master per RFC** | **decided 2026-09-17** — `RFC-00X/source.txt` is the **master**; the same-named `RFC-00X-*.md` is a **derived mirror**. Edit the master, regenerate the mirror, never hand-edit both. Verified three-way identical: local `source.txt` ≡ local `.md` ≡ the live `/RFC-00X/source.txt` (`c29c49b1…` · `4e1be519…`) |
| `RFC-002 §10.7` / `RFC-009 §10.5` — registration status sections | **done** — `rttp` `#1459939` (2026-09-16) · `iqa` `#1459963` (2026-09-17). Note the **numbering differs** (§10.7 vs §10.5) — do not cross-reference by number |
| Both specs — `web+` removed from production, prose and status tables | **done 2026-09-17** — live `web+` = 0 |
| Both specs — recipient address in the registration-status section | **corrected 2026-09-17** — both said `iana@iana.org`; the as-sent queue is **`iana-prot-param@iana.org`** |
| `RFC-009 §10.4` / `RFC-002 §10.6` — the scheme-prefix check | **open.** The current sentence fixed the subject mismatch and the negated-`or` scoping, but still (a) overstates what the check buys — the no-navigation rule is the real guard — and (b) does not say whether the check runs before or after percent-decoding. A fuller replacement is drafted, awaiting a decision |
| `RFC-009 §10.3` — *"Hex AID material is normalized to lowercase on entry"* vs `/open/`, which **rejects** uppercase | **open contradiction.** One of the two must change; it decides whether `iqa://3F9A1B2C…` is usable. `RFC-002 §10.3` is silent on the point |
| `RFC-009 §10.2` — `32lowhex` / `64lowhex` | **needs verification, not a known defect.** These may be valid *repetitions* of the rule `lowhex` (which §10.2 does define), in the style of `2DIGIT` in RFC 5322. Check RFC 5234 §3.6 before "fixing" anything |

Neither filing depends on any open item — each request carries its own complete
`Scheme syntax:` field.

Until the registry actually lists them, the only accurate sentence remains:
*submitted under RFC 7595, Provisional procedure, pending.*
