# PEguise

Static, offline detection of **vendor impersonation via VERSIONINFO** in Windows PE files.

PEguise flags binaries whose `VERSIONINFO` resource claims to be a well-known product —
`CompanyName` "Mozilla", `FileDescription` "Firefox" — while other static evidence in the
same file contradicts that claim. It is a **triage aid for malware analysts**. It produces a
weighted suspicion score with a full evidence breakdown, so you can see *why* something is
interesting. It never returns a malicious/clean verdict.

**PEguise never executes, unpacks, emulates or modifies an analysed file, and makes no
network requests of any kind.** Everything is read-only parsing.

---

## Quick start

Requires Python 3.11 or newer.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

```bash
.venv/bin/python analyze.py suspicious.exe
```

```bash
.venv/bin/python analyze.py ./samples --recursive --json > findings.json
```

```bash
.venv/bin/python -m pytest tests/ -q
```

---

## What the output looks like

```
==============================================================================
samples/FirefoxSetup.exe
==============================================================================
  sha256 : 8a2224c4cd69520c377c0bc9801fd84df5267480f9d2bb86f75e0e5dfb19da5d
  size   : 2560 bytes   machine: IMAGE_FILE_MACHINE_I386
  SCORE  : 75 / 100  ->  HIGH

  VERSIONINFO
    CompanyName        Mozilla
    ProductName        Firefox
    InternalName       7zS.sfx
    OriginalFilename   7zS.sfx
    LegalCopyright     Copyright (c) 1999-2023 Igor Pavlov

  VENDOR CLAIM  Mozilla  (from CompanyName='Mozilla'; matched 'Mozilla' by exact, confidence 1.00)

  SIGNATURE
    status            no embedded Authenticode signature
    NOT VERIFIED      certificate chain of trust; certificate revocation (CRL/OCSP); ...

  EVIDENCE
    [!] +50  Vendor claim coexists with a packer/installer self-identity  [generic_tool_identity]
          The file claims to be Mozilla but its InternalName is the self-identifying
          string of 7-Zip self-extracting archive stub. ...
          observed: {"field": "InternalName", "value": "7zS.sfx", "matched_tool": "7zip_sfx"}
          expected: {"vendor": "Mozilla", "one_of_patterns": [...]}
    [!] +20  Vendor that almost always signs, but the file is unsigned  [unsigned_but_vendor_signs]
    [!] +5   LegalCopyright does not mention the claimed vendor  [copyright_vendor_mismatch]
```

`--json` emits the same information as structured data, including every check that did
*not* fire and why.

Every attacker-controlled string in the text report — VERSIONINFO values, signer names,
resource ids, file paths — has its non-printable characters escaped (`\x1b`, `\u202e`)
before it reaches the terminal, so a sample cannot use embedded escape sequences or bidi
overrides to repaint the report. The JSON output carries the raw values; `json.dumps`
escapes them safely.

---

## The checks

Every check except the Authenticode digest comparison is **gated on a specific vendor claim
existing**. This is the single most important design decision in the tool: blank, sloppy or
unprofessional metadata on a file that impersonates nobody is *not* evidence, and PEguise
does not score it. See "What PEguise deliberately does not flag" below.

| Check | Weight | Fires when |
|---|---:|---|
| `authenticode_digest_mismatch` | 75 | The digest inside the PKCS#7 does not equal the authentihash recomputed from the file. **Not gated on a vendor claim.** |
| `generic_tool_identity` | 50 | A vendor is claimed *and* `InternalName`/`OriginalFilename`/etc. is the self-identifying string of a packer, SFX stub or installer builder. |
| `signer_cn_mismatch` | 40 | A vendor is claimed, a signature is present, and the signer's Subject CN has no plausible relationship to that vendor. |
| `signer_cn_near_miss` | 40 | The signer CN is *almost* the vendor name but is not that entity — the shape of a typosquatted signing identity. Mutually exclusive with the above. |
| `packer_section_names` | 30 | A vendor is claimed **and** a PE section name belongs to a runtime compressor (`UPX0`, `.aspack`, `.MPRESS1`…). Weight key `packer_section_compressor`. |
| `unsigned_but_vendor_signs` | 20 | A vendor is claimed, the file is unsigned, and that vendor Authenticode-signs essentially everything it ships. |
| `packer_section_names` | 15 | The same check when the section name belongs to a commercial protector (`.themida`, `.vmp0`, `.enigma1`…). Weight key `packer_section_protector`; weighted far lower — see below. |
| `anomalous_section_names` | 10 | A vendor is claimed **and** a section name is structurally implausible (random, non-printable, empty, duplicated). |
| `default_packer_icon` | 20 | A vendor is claimed *and* the file carries a packer's untouched stock default icon. |
| `internal_name_mismatch_strict` | 15 | A vendor with a small, enumerable catalogue is claimed, and the internal names match none of its known products. |
| `internal_name_mismatch_lenient` | 5 | Same, for vendors that ship thousands of binaries (Microsoft, Google) where this is weak evidence. |
| `copyright_vendor_mismatch` | 5 | A vendor is claimed but `LegalCopyright` names a different party. |
| `vendor_claim_without_names` | 5 | A vendor is claimed but both `InternalName` and `OriginalFilename` are absent. |

Score is the sum of fired weights, capped at 100. Bands: **low** 0–19, **moderate** 20–39,
**elevated** 40–69, **high** 70+.

The bands are calibrated so that the canonical impersonation pattern (big-vendor claim +
packer self-identity + unsigned when that vendor always signs) reaches **high** at exactly
50 + 20 = 70 — without needing any additional corroborating signal — and so that an
Authenticode digest mismatch reaches **high** entirely on its own.

### 1. VERSIONINFO extraction — `peguise/pe_metadata.py`

Parses `RT_VERSION` with `pefile` and pulls `CompanyName`, `ProductName`, `FileDescription`,
`InternalName`, `OriginalFilename`, `LegalCopyright`, `FileVersion`, `ProductVersion`, plus
`VS_FIXEDFILEINFO` and any non-standard string-table keys. Values are decoded leniently
(UTF-8 → UTF-16LE → Latin-1) because malformed version resources are common.

### 2. Vendor claim matching — `peguise/vendor_db.py`, `peguise/util.py`

`CompanyName` is matched against the alias set in `data/vendors.yaml` (33 vendors as shipped);
if it yields nothing,
`ProductName` is matched against aliases *and* product brand names (so `ProductName` =
"Firefox" is a Mozilla claim). Matching runs in three passes:

1. **exact** on the normalized string (case-folded, accents and ®/™/© stripped,
   punctuation collapsed) or on the legal-suffix-stripped core
   ("Mozilla Corporation" → "mozilla");
2. **token containment** in either direction;
One-word **product brands** are the exception: they must match the whole ProductName rather
than being contained in it. "Windows", "Chrome" and "Java" are ordinary words, so containment
read "Quicken for Windows" as a Microsoft claim. One-word **company** names are distinctive
and keep containment — GravityRAT asserts its Intel identity purely through
`ProductName: "Intel Core"` with no CompanyName at all, and must still be caught.

3. **fuzzy** `difflib` ratio above `vendor_claim_threshold`, computed on the *identifying
   core only*. Legal and generic suffixes are stripped first, because they are long, shared
   between unrelated companies, and carry no identifying information — comparing raw strings
   scores "AVG Technologies" at 0.88 against "ATI Technologies" purely on the shared suffix,
   which is high enough to misattribute the vendor. Comparing "avg" against "ati" gives 0.33.

### 3. InternalName / OriginalFilename consistency

If a vendor is claimed, do the internal names match *any* expected pattern for that vendor's
products? A miss is scored at one of two tiers depending on the vendor's
`internal_name_check` setting — strict for vendors with an enumerable catalogue, lenient for
Microsoft-scale vendors.

Separately, `data/packer_identities.yaml` holds the self-identifying strings of packers, SFX
stubs, installer builders and script compilers (`7zS.sfx`, WinRAR SFX, `Nullsoft Install
System`, `unins000.exe`, `Au_.exe`, AutoIt, `Wextract` / Win32 Cabinet Self-Extractor, WiX
Burn, PyInstaller, Themida/VMProtect, …). A big-vendor claim coexisting with one of these
fires the highest-weight non-signature check. Entries carry `benign_for_vendors`, so 7-Zip
is not flagged for shipping `7zS.sfx`, RARLAB is not flagged for shipping a WinRAR SFX stub,
and Microsoft is not flagged for shipping `Wextract`.

Patterns here are deliberately kept to *distinctive* self-identities. A bare `uninstall.exe`
is not matched, for instance: far too many vendors name their uninstaller that for it to
identify NSIS, and matching it would fire on every genuine WinRAR and Notepad++ uninstaller.

When this check fires, the plain `internal_name_mismatch_*` check is marked **suppressed** so
the same mismatch is not counted twice.

### 4. Authenticode — `peguise/authenticode.py`

Fully offline. Using `signify` as a pure-Python PKCS#7 parser, PEguise:

- **a.** detects signature presence/absence;
- **b.** extracts the signer certificate's Subject CN (and O, as a fallback) by matching the
  `SignerInfo` issuer + serial against the certificate set. If no certificate matches, the
  CN is reported as a best effort with a warning and the signer-CN checks are marked
  `unavailable` rather than scored — the first certificate in a blob is often an
  intermediate CA, and scoring its CN against the vendor claim would be a false finding;
- **c.** compares that CN against the claimed `CompanyName` using the fuzzy/containment
  matcher plus the vendor's curated `signer_cn_substrings`;
- **d.** **recomputes the Authenticode digest** from the PE layout — everything except the
  optional-header `CheckSum` field, the security data-directory entry, and the attribute
  certificate table — and compares it against the digest in the
  `SpcIndirectDataContent`.

The digest recomputation is implemented independently in
`authenticode.compute_authentihash()` rather than being taken from `signify`, and the two
implementations are cross-checked on every file. **If they disagree, PEguise reports
`indeterminate` and the check contributes zero** rather than firing a 75-weight finding on
an ambiguous computation.

**Validated against live finds.** A batch pulled via `signature:"Mozilla" positives:20+`
contained a sample with `CompanyName: "Google Inc."` / `ProductName: "Google Chrome"` —
signed with a certificate whose Subject CN is `Mozilla Corporation`. `signer_cn_mismatch`
correctly flags the Google/Mozilla mismatch, and independently, `authenticode_digest_mismatch`
fires too: the embedded digest does not match the file. That combination — a real signer
identity attached to content it was never issued for — is exactly what the digest check
exists to catch, and it did so on a real sample, not a fixture. Score: 100/high.

A second batch, pulled via `tag:upx signature:"Adobe" positives:0`, surfaced an active,
currently-undetected campaign: 12 distinct SHA-256 files named "Adobe Download Manager"
(a tool Adobe retired years ago), UPX-packed, all built at the **identical linker
timestamp five days before this check was run**, each individually Authenticode-signed
with a matching digest under a certificate whose Subject DN carries Adobe's real EV
identity (`serialNumber=2748129`, issued by DigiCert). Real Adobe does not freshly compile
a defunct tool on a production schedule like that. `internal_name_mismatch_strict` (no
product pattern matches "Adobe Download Manager") and `packer_section_names` (UPX) fired
correctly on every one of them — 45/elevated — at a moment when zero antivirus engines
flagged any of them. Whether the certificate is stolen, leaked, or otherwise misused is not
something PEguise can determine (see the chain-of-trust limitation above), but the identical
timestamps across distinct files rule out "this is just how Adobe ships this tool" as an
explanation.

Digging into this batch also found and fixed a real bug in `compute_authentihash`: for
sections whose `PointerToRawData` falls *before* bytes already hashed — which UPX does
routinely, since it emits a zero-size `UPX0` and points `UPX1` inside the nominal header
region — the implementation re-hashed the overlap and produced a digest that never matched,
reporting `indeterminate` on every UPX-packed signed file in this batch. Cross-checking
against signify's own fingerprint (which handled it correctly) confirmed the bug and pinned
the fix: clamp each section's start to the running high-water mark before hashing.

### 5. Section-name evidence — `peguise/util.py`, `peguise/scoring.py`

Structural evidence rather than metadata evidence. If a file claims to be Mozilla but its
sections are named `UPX0`/`UPX1`, that is the same kind of contradiction as an `InternalName`
of `7zS.sfx` — Mozilla does not ship packed binaries — and it is independent of VERSIONINFO,
so it still fires on samples whose strings were rewritten wholesale.

It also **survives memory dumping**. A sandbox dump discards the certificate table, silently
invalidating the signature checks; the section table lives in the mapped image and comes
through intact. On CAPE-dumped samples this is often the only trustworthy evidence left.

**Compressors are scored separately from commercial protectors**, because their legitimate-use
rates are nothing alike:

- *Compressors* — UPX, ASPack, MPRESS, NsPack, PECompact, Petite, Upack, NeoLite, WWPack,
  kkrunchy, Shrinker, PEPack. Essentially absent from major vendors' shipping builds today,
  largely because they trip antivirus heuristics. **Weight 30.**
- *Protectors* — Themida/WinLicense, VMProtect, Enigma, ASProtect, SVKP, tElock, Y0da,
  Perplex, StarForce, Dragon Armor. These have a real legitimate user base: security vendors
  protect their own agents with them and licensed software uses them for DRM. **Weight 15**,
  and the finding says so in the evidence text rather than pretending otherwise.

**Installer section names are deliberately excluded.** `.ndata` (NSIS) and `.wixburn` (WiX
Burn) are *not* packer evidence — Firefox Setup is an NSIS installer, so a Mozilla claim
beside `.ndata` is entirely normal. They live in `util.STANDARD_SECTION_NAMES`, and an
integrity test rejects any attempt to add them to a packer entry. The VERSIONINFO-based
`nsis` entry already catches the meaningful cases (`Au_.exe`, "Nullsoft Install System").

#### Detecting randomly generated section names

Packers that randomise their section names leave no fixed fingerprint, so `anomalous_section_names`
looks at *shape* instead. A human reads `xk3jf9` as random from its character-class structure,
not from entropy — eight bytes carry far too little signal for an entropy test. Real section
names are a dot-prefixed lowercase word, or an uppercase word, optionally with a **trailing**
digit. Each departure is one feature, and a name is reported at two or more
(`matching.section_anomaly_min_features`):

| Feature | Fires when |
|---|---|
| `no_vowels` | no vowel among ≥3 letters |
| `digit_before_letter` | a digit precedes a letter (real names *suffix* digits: `UPX0`, `.vmp1`) |
| `case_alternation` | ≥2 irregular upper/lower transitions |
| `rare_letters` | ≥2 of `j q x z k v w` in eight bytes |
| `digit_run` | ≥3 consecutive digits beside letters |
| `consonant_run` | ≥4 consecutive consonants (`.rsrc` itself has a run of 4 — safe only because known names never reach this check) |
| `unknown_name` | matches no known toolchain or packer section name |
| `non_printable` | non-printable bytes, or an interior NUL with data after it |
| `empty_name` / `duplicate_name` | empty name on a section with data; name repeated in the file |

Every fired feature is named in the evidence — `xk3jf9` reports "no vowel among its letters;
a digit precedes a letter; two or more of j/q/x/z/k/v/w". A bigram or Markov model would
score marginally better in the abstract but cannot explain itself, which is the wrong trade
for a triage tool.

The allowlist is load-bearing, and it is why the lexical features are skipped entirely for
known names: `.msvcjmc`, `.00cfg`, `.ndr64` and `.wpp_sf` are all legitimate and all trip two
features apiece. A survey of 1,076 real PE files found exactly two false positives —
`.ndr64` (RPC NDR64 transfer syntax) and `.wpp_sf` (WPP software tracing), both in genuine
Windows system DLLs — and both are now allowlisted with regression tests.

**Measured recall, not assumed.** The 50-file live Themida batch above supplied 30 real
randomized section names (`ulcbptgt`, `sacknfts`, `zvzqjrbm`, …) to test the heuristic
against — the first real, in-the-wild randomizing-packer names this tool had seen, as
opposed to hand-written examples. The original six features caught 15/30 (50%): the naming
scheme is lowercase-only with no digits and no case variation, so the digit- and case-based
features never fire on it, leaving only `rare_letters` to catch anything. Adding
`consonant_run` — validated against both this batch and the full known-name allowlist before
being kept — brought that to 23/30 (77%) with zero new false positives. The residual 23% miss
is accepted rather than chased further: this check is capped at weight 10 specifically so a
miss here costs one corroborating signal, never a verdict.

### 6. Default-resource fingerprinting — `peguise/icon_fingerprint.py`

Walks `RT_GROUP_ICON` / `RT_ICON`, hashes the raw resource bytes with SHA-256, and compares
against `data/default_icons.yaml`. A vendor claim plus a packer's untouched stock icon is
meaningful; real vendors brand their installers. A non-match contributes nothing — a custom
icon proves nothing either way.

**`data/default_icons.yaml` ships empty on purpose.** See "Populating the default-icon
database" below.

---

## What PEguise explicitly does **NOT** verify

This list is printed in every report and included in every JSON result, because misreading a
signature check is the easiest way to reach a wrong conclusion.

- **No certificate chain-of-trust validation.** No root store is consulted. A self-signed
  certificate parses identically to one issued by a public CA.
- **No revocation checking.** No CRL, no OCSP, no network access at all.
- **No timestamp or countersignature validation.** A file signed with a certificate that was
  revoked or expired years ago looks exactly like a currently valid one.
- **No certificate validity-period check.**
- **No page-hash verification.** Only the whole-file authentihash is compared.
- **No unpacking.** PEguise reports *that* a file is packed, never what is inside it.
- **No behavioural, dynamic, unpacking or emulation analysis.** Nothing is executed. A file
  whose VERSIONINFO is entirely consistent can still be malicious.
- **No detection of impersonation without a VERSIONINFO claim.** A binary with no version
  resource claims nothing and is therefore invisible to every check here except the digest
  comparison.

A file that passes every check is a file where **this specific class of evidence is absent** —
not a file that is clean. In particular, malware signed with a stolen but still-valid
vendor certificate will score **zero** here, by design.

---

## What PEguise deliberately does not flag

These are non-goals, not gaps:

- **Blank, generic or sloppy metadata with no vendor claim.** `InternalName` = "main",
  `OriginalFilename` = "tool_v2_FINAL.exe", no copyright, unsigned — this is what a
  hobbyist's build looks like, and it scores 0. Every impersonation check is gated on a
  specific vendor claim existing.
- **A vendor's own packer identity.** 7-Zip shipping `7zS.sfx`, Microsoft shipping
  `Wextract` — handled by `benign_for_vendors`.
- **Unsigned binaries from vendors that genuinely ship unsigned.** Controlled per vendor by
  `almost_always_signed`.
- **Signer names that differ from `CompanyName` for legitimate reasons.** See below.

---

## Known false-positive scenarios

**Subsidiary, legal-entity and renamed signers.** `CompanyName` "Mozilla" is signed by
"Mozilla Corporation"; Microsoft system binaries are signed as "Microsoft Windows", not
"Microsoft Corporation"; acquisitions leave products branded one way and signed another for
years. PEguise handles the common shapes with substring/containment matching plus per-vendor
`signer_cn_substrings`, and the signer comparison is *deliberately* more permissive than the
claim comparison. It will still misfire on entity names with no lexical overlap at all
(a product signed by an unrelated-sounding parent company, or an OEM/reseller build). **If
`signer_cn_mismatch` is your only finding, verify the signer manually before concluding
anything.**

**Legitimate repackaging.** Enterprise deployment teams, mirrors and software-distribution
sites routinely rewrap vendor installers in NSIS, Inno Setup or 7-Zip SFX while preserving
the original vendor's VERSIONINFO. That is exactly the `generic_tool_identity` pattern and it
will score high. This is the tool's most common false positive, and it is inherent to the
technique — the static evidence is genuinely identical.

**Bundlers containing a genuinely signed component.** Three files from that same batch score
0: they carry no VERSIONINFO claim of their own, but contain a real, validly-signed Mozilla
binary embedded inside them (confirmed by locating the actual X.509 Subject DN bytes and a
nested MZ/PE header in the file). This is out of scope for a VERSIONINFO-impersonation tool
by design — the outer wrapper makes no claim, so there is nothing to contradict — but it is
worth naming explicitly: a trojanized installer that bundles a real signed component
alongside its payload will not be flagged by any check here. It would need a different
technique (recursive analysis of embedded/overlaid PE images), which this tool does not do.

**Third-party products that name a vendor.** A ProductName like "Excel-DNA Add-In Framework
for Microsoft Excel" contains the distinctive token "Microsoft" and is read as a Microsoft
claim. Such files score low (the remaining checks clear), but they do appear in output. This
is the deliberate cost of keeping one-word company tokens matching by containment — see
above for why.

**Incomplete vendor product patterns.** `data/vendors.yaml` cannot enumerate a major vendor's
full catalogue. A genuine but obscure vendor binary can fire `internal_name_mismatch_*`. This
is why lenient-tier vendors are scored at 5 rather than 15, and why the fix is to add the
pattern to the data file.

**Legitimately packed software.** The compressor/protector split was validated against two
live VT batches, not just the original malware corpus:

- `tag:themida signature:"ESET" positives:0` / `signature:"Avast Software" positives:0` /
  `signature:"Malwarebytes" positives:0` — **zero results for all three.** The original
  justification for weight 15 ("security vendors legitimately use these") does not hold up;
  it was an assumption I never checked. Corrected below.
- `tag:themida tag:signed positives:0` — 50 genuinely signed, zero-detection files. None
  claim a tracked vendor (0/33), confirming weight 15 causes no false positives *on the
  vendors PEguise tracks*. But every real legitimate user in that batch is an ordinary
  commercial ISV protecting its own product — CyberLink, Corel, Kingsoft, Tencent, WIZVERA,
  SITEPRO, EPKI Center — not a security vendor. That is the actual legitimate-use case
  protectors have; the security-vendor framing was wrong.
- A separate batch, `tag:upx signature:"Adobe" positives:0`, initially looked like a
  counter-example to the compressor weight itself — a real Adobe EV certificate signing UPX-
  packed content — until the identical build timestamps across 12 distinct files revealed it
  as an active campaign rather than Adobe's own practice (see the Authenticode section
  above). Net effect: no weight change, but real confirmation that `packer_section_names`
  (30) plus `internal_name_mismatch_strict` (15) catches something live and currently
  undetected by every AV engine.
- The Themida batch is also where `anomalous_section_names` was tuned: modern Themida does not
  leave a `.themida` section at all (only 15/50 files did) — it randomizes eight lowercase
  letters instead, with no digits and no case variation. See the heuristic section below.

**Run `tools/section_survey.py` against your own clean corpus before retuning these
weights** — any file it reports is a false positive you can fix by adding the vendor id to
that packer entry's `benign_for_vendors`.

**Trailing-data digest mismatches.** Some legitimate installers append data (configuration
stubs, affiliate tags) after signing, which genuinely breaks the authentihash. Windows itself
rejects these, but they exist in the wild. The finding is correct — the signature does not
cover the file — but it is not always malicious.

**The near-miss check.** `signer_cn_near_miss` fires when the fuzzy pass was the *only* thing
that accepted the signer. Genuine entity variants are caught earlier by the exact,
curated-substring or containment passes, so reaching the fuzzy pass is itself the anomaly.
A vendor whose signing entity has no token overlap with its `CompanyName` and is only
*lexically* similar would misfire here; add the correct CN to that vendor's
`signer_cn_substrings` to fix it permanently.

---

## Extending the reference data

All reference data lives in `data/` as YAML, entirely separate from the scoring logic. Each
file's header comments document its schema in full. The shipped `vendors.yaml` covers 33
vendors — the major software publishers plus the hardware/driver, remote-access,
messaging and security vendors whose identities are impersonated most often. `--data-dir` and `--config` point the
tool at alternative copies. A `.json` file with the same base name is accepted in place of a
`.yaml` one if PyYAML is unavailable.

### `data/vendors.yaml` — add a vendor

```yaml
  - id: acme                          # stable machine key
    display_name: Acme
    aliases:                          # spellings seen in real CompanyName fields
      - Acme
      - Acme Corporation
      - "Acme(R) Software"
    product_names:                    # brand names that count as a claim in ProductName
      - Acme Studio
    internal_name_check: strict       # strict | lenient (when in doubt: lenient)
    almost_always_signed: true
    signer_cn_substrings:             # lowercase; stops subsidiary-name false positives
      - acme
    copyright_tokens:
      - acme
    product_patterns:                 # case-insensitive regexes, re.fullmatch
      - '(?i)(acmestudio|acmeupdater|acme\w*)(\.exe|\.dll)?'
```

Keep `product_patterns` **generous**. A missing pattern costs a false positive; an extra one
costs only a missed weak signal. Use `internal_name_check: lenient` for any vendor with a
large catalogue.

### `data/packer_identities.yaml` — add a packer or installer

```yaml
  - id: acme_installer
    name: Acme Install Builder
    fields: [InternalName, OriginalFilename, ProductName]
    patterns:
      - '(?i).*acme install builder.*'
      - '(?i)acmeinst\.tmp'
    benign_for_vendors: [acme]        # never flag Acme for shipping its own stub
    note: Acme Install Builder bootstrapper.
```

Keep patterns **tight**. A pattern matching ordinary filenames (`setup.exe`, `uninstall.exe`)
fires on huge numbers of benign installers.

Add `section_names` and `category` when the tool leaves a structural fingerprint:

```yaml
  - id: acme_packer
    name: Acme Packer
    category: compressor          # compressor | protector | other
    patterns: []                  # may be empty when section_names is present
    section_names: [.acme0, .acme1]   # max 8 chars; matched case-insensitively
    benign_for_vendors: []
```

Never list a name that appears in `util.STANDARD_SECTION_NAMES` — an integrity test rejects
it, because such a name fires on every clean build.

**Always set `benign_for_vendors` when a vendor legitimately ships the identity you are
matching** — otherwise every genuine copy of that vendor's software scores 50. The test
`test_no_vendor_self_trips_on_a_generic_tool_identity` cross-checks the two databases against
each other and fails if you miss one.

### `data/weights.yaml` — retune scoring

Every weight, matching threshold, severity threshold, the score cap and the band boundaries
live here. The scoring module contains no numbers. A `weights` mapping that omits a check is
rejected at load time, so a misspelled key cannot silently disable a check. Point `--config` at your own copy to run alternative
calibrations without editing the shipped file.

### Populating the default-icon database

`data/default_icons.yaml` ships **empty**. There is no universally correct set of hashes to
bundle: default icons change between tool versions (7-Zip 9.x, 19.x and 24.x SFX modules all
differ), and a hash copied from an untrusted source produces a check that looks authoritative
while silently matching nothing. Generate your own from stubs you obtain directly:

```bash
python tools/hash_icons.py 7zSD.sfx --id 7zip_sfx_default --name "7-Zip SFX default icon" --tool 7zip_sfx --note "7-Zip 24.08 extra package"
```

Paste the printed block under `default_icons:`. Sources for stock stubs: the 7-Zip "extra"
package (`7zS.sfx`, `7zSD.sfx`), the WinRAR install directory (`Default.SFX`), an NSIS
installer built with no custom icon, an Inno Setup script compiled with no `SetupIconFile`.

Until it is populated, the icon check reports `unavailable` and contributes zero. That is
intentional and non-fatal.

### Validating the packer weights against your own corpus

```bash
python tools/section_survey.py /path/to/corpus
```

Reports every distinct section name found, which files the packer check would fire on, and
which the anomaly heuristic would flag. Run it against a **clean** corpus — a Windows
installation, a vendor download mirror, a golden-image share — before trusting the shipped
weights. Anything it reports there is a false positive; fix it by adding the vendor id to
that packer entry's `benign_for_vendors`, or by lowering the category weight in
`data/weights.yaml`.

Read-only: files are parsed, never executed.

---

## CLI reference

```
analyze.py <file_or_directory> [options]

  --json                emit machine-readable JSON
  -r, --recursive       walk subdirectories
  -v, --verbose         show every check, including those that did not fire
  --min-score N         only report files scoring at least N
  --fail-band BAND      exit 1 if any file reaches this band (low|moderate|elevated|high)
  --data-dir DIR        alternative reference-data directory
  --config FILE         alternative scoring configuration
  --all-files           analyse every file, not only those with an MZ/PE signature
```

Exit codes: `0` normal, `1` a file reached `--fail-band`, `2` usage error, `3` reference data
could not be loaded.

Directory scans filter on the MZ/PE signature rather than on file extension. A file passed
directly is always analysed, so you get an explicit "not a PE" result rather than silence.
With `--json`, a scan that finds nothing still writes a document with an empty `results`
array, so a pipeline consumer never receives empty output.

---

## Architecture

```
analyze.py                    CLI entry point, argument parsing, exit codes
pyproject.toml                project metadata (Python >= 3.11), dependencies, tool config
peguise/
  analyzer.py                 pipeline orchestration, target discovery
  pe_metadata.py              PE facts + VERSIONINFO extraction (pefile)
  authenticode.py             signature parsing (signify) + independent authentihash
  icon_fingerprint.py         RT_ICON / RT_GROUP_ICON hashing and matching
  vendor_db.py                reference data loading and schema validation
  scoring.py                  claim detection, the checks, weighted assembly
  util.py                     normalization, fuzzy matching, section-name analysis
  report.py                   text and JSON rendering
data/
  vendors.yaml                vendor reference database
  packer_identities.yaml      packer / SFX / installer self-identifying strings
  default_icons.yaml          stock default-icon hashes (ships empty — see above)
  weights.yaml                all weights, thresholds and band boundaries
tools/
  hash_icons.py               populate default_icons.yaml from a stock stub
  section_survey.py           survey section names, validate the packer weights
tests/
  pebuilder.py                minimal PE32 writer for fixtures
  pesigner.py                 real Authenticode signatures for fixtures
  make_fixtures.py            fixture corpus generator
  test_peguise.py             the test harness
```

### Graceful degradation

Nothing in a malformed sample can crash a scan. Each stage catches its own failures and
reports a status:

- `pefile` missing or the PE unparsable → metadata `error`/`unavailable`; the file still
  produces a result with every check marked unavailable.
- `signify` missing or the PKCS#7 blob unparsable → signature checks report `unavailable`
  while all signature-independent evidence is still scored.
- Resource directory unparsable → icon check reports `error`, other checks unaffected.
- Authentihash implementations disagreeing → digest check reports `indeterminate`, weight 0.
- No certificate matching the `SignerInfo` → signer CN reported as a best effort with a
  warning; the signer-CN checks report `unavailable`, weight 0.
- Malformed resource tree nodes → skipped individually; the icon walk continues.
- Malformed reference data → a clear `ReferenceDataError` and exit code 3, before any file is
  touched.

---

## Test harness

```bash
.venv/bin/python -m pytest tests/ -q
```

Fixtures are generated from scratch by `tests/pebuilder.py`, a minimal PE32 writer — no
third-party binaries are committed and nothing is downloaded. The fixtures are inert
containers whose only interesting content is their resource directory; they are parsed, never
executed. Signed fixtures carry a **real, parsable Authenticode signature** built by
`tests/pesigner.py` using a throwaway self-signed certificate minted at test time. Because
PEguise never validates chains, a self-signed certificate exercises exactly the same code
path as a commercially issued one.

The four required scenarios:

| Case | Fixture | Expectation | Result |
|---|---|---|---|
| **1. Positive control** — genuine signed vendor binary | `signed_case1_mozilla_correct.exe` | low | 0, no checks fire |
| **2. Known bad** — `CompanyName`="Mozilla", `InternalName`="7zS.sfx", unsigned | `case2_mozilla_claim_7zsfx.exe` | high | 75 (`generic_tool_identity` + `unsigned_but_vendor_signs` + `copyright_vendor_mismatch`) |
| **3. Honest freeware** — sloppy `InternalName`, unsigned, no vendor claim | `case3_honest_freeware.exe` | low | 0, all impersonation checks `not_applicable` |
| **4. Subsidiary signer** — `CompanyName`="Mozilla", signer CN="Mozilla Foundation" | `signed_case4_subsidiary_cn.exe` | not over-flagged | 0 |

(Case 2 scores 50 + 20 + 5; the core claim-plus-packer-plus-unsigned pattern alone reaches 70.)

Section-name coverage: compressor vs protector weighting, the ValleyRAT shape (dot-prefixed
`.upx0`/`.upx1`), packer sections staying silent without a vendor claim, `.ndata`/`.wixburn`
never firing, metadata and section evidence counting independently, same-tool suppression,
each anomaly feature, the two real-world malformed-name shapes, and a regression list of 19
genuine section names that must never be flagged.

**Reference-data integrity** is tested as its own concern, because the databases are meant to
be extended: every regex must compile, no alias may be claimed by two vendors, every alias and
product name must resolve back to its own vendor, every `benign_for_vendors` id must exist,
and no vendor may ship a name that a generic-tool entry claims without an exemption. Each of
the 33 vendors is additionally checked against a plausible genuine binary (must score 0) and
against the impersonation pattern (must reach `high`).

Plus coverage for: the digest-mismatch path from a real signature; tamper detection
(appending bytes to a signed file); the near-miss/typosquat check; genuine 7-Zip SFX not
being flagged for its own identity; strict vs. lenient name-mismatch tiers; icon-hash
matching against a generated fixture icon; score capping; weights being read from config
rather than code; non-PE, truncated and empty inputs degrading without crashing; a simulated
absence of `signify`; and the CLI's JSON, text, filtering and exit-code behaviour.

### Running against a real signed binary

The synthetic corpus covers every code path, but real vendor binaries have real quirks
(multiple signatures, nested signatures, SHA-1 legacy digests, unusual DN encodings). To run
the end-to-end positive control against a binary you supply:

```bash
PEGUISE_TEST_SIGNED_PE=/path/to/genuine_signed.exe .venv/bin/python -m pytest tests/ -q
```

Use a genuine signed Microsoft system binary (a copy of `C:\Windows\System32\notepad.exe`) or
a signed Mozilla installer. The test skips when the variable is unset.

---

## Dependencies

Python 3.11 or newer. `pefile`, `signify` (0.9 or newer — the PE signature API PEguise
imports moved in 0.9, and an older release would silently disable every signature check),
`PyYAML` — all pure Python, all working fully offline. `signify` is used
strictly as an ASN.1/PKCS#7 parser; its chain-validation and timestamp-verification
facilities are never invoked. `pytest` is needed only for the test harness.

## License

MIT. See [LICENSE](LICENSE).

## Scope

PEguise performs static analysis of files at rest. It does not execute, unpack, emulate,
sandbox, decompress or otherwise run any analysed sample, and it makes no network requests.
