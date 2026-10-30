# Immutable local NVD/CNA catalogs

WiFiScope can build and search a larger catalog from **explicit local NVD 2.0
JSON or gzip files**. It performs no download, collection, device operation or
background update. A stored CVE is public catalog metadata, not a finding about
a device. The index layer does not evaluate applicability; the explicit inventory
audit described below supplies a separate bounded three-valued evaluator.

```console
python -m wifiscope catalog build --input annual.json.gz --input recent.json.gz --out NEW.db
python -m wifiscope catalog build --input feed.json.gz --sha256 EXPANDED_SHA256 --out PINNED_NEW.db
python -m wifiscope catalog info --db NEW.db
python -m wifiscope catalog search --db NEW.db --vendor vendor_z --product product_z --limit 20
python -m wifiscope catalog search --db NEW.db --cve CVE-2026-12345
```

Give one `--sha256` per input, in input order, or omit every pin. Build pins are
SHA256 of **expanded bytes**, including whitespace and an optional UTF-8 BOM,
matching the NVD META convention. Compression is detected by gzip magic bytes.
`info` and `search` accept `--sha256 DB_SHA256` to check the complete database file.
Digests establish byte integrity against the caller's expected value; they do
not authenticate a source or make an arbitrary database NIST-approved. A
`pin_verified` feed field records the builder's assertion, not an independent
signature check by the reader. Official feed information:
[NVD data feeds](https://nvd.nist.gov/vuln/data-feeds).

Output must be a new file in an existing local directory. Existing files, links,
link ancestors, Windows junctions, URL/UNC syntax and Windows mapped remote drives
are refused. Publication uses an exclusive hard link after staging, commit,
close and verification; filesystems without hard-link support fail safely.
Supplied feeds and earlier generations are unchanged. Use local storage; other
OSes' mounted remote filesystems cannot be distinguished portably by this API.
Input and database paths, descriptions and references supplied by feeds are not
printed in normal JSON output. Search references always use the NVD detail URL.

## Data and coverage

Any valid CVE identifier can be stored, including hardware, OS, unfamiliar
vendors, CNA-only records, metadata-only records and Rejected CVEs. Literal
vendor/product comparisons are case insensitive (`casefold`), with no aliases,
fuzzy matching, product whitelist or SQL wildcard interpretation. Rejected CVEs
remain searchable and are excluded from `relevant()` candidate retrieval.

NVD configuration trees retain AND/OR, negate, nodes, vulnerable=false context,
CPE criteria, matchCriteriaId and all four version bounds. Missing operators use
OR without flattening trees. CNA `affected` source/affectedData rows retain
vendor/product, cpes, defaultStatus and versions with version, status, lessThan,
lessThanOrEqual, versionType and changes. Changes retain source order. Version
strings such as `0` and `2.*` are data; the catalog does not interpret ranges.
Platforms, modules, programFiles, programRoutines, routines, collectionURL,
packageURL, packageName and repo are retained under `context` and carry an explicit
`cna_context_unknown` gap. Unknown future fields or malformed applicability
shapes preserve the CVE with controlled gaps and unsupported flags. Descriptions,
credits and reference prose are discarded. No imported text becomes instructions.

`info()` reports unique `records`, `input_records`, `duplicate_records`,
`rejected_records`, `without_applicability` and `unsupported_records`, plus a
content-derived `catalog_id`, schema_version and `feeds`. Duplicate count is input
minus unique. Without-applicability means both configuration and affected
containers were absent/empty, rather than an assessment that a CVE is harmless.
Unsupported means at least one controlled gap (including unknown status, dates
or CVSS), not that every record without gaps has a supported matching algorithm.
Feed metadata includes zero-based feed_index, source_sha256, expanded_sha256,
source_bytes, expanded_bytes, records, total_results, start_index,
results_per_page, original timestamp, partial and pin_verified. Missing total,
a nonzero start, or a record count different from total is explicitly partial.
A source with partial=false only describes that supplied envelope; it does not
prove the source covers every CVE or every product.

Duplicate CVEs retain membership in every input feed. Newest comparable parsed
lastModified wins. Equal-time different normalized content, conflicting missing
times, or mixed timezone-aware/naive timestamps fail the complete build. Exact
normalized duplicates deduplicate even with missing dates. Dates without a zone
remain source dates with no invented timezone or verified review date.

## Python interfaces for downstream consumers

```python
from wifiscope.catalog_store import CatalogIndex, build_catalog

info = build_catalog([feed_path], new_db_path,
                     expected_sha256=None, cancel=None, progress=None)
with CatalogIndex(new_db_path, expected_sha256=None) as index:
    info = index.info()
    summaries = index.search(cve=None, vendor="vendor_z", product="product_z",
                             limit=20, offset=0)
    full = index.get("CVE-2026-12345")
    page = index.relevant([
        {"kind": "cpe", "part": "a", "vendor": "vendor_z", "product": "product_z"},
        {"kind": "cna", "vendor": "literal vendor", "product": "literal product"},
    ], limit=50000, after=None)
```

`CatalogError` and its `CatalogCancelled` subclass (catalog_stream) inherit
ValueError. SQL, decoding and filesystem errors cross the public boundary as
controlled errors. `CatalogIndex` is a context manager with an idempotent close.
Opening it only reads the selected local file.

`search` accepts exact CVE **or** both vendor and product, or neither for CVE-order
browse. limit is integer 1..100; offset is integer 0..1000000; booleans are refused.
Identity strings are 1..256 characters. Summary dictionaries contain exactly
`cve`, `status`, `published`, `modified`, `reference`; no configuration bodies.
`get` returns None for a valid missing CVE, otherwise a fresh full dictionary:

- `cve`, controlled `status`, original valid `published`/`modified` or None.
- `cvss`: list of `{score: number 0..10, version: "2.0"|"3.0"|"3.1"|"4.0", source: str}`.
- `configurations`: list of nodes. Each node has `operator: "AND"|"OR"`,
  `negate: bool`, `nodes: list[node]`, `cpeMatch: list[match]`, `unsupported: bool`.
  Match has `unsupported: bool` and any retained supported `criteria`,
  `vulnerable`, `matchCriteriaId`, versionStartIncluding, versionStartExcluding,
  versionEndIncluding, versionEndExcluding. A supported match has criteria and
  boolean vulnerable; absent/malformed required fields set unsupported.
- `affected`: list of `{source: str|None, affectedData: list[row]}`. Each row has
  `vendor`, `product` (str|None), `defaultStatus` (affected/unaffected/unknown|None),
  `versions`, `context`, `cpes` and boolean `unsupported`. Each version has boolean
  `unsupported`, `changes` and retained version/status/lessThan/lessThanOrEqual/
  versionType; each change is `{at: str, status: affected|unaffected|unknown}`.
- `applicability`: `{configurations, affected}`, each missing/present/unsupported.
- `gaps`: sorted unique controlled codes: status_unknown, timestamp_unknown,
  cvss_unknown, configuration_unknown_field, configuration_shape_unknown,
  cpe_unknown, cpe_pattern_unknown, affected_shape_unknown, affected_unknown_field,
  cna_identity_unknown, cna_context_unknown, cna_version_unknown.
- `catalog_id`, `reference`, `feed_membership` (zero-based input numbers),
  `source_sha256` (sorted distinct **expanded** source digests).

Statuses are Received, Awaiting Analysis, Undergoing Analysis, Analyzed, Modified,
Deferred, Rejected or Unknown. Unknown source statuses create a status_unknown gap.
Vendor/product literals preserve original spelling in full records. CPE identity
keys include parts a/o/h, including environmental leaves. Explicit CNA cpes add
CPE keys; literal CNA vendor/product add separate CNA keys. No CNA-to-CPE alias is
inferred. Unknown/generic CPE vendor/product patterns use broad retrieval buckets
and gaps, rather than disappearing from candidate retrieval.

`catalog_records.parse_cpe23(string)` is a lexical helper, **not a matcher**. It
returns None for malformed syntax or a dictionary with the eleven unescaped CPE
fields part/vendor/product/version/update/edition/language/sw_edition/target_sw/
target_hw/other plus `wildcard_fields` (names containing an unescaped * or ?).
Escaped colons, backslashes and wildcards remain literal. ANY and NA retain their
literal `*` and `-` representations; consumers must supply their semantics.

`relevant(identities, *, limit=50000, after=None)` accepts 1..8192 exact identities
of the shapes above. limit is integer 1..50000. The returned dictionary contains
`records` (full records, deduplicated in CVE order), `truncated: bool`,
`next_after: CVE|None`, `examined: int`, `identity_queries: int`,
`identity_queries_total: int`, `work_limited: bool`. Each identity/broad bucket is
queried after the same cursor; unioning the smallest limit+1 CVEs preserves stable
pagination across sources and identities. Pass next_after as after on the next
call with the same identities. A complete last page has truncated=false and
next_after=None. Returned records serialize to at most **16MiB** of compact UTF-8
JSON including list punctuation. A single record larger than that page budget
raises a controlled error.

`examined` counts retrieved index-hit rows (including duplicate identity hits).
A **per-call** 200000-hit work budget, independent of the million-record generation
limit, yields work_limited=true, truncated=true and next_after=None: that partial
union has no safe continuation. Narrow the supplied identities and disclose
unexamined work. SQL also has a 20-million-instruction budget per public call;
exceeding it raises a controlled error. Byte or record truncation with a complete
identity union has a safe next_after. Truncation, missing applicability and
unsupported gaps must never become a no-vulnerability clearance claim.

## Resource and SQLite boundaries

Generation limits: 64 inputs; 256MiB actual source bytes and 2GiB expanded bytes
per file; 1000000 input records; 16MiB encoded record; JSON depth 32 and 250000
lexical decoded nodes (including object keys); 8192 CPE-match leaves and 4096
CNA rows per CVE; 8GiB database. Numbers are finite, integers have at most 18
digits, float tokens at most 64 characters and exponent magnitude at most 100.
Envelope keys have at most 256 characters and 256 keys; each unknown envelope
value has the same 16MiB/depth/node bounds and cannot supply vulnerability rows.
Typed normalization overhead is bounded independently (16MiB stored body,
40 levels, 4000000 nodes (including normalization overhead) on readonly decode). Identity fields are 256 characters;
CPE criteria 2048; CNA version/bounds/changes 1024. Overlong applicability literals
become explicit gaps, not truncated version assertions. Syntax, CVE ID, resource,
source-pin, disk, cancellation and duplicate-conflict failures abort generation.
The CPE-leaf cap is per CVE across the complete tree: 8192 is accepted, while
8193 aborts the generation without dropping conditions. This finite compatibility
budget does not claim that every annual or future feed record will fit.
The CNA affected-row cap is also per CVE, summed across source containers:
4096 rows are retained in source order; 4097 aborts the whole generation without
publishing a partial database. Synthetic 2749-row and 4096-row build/read controls
verify exact retention. The database schema remains version 1; no migration is
needed. Other source, normalized-body, depth, node, database and query limits
remain unchanged.

Cancellation accepts a callable or Event-like is_set(), checked during chunks,
records and SQL progress. Progress receives fresh dictionaries containing only
status running/complete/cancelled, numeric records/expanded_bytes/feed_index/
elapsed_ms, at most five running updates per second plus a final event. Callbacks
cannot mutate subsequent events. Callback exceptions abort and clean owned
staging files. The complete callback validates readiness before exclusive
publication so a callback failure can still abort without a published database.
Publication failure still makes build raise; successful return is the receipt.

Before publication, the builder runs SQLite `quick_check` on its private, closed,
size- and schema-verified generation. This full scan has a separate finite budget
of 64 VM instructions per database byte (at most 549755813888 at the 8GiB cap)
and a 600-second elapsed deadline. The linear allowance accommodates inspection
of the whole bounded database. Every 1000 VM instructions, the scan checks both
budgets and cancellation; the deadline and cancellation are checked again after
the scan. Progress checks cannot interrupt an individual blocking filesystem
operation, so the deadline is checked when SQLite resumes executing instructions.
Integrity errors, exhausted scan budgets and cancellation abort publication and
clean owned staging files. The ordinary readonly handler is restored afterward;
public queries keep their 20-million-instruction limit and have no scan bypass.

SQLite application_id is 0x57534332, user_version is 1. Exact schema objects:

```sql
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE feeds (feed_index INTEGER PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE records (cve TEXT PRIMARY KEY, status TEXT NOT NULL, published TEXT, modified TEXT, body TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE identities (kind TEXT NOT NULL, part TEXT NOT NULL, vendor TEXT NOT NULL, product TEXT NOT NULL, cve TEXT NOT NULL, PRIMARY KEY (kind, part, vendor, product, cve)) WITHOUT ROWID;
CREATE TABLE memberships (cve TEXT NOT NULL, feed_index INTEGER NOT NULL, PRIMARY KEY (cve, feed_index)) WITHOUT ROWID;
CREATE INDEX identities_names ON identities (vendor, product, cve);
CREATE INDEX identities_cve ON identities (cve);
CREATE INDEX memberships_feed ON memberships (feed_index, cve);
```

metadata has one `info` canonical JSON value; feeds.body holds the corresponding
feed metadata JSON. records.body holds the normalized full record before appended
provenance fields. identities.kind is cpe/cna/broad; broad uses empty vendor/product
and part a/o/h or *. CNA part is empty. Memberships retain superseded source input
numbers as well as winning-record sources. Schema text and all object names must
match exactly, including rejection of extra sqlite_stat tables, views, triggers,
virtual tables and custom indexes. Reader uses mode=ro&immutable=1, query_only,
trusted_schema=OFF, disabled extensions, denied authorizer writes/ATTACH/DDL/
extension functions, SQLite limits and a progress handler. Fixed parameterized
queries validate returned summaries, metadata and full records. No migration,
repair or sidecar generation is performed. Files must be self-contained immutable
SQLite generations; an external writer or WAL is outside this format's contract.

The optional synthetic capacity test is explicitly local:

```powershell
$env:WIFISCOPE_CATALOG_STRESS='1'
python -m unittest discover -s tests -p test_catalog_store.py -k generated_50001_record_capacity
```

It generates 50001 CVEs in a temporary directory and verifies indexed lookup.
Capacity evidence does not establish complete NVD coverage or product superiority.

## Explicit inventory audit / 显式清单审计

Both desktop modes expose **漏洞库与资产清单**. Opening/switching the panel reads
no file, opens no database and collects nothing. Follow the three Chinese steps:
open/build a local catalog; select/import inventory; run and inspect a preview.
Professional settings expose ordered source pins, explicit new-file build,
database pin and budgets. Source file selection does not hash/read the files.
Browse uses exact CVE or literal vendor+product, 20 rows per page; edits reset
pagination and stale rows. Details show typed models/provenance and fixed NVD
links. Rejected, missing applicability and unsupported rows remain distinct.

The local form extracts only the explicitly selected detail identity: literal CPE
part/vendor/product or literal CNA vendor/product. Enter your own asset label
and version; advisory versions, ranges and environmental requirements never
become observations. Literal punctuation in a user version is safely escaped in
CPE. Missing extra attributes remain ANY/unknown, `complete_parts=[]`, source
`local`, identification `declared`, time null. Equal form labels intentionally
share `manual:<label>` asset IDs (label ≤249 characters); component IDs hash the
asset/identity/literal version/scheme/first unused collision ordinal. Multiple assets/components
and explicit removal are supported. These are local declarations, never proof of
installation or network discovery, and are never implicitly joined to IP assets.
Pattern-only/unsupported identities cannot replace the previous inventory.

Only a validated audit report becomes an apply/export preview. Build/open/search/
detail/import/form actions invalidate report eligibility and preserve the current
main report, case snapshot and triage. All file parsing/build/open/query/audit/
export work runs through the shared worker, cancel event, owner and Tk queue;
each SQLite connection is opened and closed by its worker. Closing the owner
cancels work and ignores late delivery. Catalog progress preserves its own units,
coalesces queued updates and emits at most five running events/second plus final;
capture counters retain their existing semantics. Cooperative cancellation cannot
interrupt an individual filesystem operation or the current bounded readonly
query; the latter retains its 20-million-instruction ceiling.

```console
python -m wifiscope catalog audit --db NEW.db --inventory inventory.json --out NEW_AUDIT
python -m wifiscope catalog audit --db NEW.db --inventory bom.json --inventory-format cyclonedx --out NEW_SBOM_AUDIT
python -m wifiscope catalog audit --db NEW.db --inventory document.spdx.json --inventory-format spdx
python -m wifiscope catalog audit --db NEW.db --inventory scan.xml --inventory-format nmap --out NEW_NMAP_AUDIT
python -m wifiscope catalog audit --db NEW.db --inventory inventory.json --input ORIGINAL_REPORT.json --sha256 DB_SHA256
```

`--inventory-format` defaults to `native`; there is no automatic format guessing.
No `--input` means a new empty schema1 local report, not collection. A previously
redacted report is refused: use original local evidence or choose the explicit
empty-report action. `--out` creates a new JSON/CSV/static-HTML bundle; stdout is
only `{status,bundle_created:true}`. Without it stdout is the shared default HMAC
projection. `--include-identifiers` is a deliberate local export choice and
cannot restore identities from an already redacted report. Catalog hashes stay
public; inventory IDs, CPE/CNA/version strings and source-document hashes use the
same per-export HMAC closure as findings, evidence joins and case snapshots.
Source timestamps/controlled gap counters remain public. Exit 0=complete,
1=partial, 130=cancelled, 2=controlled refusal.

Native schema1 preserves declared provenance and explicit `complete_parts`
claims. Assets 1..1024, total components 1..8192. Each component has either an
explicit CPE 2.3 or literal CNA vendor/product/version, with `version_scheme`
numeric/semver2/openssh-portable/unknown, source and identification enums,
nullable source timestamp/digest. Absence is open-world unless the native author
explicitly closes a part. The form and SBOM adapters never close parts. Audits
evaluate AND/OR/negation, environmental predicates, CPE attributes and supported
declared version ordering; unsupported/missing conditions remain unknown.
CPE name relations remain case-insensitive. Declared version ordering and CNA
exact-version declarations use the original decoded literal version, preserving
case and escaped characters: SemVer prereleases `RC.1` and `rc.1` differ. The
strict CPE parser exposes this spelling as `Attribute.original_text`; existing
case-folded `text` and `tokens` keep their matching semantics. Unsupported NVD
configuration criteria remain unknown at the strict parsing boundary, and the
detail chooser omits them while retaining other literal identities. Source
criteria and controlled gaps are preserved; no CPE conversion is inferred.

A CNA version declaration with both `lessThan` and `lessThanOrEqual` is
unsupported even when their values agree. New normalization retains both fields
with `cna_version_unknown`; evaluation also treats older typed declarations as
unknown without falling through to `defaultStatus`. Independently supported
source models retain their existing three-valued alternative-model behavior.
Budgets: ≤50000 asset-CVE pairs, ≤50000 relevant records, ≤4096 retained results,
≤500000 predicates, plus aggregate byte/node bounds. Cancellation/work-limit
reports retain partial state and nullable unexamined counts. No result is a
confirmed installation, exploitability assertion or safety clearance.

## Bounded SBOM adapters / 有界 SBOM 身份提取

`inventory_import.import_inventory(path, *, format, cancel=None)` returns an
independent normalized schema1 inventory. It reads one explicit regular local
file, rejects network/link paths, duplicate JSON keys, nonfinite numbers, depth
>32, >250000 nodes or total source >16 MiB before unbounded decoding/copying.
No external schemas/references/URLs/PURLs are fetched. Unknown metadata is not
copied. This extracts bounded identities, **not full SBOM schema conformance**.

| Explicit format | Supported target entries | Refused / not inferred |
| --- | --- | --- |
| native | Exact existing schema1 contract; source/time/complete-parts retained | Unknown schema fields and malformed identity |
| cyclonedx | JSON `bomFormat=CycloneDX`, `specVersion=1.6` or `1.7`; root/nested `components`, optional `metadata.component`; explicit CPE 2.3 | Tools/dependencies/services/pedigree are not installed components; names/suppliers/PURLs are not CNA/CPE aliases |
| spdx | JSON `spdxVersion=SPDX-2.3`; packages' SECURITY/cpe23Type externalRefs with explicit CPE 2.3 | `SPDX-2.3.1` root is refused; patch spec title is not a root-version synonym; package names/PURLs/suppliers are not inferred |
| nmap | Local XML direct service/osclass explicit CPE URI or formatted assertions; one source host per asset, typed uncertainty | No scanner execution, banner-to-CPE inference, address merging, installed-state proof or full Nmap/legacy URI conformance |

SBOM CPE identity requires literal part/vendor/product/version, no target patterns;
unspecified extra attributes may remain ANY/NA. CPE 2.2, malformed/patterned CPE,
PURL-only or package-only entries remain counted gaps. If no usable CPE remains,
the complete import is refused with a controlled explanation; no empty clean
audit is possible. >8192 retained components refuses the entire import without
truncation. Cancellation/callback failures preserve the previous inventory.

One SBOM document is one logical asset with no inferred address. Source=sbom,
identification=imported, complete_parts empty. Source SHA256 is over exact input
bytes. Time is CycloneDX metadata.timestamp or SPDX creationInfo.created, or
null; report/audit time never substitutes for source time. Optional/excluded,
1.7 isExternal/versionRange and ordinary included components all remain
runtime-state-unverified; versionRange never becomes an observed version.

IDs are deterministic for the exact document bytes and depth-first source-entry
ordinal (root components first, metadata.component last), plus normalized decoded
CPE kind/text. Equivalent case/escaped-literal CPE repetitions within one source
entry retain one component; identical CPEs on separate entries retain separate
components. Document byte changes deliberately change document/component IDs.
`input_entries` counts every target entry including nested/unmapped ones;
`input_cpe_identifiers` counts explicit CPE assertions before filtering;
`retained_components` counts normalized retained components; `unmapped_entries`
counts target entries with no usable CPE; `unsupported_identifiers` counts
unsupported assertions/references including repeats; `duplicate_identifiers`
counts within-entry repeated equivalent identifiers including unsupported raw
repeats. These units are independent and must not be summed into a package total.
Gaps include SBOM/import/runtime unverified, missing time, unsupported/unmapped
identifiers and duplicates. Source gap counters persist in ordinary exports.

Removing an imported component retains original source counters/digest/time,
updates retained_components and marks partial/input-partial. Adding manual facts
to a document import is refused to avoid misrepresenting the single source scope;
click **新建空白声明清单** to explicitly replace the panel inventory first. Ordinary
native inventories without import_context can be extended by the form.

The explicit **完整合成演练** action creates an exclusive private temporary source
and database, builds and audits them, then closes/deletes that temporary directory.
It returns a synthetic report preview only, without changing the selected real
catalog/inventory or existing small-pack demo. Invented Example Vendor/Sample
Labs identities cover CPE, CNA-only, positive/negative and missing-OS controls;
all component source times remain null and all identification is declared. No
filesystem creation occurs merely opening the panel.

## Accepted measured capacity (2026-10-29)

These are controller-measured single local runs, not reruns of the desktop commit,
comparative benchmarks, repeatability estimates or market/global coverage. Shared
Windows 11 desktop, Python 3.12.10, SQLite 3.49.1; process peak is Windows
PeakWorkingSetSize, excluding OS cache, children and system-wide RAM. Rows 1/2
were measured at accepted `a086dcf`, rows 3/4 at `40f48a0` (same public API/schema,
later builder-only integrity-scan budget fix).

| Input | Source records | Unique stored | Build s | Complete query batch s | Peak process bytes | DB bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Official NVD recent | 5811 | 5811 | 13.855 | 0.029 | 34582528 | 15474688 |
| Official NVD 2021 annual | 23481 | 23481 | 74.920 | 0.503 | 53252096 | 187219968 |
| Official recent + 2021 | 29292 | 29284 | 171.483 | 1.301 | 51806208 | 202665984 |
| Synthetic invented capacity | 1000000 | 1000000 | 343.181 | 1.489 | 33136640 | 825470976 |

Query times include open/info/get/known/relevant acceptance batches; synthetic
batch includes first/last get and two 100-row pages for ten identities. They are
not per-query latency. Official expanded hashes matched NVD META at retrieval;
combined input had 8 duplicate rows, 1090 Rejected/without-applicability rows and
10154 records with a metadata/semantic gap. A separate second synthetic build
cancelled in 0.282s; this is not a maximum cancellation latency for every stage.
Earlier valid-feed leaf-cap and million-row integrity-scan-budget refusals led
to explicit finite fixes; no uninterrupted-success claim is made. No datasets
are distributed and acceptance of these sources does not guarantee future feeds.

A subsequent 25-annual-feed attempt stopped safely at the former 2048 CNA-row
cap and published no database. After the reviewed 4096-row limit change, the
2026-10-29 historical acceptance at source commit
`d676fdd01edd47fbf7cb830bad1347e246352e7f` (public product-equivalent
`54112f97f44392c23ad40365c7474e3b8c884ebc`) successfully indexed all 25 supplied
official annual files, 2002..2026: **416321 input / 416321 stored / 0 duplicates**,
18842 Rejected/without-applicability records and 224169 records with a
metadata-or-semantic gap. This is historical indexing acceptance, not a fresh
benchmark of the Nmap feature or complete inventory assessability. These are
catalog records, never 416321 confirmed vulnerabilities on a network.

The inventory evaluator still has independent work limits. Large annual-catalog
audits can reach the 500000-predicate cap before every source host is examined;
they remain partial with `unexamined_pairs=null`. No complete annual inventory
coverage or safety clearance follows from the accepted indexing count.

Actual-source applicability at accepted `5be2ea4` used the 29284-record combined
catalog and six explicitly synthetic declared components/assets: 158 relevant
records, 891 asset-CVE pairs, 10 modeled true / 809 unknown / 72 false, 819 retained,
0 unexamined, 217814 predicates. Apache CVE-2021-41773 and CNA-only CVE-2012-20003
positive/negative/open-world controls passed. The 7.505501s run includes audit,
projection, bundles and case IO; it is not isolated audit latency. Default HMAC,
re-export non-resurrection and case/triage joins passed. None are device findings.

Reproduce an independent synthetic run without downloads:

```console
python -m wifiscope.catalog_benchmark --directory NEW_SYNTHETIC_DIR --records 10000
python -m unittest tests.test_inventory_import tests.test_catalog_gui tests.test_catalog_benchmark
```

The helper supports 1..1000000 invented records, retains generated gzip/database
in the explicit new local directory and prints count/build/query/cancellation/
memory/hash receipts without paths. It uses **tracemalloc Python allocation peak**,
which is not the process-peak metric above. Its query batch is open/info/first+last
get and up to two 20-row pages for one identity. A separate build cancels on its
third cooperative check and verifies cleanup; this is a small cancellation probe,
not an in-scan latency guarantee or the controller's separate million-row run.

## Offline Nmap identities / 离线 Nmap 身份主张

Select `nmap` explicitly in CLI or the catalog panel, then choose an existing
local XML file and click **明确导入**. Opening/switching modes/tabs performs no IO
or collection. No Nmap executable is required or launched. Direct service/cpe
and osclass/cpe assertions are supported for a/o/h parts; script CPEs, hostnames,
MACs, banners, command/path/prose and nested script output are ignored. Each
source host remains its own asset; retain 1..16 unique canonical literal IPs
when available. Addressless identities remain logical source assets, never
automatically merged with collected devices. `complete_parts` stays empty.

Bounds apply together: source XML ≤16 MiB, depth 64, 200000 elements, 4096 source
hosts, 65536 port rows and 65536 combined service+osclass entries; attributes
≤4096 characters, text ≤65536. Normalized schema1 inventory ≤16 MiB, depth 32,
250000 nodes, 1024 retained assets and 8192 components. Overflow, no usable
identity or cancellation refuses the whole import without truncation.

CPE URI conversion is a finite reviewed profile: input/output ≤4096 characters,
decoded field ≤1024 tokens; indexed folded decoded vendor/product literals each
≤256 characters (oversized names become unsupported counts/gaps). Omitted URI
fields become ANY, ordinary `-` becomes NA; explicit NIST printable punctuation
percent mappings, `%01`/`%02` edge patterns and packed edition are supported.
Literal `%2a`/`%3f` remain escaped literals; decode once, so `%2502` stays literal.
Malformed escapes, unsupported percent encodings, controls, invalid parts,
embedded/repeated-star patterns and malformed packing are refused. Language is
limited to 2..3 ASCII letters with optional 2-letter/3-digit region. This is not
full legacy URI, RFC5646 or NIST conformance certification. Original decoded
version case survives formatted conversion; existing case-insensitive identity
matching and catalog-source unsupported-criterion policy remain independent.

Preview distinguishes `service`/`osclass`, `probed`/`table`/`unknown`, protocol,
port/state, host status, confidence (source scale 0..10), accuracy (source 0..100),
URI/formatted binding, typed metadata validity, source time/time basis and
`presence=asserted|possible`. These are unverified scanner claims, never a local
measurement or vulnerability probability. Asserted admission requires a valid
probed/open/up application identity with address/port/protocol and supported
literal attributes. OS/hardware, table/unknown, patterned, invalid or addressless
evidence stays possible. Alternative OS fingerprints cannot jointly establish
an AND environment; possible evidence cannot prove positive or negative version
or environment facts. Unsupported/missing conditions remain unknown.

Source SHA256 covers exact XML bytes. Source time prefers valid host end, then
host start, then document start only when earlier fields are absent; supplied
invalid/inverted host times remain null/unknown without falling back to now or
file time. Document time stays separate. Missing completion or explicit source
error sets partial; all imports retain unverified runtime/scope gaps.

`input_entries=service_entries+osclass_entries`, including entries without CPE;
`input_cpe_identifiers` counts direct assertions before filtering. Accepted typed
equivalents deduplicate only within one source entry with original literal
version agreement. Repeated rejected raw text counts separately as input and
unsupported, never duplicate; existing SBOM counter rules above stay separate.
`retained_components`, `unmapped_entries`, `unsupported_identifiers` and
`duplicate_identifiers` retain their distinct units. `scanner_summary` exposes
input/retained/unmapped hosts, service/osclass entry counts and source
`scan_status=success|error|unknown`; no counter is confirmed vulnerability count.

Select a component row and explicitly choose **明确设置所选组件版本排序**:
`unknown` (default), `numeric`, `semver2` or `openssh-portable`. This independent
worker-validated analysis edit changes only that component's scheme, never its
IDs, original CPE/version spelling, addresses, metadata/digest/time/counts or
possible presence. Ordering is an analyst choice, never inferred from a banner
or vendor, and never confirms a hypothesis. It invalidates the old preview;
run audit again. Removal preserves original source entry/CPE/scan-status counts,
updates retained components and retained/unmapped hosts, and marks partial.
Unretained hosts may include deliberate removals; removing the final component
produces the existing explicit empty scope, which cannot audit as clean.
Imported scope still requires an explicit new manual scope before adding
unrelated declarations.

The new **Nmap 合成演练** creates temporary invented XML and catalog records with
two documentation-address hosts, a probed service and mutually exclusive OS
hypotheses. It marks `report.synthetic=True` before audit even though component
source is `nmap`. Existing selected DB/inventory and main report/case/triage stay
unchanged until deliberate Apply; the earlier demos remain. Display preparation
runs in shared workers: source preview ≤about 16 Ki characters, full audit text
≤65536, ≤3 components per host/result, ≤160 characters per identity/version field;
omissions are labeled and do not truncate stored inventory/results.

Only validated audit reports can Apply/export; metadata/import/order actions
cannot. Default shared HMAC covers all addresses, IDs, CPE/version and document
digests while preserving report/case/CSV/HTML joins. Raw export requires an
explicit choice; re-export cannot resurrect pseudonymized identities. Additive
schema1 addresses/scanner/counter fields may be refused by older strict readers.
Native Linux/RF validation, novice studies, universal coverage and market
superiority are not established by synthetic Tk/CLI tests.

Matching prepares an independently validated, owned inventory snapshot per asset
for each audit. Its lazy parsed-component cache retains at most 256 entries and
131072 attribute tokens across original and evaluation names; shared names count
once. Capacity causes eviction or uncached evaluation, never dropped evidence.
Possible scanner evidence uses an internal class-only evaluation view; original
CPE/version spelling, ordering declarations and scanner metadata remain in the
inventory and reports. CNA criteria are processed one at a time across components,
without retaining a parsed criterion list. No prepared state survives a new audit
or an inventory revision.

Preparation, cache operations and matching consume the existing predicate budget.
Reuse avoids repeated parsing, but predicate totals can increase for small inputs
because preparation is now charged. The 500000-predicate, 50000-pair, 4096-result
and 2 MiB result limits remain unchanged. Cancellation or work exhaustion can
still produce partial output with null unexamined-pair counts. This does not
establish complete annual-catalog assessment or a wall-time speedup.
