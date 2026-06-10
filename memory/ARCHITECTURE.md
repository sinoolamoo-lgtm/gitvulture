# GitVulture — Architecture Specification v2.0

> **Status**: signed off (5-round architecture review, Feb 2026).
> **Scope**: end-to-end design contract for the next major refactor.
> Implementation order: §3 → §4 → §A-bugs → §5 → §6 → §7 → §8 → §9.

---

## 0. North Star

GitVulture is an **offensive Git-exposure recon and exploitation framework**
that turns a single URL into a complete attack chain. It must:

1. Recover the maximum amount of repository data from any exposure.
2. Detect every secret recoverable from that data.
3. Link static vulnerabilities to live endpoints.
4. Drive an AI-assisted escalation loop with strict scope guarantees.
5. Produce a verifiable, citation-checked exploit roadmap.

Authority: every component on the read path is mechanical. Every aggressive
or mutating action passes through a single `ScopeGuard` (§2). The LLM
never directly executes HTTP — it proposes; the guard authorizes.

---

## 1. Pipeline Overview

```
P0  Bootstrap            → CLI parse, env, logger, output dir
P1  Reconnaissance       → soft-404 baseline (N samples + SimHash), .git probes,
                           WAF detection, bypass storm
P2  Ref Discovery        → dumb-HTTP refs + reflog + brute force
P3  Smart-HTTP (D1)      → ls-refs, fetch, pack download; feedback to P2
P3' Object Acquisition   → packs + loose objects + BFS (visited-set termination)
P4  Reconstruction       → non-bare repo, fsck --reflogs, blame, checkout
P5  Secret Hunt          → 23 regex rules + tunable entropy + allowlist
P6  Live Verification    → APIs + permission enum (C3) + cloud lateral
P7  AI Triage            → Claude strategic analysis (read-only artifacts)
P8  Escalation Worklist  → graph of handlers (replaces L1-L8 ladder)
P9  Exploit Roadmap      → strict-mode AI with citation verifier
PX  Reports              → JSON + MD + secrets/ + sast/ + escalation/ + graph.dot
```

Phases P0-P5 always run. P6-P9 are opt-in via flags. The Worklist (§5)
makes P8 a feedback graph rather than a linear ladder; any verified
artifact can re-enqueue earlier handlers.

---

## 2. ScopeGuard Contract (E1)

The single authority for every outbound request and every state-changing
operation.

```python
# /app/gitvulture/core/scope_guard.py

@dataclass(frozen=True)
class ScopeContract:
    # Identity = (scheme, host, port). No silent http↔https drift.
    authorized_hosts: frozenset[tuple[str, str, int]]

    # Mutating endpoints require EXACT path match (no prefix freedom).
    # Smart-HTTP registers ("/info/refs"), ("/git-upload-pack"); WebDAV
    # PUT registers its target paths explicitly.
    extra_allowed_post_endpoints: frozenset[tuple[str, str, int, str]] = ...
                                # (scheme, host, port, exact_path)

    read_only_methods : frozenset[str] = frozenset({"GET","HEAD","OPTIONS","PROPFIND"})
    mutating_methods  : frozenset[str] = frozenset({"POST","PUT","PATCH","DELETE","MKCOL","PROPPATCH","MOVE","COPY"})

    allow_mutating      : bool = False   # --allow-mutating
    allow_lockout_risk  : bool = False   # --allow-lockout-risk (consumed by L5 cred handler, NOT authorize())
    interactive_consent : bool = True

@dataclass
class Decision:
    allowed: bool
    reason: str                        # always populated
    consent_required: bool = False
    recommended_method: Optional[str] = None
```

### 2.1 Rules enforced by `authorize(method, url)`
1. Parse → normalize → resolve relative segments. Reject only if
   `resolved_host:port` is not in `authorized_hosts`. **Encoded path
   payloads on in-scope hosts are allowed by design** (they ARE the bypass
   library).
2. Read-only methods → allow + audit.
3. Mutating methods → allowed iff `(scheme,host,port,path) ∈
   extra_allowed_post_endpoints` after normalization. Otherwise:
   - `interactive_consent=True` AND TTY → prompt operator with full lineage.
   - `interactive_consent=False` OR non-TTY → deny.
4. Every 30x redirect re-runs `authorize_redirect()` against the new
   `(method, url)`. `httpx.AsyncClient(follow_redirects=False)` + manual
   loop is mandatory.
5. PROPFIND default `Depth: 1`; `Depth: infinity` gated on `--offensive`.

### 2.2 Audit JSONL
One line per decision (including rejects):
```
{seq, ts, decision, method, url, host, reason, consent_required,
 origin_artifact_id, lineage[]}
```
Written to `<out>/scope-audit.jsonl` for blue-team replay and our own
graph debugging.

### 2.3 Orthogonality
- `--offensive` ↔ aggressive *techniques* (bypass storm aggressiveness, IMDS
  pivot, time-based SQLi, default-creds spray, WebDAV enum depth, ...)
- `--allow-mutating` ↔ state-changing *verbs*.
- WebDAV PUT, default-creds spray, time-based SQLi need **both**.

### 2.4 Consent serialization
All `request_consent()` calls funnel through a single `asyncio.Lock`.
N parallel async workers cannot interleave prompts; the human sees one
prompt at a time with the artifact lineage.

---

## 3. Smart-HTTP Layer (D1)

The dumb-HTTP path is preserved; smart-HTTP is the new primary discovery
mechanism.

### 3.1 Protocol selection
```
GET {target}/.git/info/refs?service=git-upload-pack
Headers:
  Accept: application/x-git-upload-pack-advertisement
  Git-Protocol: version=2
```
Content-Type response:
- `application/x-git-upload-pack-advertisement` → smart (parse pkt-line)
- anything else → dumb-only target

### 3.2 pkt-line framing
- 4 hex chars (incl. header) length + payload
- `0000` = flush, `0001` = section delim (v2), `0002` = response-end (v2)
- Length `0001/0002/0003` = control sentinels; data starts at `0004`
- Reject length > `0xfff0`
- Pure-Python in `/app/gitvulture/core/smart_http.py` (~80 LOC, no dulwich
  dep — their pkt-line is internal/unstable across versions)

### 3.3 Protocol v1
First pkt: smart banner `"# service=git-upload-pack\n"` + flush.
First ref pkt: `"<sha> <ref>\0<caps>"` — split on `\0` for line 1 only.
Subsequent ref pkts have no caps. Edge cases:
- Empty repo: `0000…0 capabilities^{}\0<caps>` (no refs, valid caps)
- Symref discovery: extract `symref=HEAD:refs/heads/<x>` from caps →
  feed to P4 as default-branch hint
- Object format: `object-format=sha1` is implicit. **`sha256` is hard
  fail-closed** unless `--allow-sha256` (experimental, not implemented v1).

### 3.4 Protocol v2 — section-aware
v2 caps come from `info/refs` but **refs require a separate POST**:
```
POST /git-upload-pack
content-type: application/x-git-upload-pack-request
Git-Protocol: version=2

command=ls-refs
agent=gitvulture/2.0
0001
ref-prefix refs/
symrefs
peel
0000
```
Parse `<sha> <ref> [symref-target:...] [peeled:...]` → P2 feedback.

v2 fetch response is sectioned. State machine:
```
acknowledgments → shallow-info? → wanted-refs? → packfile-uris? → packfile
                                                                  ↑
                                          start side-band-demux HERE
```
Only after the literal `packfile\n` pkt does packdata begin. Earlier
sections are logged + ignored if unimplemented.

### 3.5 Capability negotiation
- Side-band: auto-negotiate `side-band-64k` → `side-band` → raw pack.
- Unknown caps (`bundle-uri`, `promisor-remote`, `packfile-uris` we don't
  implement): ignore per v2 forward-compat spec, **but** skip their
  response sections cleanly.
- `filter` (partial clone): default-OFF. `--smart-filter-blobs` is the
  explicit opt-in. We hunt secrets in big blobs by default.

### 3.6 Pack download
Stream side-band band 1 directly into
`<out>/.git/objects/pack/pack-<digest>.pack`. Never accumulate in memory
(repos can be GB). Band 2 = progress → `[SMART-PROG]` log. Band 3 = fatal.
Generate `.idx` via `git index-pack --stdin`.

### 3.7 ScopeGuard registration
```python
contract.register_post_exact(scheme, host, port, "/info/refs")
contract.register_post_exact(scheme, host, port, "/git-upload-pack")
contract.register_post_exact(scheme, host, port, "/.git/info/refs")
contract.register_post_exact(scheme, host, port, "/.git/git-upload-pack")
```
**No global POST loosening.** Each new mutating capability registers its
exact endpoints, or it doesn't fly.

### 3.8 Feedback loop
After v1/v2 ref enumeration, diff against `RefSet` from P2:
```
new_refs = smart_refs - p2_refs
```
- New SHAs → seeded into P3' BFS frontier
- New ref names → written under `<out>/.git/refs/...` + `packed-refs`
- Log: `[SMART] discovered 47 refs (12 NEW)`

### 3.9 Failure modes
- 401/403 on POST → retry once with `--auth`/`--cookies` (D8).
- v2 garbled → fall back to v1.
- v1 stall (no NAK/ACK in 30s) → downgrade to dumb-HTTP.
- Pack corruption → keep partial file, log, continue dumb mode for missing SHAs.
- Union refs from smart + dumb (set-based, normalized) — whichever yields
  larger object closure wins.

### 3.10 Test matrix
gitea, gitlab-ce, apache+gitweb-cgit, **+ one sha256 repo**.

---

## 4. SAST Engine (C1)

### 4.1 Engine
Semgrep CLI as subprocess. NOT bandit, NOT custom AST walker.
Semgrep absent → skip C1 + loud warning + install instructions.
`--sast-autoinstall` is the explicit opt-in (never silent install).

### 4.2 Hybrid taint strategy
Semgrep OSS taint is **intra-file only**. Cross-file/interfile taint is
Pro-only. Therefore:
- **Taint-mode** rules for same-file flows (default, low FP ~10%)
- **Pattern-mode** rules + sanitizer-exclusion for 15 high-signal sinks
  (`unserialize`, `pickle.loads`, `mysqli_query`, `shell_exec`, `eval`,
  `system`, `Runtime.exec`, `ObjectInputStream`, `Marshal.load`, `exec`,
  `popen`, `system`, `DocumentBuilder`, `lxml.etree.parse`, `node-serialize`)
- Pattern-mode accepts higher FP (~25%) to catch cross-file sinks
- README explicitly documents both: same-file ~10% FP, cross-file
  pattern ~25% FP. NEVER claim "8-12% FP" alone.

### 4.3 Curated ruleset (~80 rules, embedded YAML)
| Category | Rules | Examples |
|---|---|---|
| SQL injection | 12 | concat into `mysqli_query`, `executeRaw`, f-string `cursor.execute` |
| Cmdi | 8 | `exec`/`system`/`popen`/`shell_exec` with taint |
| SSRF | 6 | `requests.get(user)`, `curl_exec`, `URL().openConnection()` |
| Deserialization | 7 | PHP `unserialize`, `pickle.loads`, Java `ObjectInputStream` |
| SSTI | 5 | `Jinja2.from_string(user)`, Twig/Smarty `evaluate` |
| File upload | 6 | `move_uploaded_file` no-ext-check, multer no filter |
| Path traversal | 5 | `open(user_input)`, `fs.readFile(req.query.path)` |
| Auth bypass | 8 | hardcoded role checks, `isAdmin=true`, mass-assignment |
| XXE | 3 | DocumentBuilder no-setFeature, lxml resolve_entities=True |
| Weak crypto | 6 | MD5/SHA1 password, ECB mode, hardcoded IV, `Math.random()` token |
| IDOR hint | 4 | controller `:id` skipping currentUser — **`hint` severity max** |
| CORS | 3 | `Allow-Origin: *` + `Allow-Credentials: true` |
| Open redirect | 3 | `redirect(req.query.url)` |
| Hardcoded creds | 4 | with framework context (overlap with P5 but enriched) |

Embedded at `/app/gitvulture/sast/rules/*.yml`. `--sast-rules <path>` for
power-user override.

### 4.4 False-positive control
1. Source-to-sink taint required (no bare-sink matches)
2. Sanitizer awareness (`PDO::prepare`, `htmlspecialchars`, ORM where-builders)
3. Framework allowlist (Eloquent, Django ORM, SQLAlchemy filter)
4. Test/fixture exclusion (`^(tests?|spec|fixtures?|examples?)/`)
5. `--sast-all` opens floodgates (default off)
6. AST-level dedup → same sink across commits collapsed
7. IDOR + auth-bypass capped at `hint` severity, never `critical`, never
   auto-trigger probes (graph step 5 ignores `hint`/`info`)

### 4.5 Multi-source scan (Trap 2 from review)
Run on:
- **HEAD** (primary): `recovered_source/`
- **Dangling blobs**: critical-severity rules only
- **C8 diff set**: removed-from-HEAD but present-in-deployed-live blobs

`commit_first_seen` populated via:
```
git blame -L <line>,<line> --reverse <commit>..HEAD -- <file>
```
If blame fails → field omitted (never invented).

### 4.6 Sink → endpoint linking (no re-derivation)
**L3 is the single source of truth** for `file → endpoint` mapping.
SAST emits `(file, function_name, line)`; linker joins against
`L3.endpoint.source_files[]`. No duplicate route parsers.

Confidence levels:
- `exact` — file + line maps to exact route declaration
- `param-normalized` — `:id` ≡ `\d+`, segment count must match
  (`/a/:x` does NOT match `/a/b/c`)
- `file-path-fallback` — no router parser for this framework, correlate
  by file path proximity to L3-known endpoints

Cross-reference against L3's `discovered_endpoints[]`:
- exact match → `live=yes` (high confidence)
- pattern match → `live=probable` (medium)
- no match → `live=unknown` (still reported)

### 4.7 Active follow-up probes
Graph step 5 (re-enqueue handlers on `live=yes` sinks):
- SQLi sink → **time-based probe gated behind `--offensive`**, hard cap
  `SLEEP(3)`, concurrency=1, max 5/endpoint, audit-logged
- SSRF sink → requires `--collaborator <host>` for OOB validation;
  without it → `live=unverified`, no active probe
- File upload sink → polyglot payload, read-only (HEAD/OPTIONS first)
- Default: read-only fingerprint probes only

### 4.8 Robustness
- Per-file `try/except`; parse errors → `<out>/sast/parse_errors.log`
- 10s timeout per file
- One bad file never aborts the run
- `--metrics=off --jobs N --timeout 30 --max-target-bytes 10MB`
- Auto-skip `node_modules/`, `vendor/`, `bower_components/`

### 4.9 Outputs
```
<out>/sast/
├── sast.md           ← human report grouped by severity
├── sast.json         ← machine-readable artifact stream
├── by-endpoint.md    ← pivot: per-endpoint sinks, including taint chain
└── parse_errors.log
```
`by-endpoint.md` includes **full taint path** `source → [sanitizers] → sink`
so Phase 9 citation verifier can cite the chain, not just sink line.

---

## 5. Worklist Graph (Backbone)

Replaces `EscalationEngine.run()` linear pipeline. Every handler (E1, D1,
C1, future C3-C9, D2-D10) plugs into this interface.

### 5.1 Identity model (Traps 1 + 2)

**Trap 1 — canonical_form is identity-only**:
```python
ArtifactId = str   # sha256(canonical_form)[:16]

CANONICAL_FIELDS = {
  "host"            : {"scheme","host","port"},
  "endpoint"        : {"method","normalized_url"},
  "blob"            : {"sha"},
  "commit"          : {"sha"},
  "ref"             : {"name","sha"},
  "finding"         : {"rule_id","file_path","line_no","match_hash"},
  "key"             : {"key_material_hash"},
  "verified_key"    : {"key_material_hash"},
  "enumerated_key"  : {"key_material_hash"},
  "sast_sink"       : {"rule_id","file","function","line"},
  "ssrf_primitive_unconfirmed" : {"endpoint_id","param"},
  "ssrf_primitive"  : {"endpoint_id","param"},
  ...
}

# EXPLICITLY EXCLUDED from canonical_form (metadata only):
# severity, confidence, created_at, origin_lineage, extra, cost, verified
```
Unit test contract: same logical artifact across runs → same id;
metadata mutation → same id.

**Trap 2 — state-as-kind, never state-as-payload**:
Promotions are graph edges between distinct kinds, never metadata bumps.
```
key                          → VerifyHandler              → verified_key
verified_key                 → CloudEnumHandler           → enumerated_key
endpoint                     → FingerprintHandler         → fingerprinted_endpoint
ssrf_primitive_unconfirmed   → CollaboratorHandler        → ssrf_primitive
finding                      → ExploitChainHandler        → confirmed_exploit
```
Each transition is an explicit handler producing a new artifact.

### 5.2 Data structures

```python
@dataclass(frozen=True)
class Artifact:
    id: ArtifactId               # from canonical_form per §5.1
    kind: str                    # see kind taxonomy
    payload: dict                # all kind-specific fields (incl. non-identity)
    severity: Severity = "info"
    confidence: float = 1.0
    origin_lineage: tuple[ArtifactId, ...] = ()  # capped at 32
    created_at: float = field(default_factory=time.monotonic)

@dataclass
class Task:
    seq: int                     # monotonic from scheduler
    handler_id: str
    artifact_id: ArtifactId
    priority: int                # lower = higher priority
    attempt: int = 0             # max 3 with exponential backoff
    reenqueue_depth: int = 0     # capped at 3 per lineage chain
    parent_task_seq: Optional[int] = None

@dataclass
class HandlerResult:
    status: Literal["ok","skipped","failed","retry"]
    new_artifacts: list[Artifact] = ...
    findings: list[Finding] = ...
    cost: ResourceCost = ...
    notes: str = ""
```

### 5.3 Handler protocol

```python
class Handler(Protocol):
    handler_id: str              # stable id, used in visited-set
    handler_class: str           # for priority ordering
    handles: set[str]            # artifact kinds consumed
    requires_consent: bool = False
    estimated_cost: Optional[ResourceCost] = None  # required for HTTP/LLM-heavy

    async def can_handle(self, artifact: Artifact, ctx: Ctx) -> bool: ...
    async def run(self, artifact: Artifact, ctx: Ctx) -> HandlerResult: ...
```

### 5.4 Scheduler

```python
class Worklist:
    visited: set[tuple[str, ArtifactId]]   # (handler_id, artifact.id)
    seen_artifacts: dict[ArtifactId, Artifact]
    queue: heap[(priority, seq, Task)]
    budget: Budget
    guard: ScopeGuard

    async def submit(self, artifact, parent=None) -> None:
        # 1. Canonicalize → id. If id in seen_artifacts → merge lineage, return.
        # 2. Cycle guard: if id in any parent.origin_lineage → reject (loop_guard_tripped finding).
        # 3. reenqueue_depth tracking: capped at 3 per lineage chain.
        # 4. For each matching handler:
        #      if (handler.handler_id, id) in visited → skip
        #      prio = priority_fn(artifact, handler)
        #      heappush((prio, next_seq(), Task(...)))

    async def run(self) -> RunReport:
        async with TaskGroup() as tg:
            for _ in range(self.concurrency):
                tg.create_task(self._worker())

    async def _worker(self):
        while True:
            # termination: queue empty AND no in-flight for K=3 ticks
            if self.budget.exhausted(): break
            task = await self.dequeue_or_wait()
            if task is None: break
            handler = self.handlers[task.handler_id]
            # E1 pre-check
            decision = self.guard.authorize_handler(handler, task.artifact)
            if not decision.allowed:
                self.audit(task, decision); continue
            try:
                result = await handler.run(task.artifact, self.ctx)
            except Exception as e:
                if task.attempt < 3:
                    task.attempt += 1
                    await asyncio.sleep(2 ** task.attempt + jitter())
                    self.enqueue(task); continue
                self.audit_failure(task, e); continue
            self.budget.consume(result.cost)
            for new_art in result.new_artifacts:
                await self.submit(new_art, parent=task)
            for finding in result.findings:
                self.finding_store.append(finding)
```

### 5.5 Priority function (deterministic, replay-safe)

```python
SEVERITY_PRIO = {"critical":0,"high":10,"medium":20,"low":30,"hint":40,"info":50}
HANDLER_CLASS_PRIO = {
    "recon":0, "ref_discovery":1, "smart_http":1,
    "object_acq":2, "reconstruct":3, "secret_hunt":4,
    "verify":5, "sast":5, "live_diff":5,
    "escalation":6, "ai_probe":7, "exploit_roadmap":8,
}
def priority(art, handler) -> int:
    return SEVERITY_PRIO[art.severity] * 100 + HANDLER_CLASS_PRIO[handler.handler_class] * 10
# Tiebreak: monotonic seq number (FIFO within same priority).
# created_at REMOVED — wall-clock breaks replay determinism.
```

### 5.6 Budget (Trap 4)

```python
@dataclass
class Budget:
    max_wall_clock_s : float = 1800
    max_http_requests: int   = 50_000
    max_llm_tokens   : int   = 500_000
    max_handler_calls: int   = 10_000

    # Reserve for terminal handlers — Trap 4 fix.
    report_reserve: ResourceCost = ResourceCost(
        http=2_500, llm_tokens=20_000, wall_clock_s=60)

    spent: ResourceCost = field(default_factory=ResourceCost)

    def can_afford(self, cost: ResourceCost, *, terminal=False) -> bool:
        if terminal: return self._has_reserve_for(cost)
        return self._has_non_reserve_for(cost)
```

Terminal handlers (`ExploitRoadmapHandler`, report writer, secrets
exporter) always draw from the reserve. Partial reports stamp:
`⚠ partial — budget exhausted at <reason>`.

Default-floor estimate: handlers without `estimated_cost` are charged a
floor (`http=10, llm=0, wall_clock=1s`) at pre-check, reconciled to actual
post-hoc. Prevents "free" handlers from silently blowing the budget.

### 5.7 Termination
1. Queue empty AND no in-flight tasks for K=3 consecutive scheduler ticks
   (debounce against async producers), OR
2. Budget exhausted (terminal handlers still get the reserve), OR
3. SIGINT — drain in-flight (60s grace timeout), checkpoint, exit.

### 5.8 Object acquisition is NOT atomized (Trap 3)
BFS stays inside `ObjectEngineHandler` as an internal batch loop. Heap
never sees individual blobs. Emissions are coarse:
- `repo_reconstructed` (1, after reconstruction)
- `finding[]`, `sast_sink[]`, `key[]` (only escalation-worthy artifacts)

Scheduler memory stays O(escalation surface), not O(blobs).

### 5.9 Determinism & replay
- `SEED = sha256(target_url + scan_started_at)` seeds all RNG (UA
  rotation, jitter, backoff).
- Every task has a monotonic seq number.
- Audit JSONL records every decision: `seq, ts, task_id, handler_id,
  artifact_id, decision, cost, new_artifact_ids`.
- `gitvulture --replay <audit.jsonl>` reconstructs the graph without
  network IO. For Phase 9 verifier debugging.

### 5.10 Observability
- `<out>/graph.dot` Graphviz output at end (artifact lineage).
- SIGUSR1 → live state dump: queue size, top-10 priorities, in-flight,
  budget %, recent transitions.
- `gitvulture --interactive` `graph` command → same dump on demand.

### 5.11 Checkpoint & resume
- Every 100 tasks: serialize `seen_artifacts` (**ids + metadata only**,
  no raw secret bodies), `visited`, `queue`, `budget.spent` to
  `<out>/.checkpoint.json` (chmod 0600, encrypted iff `--encrypt-loot`).
- Raw secrets live solely in `secrets/files/`.
- `--resume <out_dir>` restores state; HttpClient cache prevents re-fetch.

---

## 6. Handler Migration Roadmap

Each existing phase + each Part-C/D item becomes a Handler implementing §5.3.

### 6.1 Core handlers (P0-P5 + always-on escalation primitives)
```
ReconHandler              host                → endpoint, ref, origin_candidate, waf_profile
SmartHttpHandler          host                → ref, commit
RefDiscoveryHandler       host, ref           → commit, blob, ref
ObjectEngineHandler       commit, ref         → repo_reconstructed (internal BFS, NOT atomized)
ReconstructHandler        repo_reconstructed  → branch, commit, dangling_blob, dangling_commit
SecretHuntHandler         repo_reconstructed  → finding, key
SastHandler               repo_reconstructed  → sast_sink, finding
LiveDiffHandler           repo_reconstructed, endpoint  → finding, endpoint
```

### 6.2 Opt-in escalation handlers
```
VerifyHandler             key             → verified_key                  [--verify-secrets]
CloudEnumHandler          verified_key    → finding, cred, enumerated_key [--verify-secrets]
DbConnectHandler          verified_key    → finding                        [--connect-db]
SshAttemptHandler         ssh_key         → finding                        [--ssh-attempt]
JwtForgeHandler           key (JWT-kind)  → finding                        [--ai]
CiCdSecretsHandler        blob (workflow yml) → cred, finding
OriginFinderHandler       host            → host (new, after SimHash check ≥0.85)
SubdomainExpandHandler    host (internal hostname extracted from configs) → host
AiProbeHandler            endpoint, finding → endpoint, finding            [--ai, --escalate]
ExploitRoadmapHandler     *               → terminal, exploit-roadmap.md   [--exploit-roadmap]
```

### 6.3 Bypass handlers (registered with ReconHandler + SmartHttpHandler)
- `D1` Smart-HTTP (§3)
- `D2` Origin discovery (crt.sh, DNS history, Shodan/Censys)
- `D3` Alternative ports (`:8080,:8443,:8000,:8888,:9000,:3000`)
- `D4` Path normalization tricks (`..;/`, matrix params, Unicode NFC/NFKC,
       overlong UTF-8, triple-encoding)
- `D5` Method override + HTTP/2→1.1 downgrade (NO request smuggling)
- `D6` `Range: bytes=0-` for blocked large packs
- `D7` Cache-key manipulation
- `D8` Authenticated retry on 401/403 paths
- `D9` `X-Forwarded-For` rotation, jitter, tarpit detection
- `D10` WebDAV (PROPFIND Depth=1 default; PUT/MKCOL gated on
        `--offensive + --allow-mutating`)

### 6.4 Source-derived chains (high-value escalation)
- `C1` SAST (§4)
- `C2` Recursive secret pivoting (handled implicitly by graph: verified_key
       re-enqueues handlers consuming it)
- `C3` Cloud permission enumeration (CloudEnumHandler)
- `C4` DB direct connect (DbConnectHandler — `--connect-db` gate)
- `C5` SSH / deploy keys (SshAttemptHandler — `--ssh-attempt` gate)
- `C6` CI/CD secrets (CiCdSecretsHandler — parses `.github/workflows/*`,
       `.gitlab-ci.yml`, `Jenkinsfile`, OIDC `aud`/`sub`)
- `C7` JWT forging (alg:none, weak HS256 cracking against recovered wordlist,
       `kid` injection, `jku`/`x5u` confusion)
- `C8` Live diff (LiveDiffHandler) — HEAD ↔ live deployment
- `C9` Git-native pivots (`.git/hooks/*`, `.gitmodules`,
       `objects/info/alternates`, `.js.map` deobfuscation,
       internal hostname extraction)

---

## 7. Bug Fixes (Part A from review)

| ID | Fix |
|---|---|
| A1 | Drop `git init --bare`; use non-bare repo OR `git --git-dir=.git --work-tree=recovered_source/ checkout` |
| A2 | `git fsck --reflogs --dangling --lost-found` (reflog ghosts preserved) |
| A3 | BFS visited-set termination, no round cap; safety ceiling `max_iters=100_000` to prevent hangs |
| A4 | Soft-404 = N=3 random samples + SimHash similarity ≥ 0.85 (Ratcliff-Obershelp); re-baseline every 500 requests |
| A5 | Document: `PYTHONUNBUFFERED` env var only affects child processes (git, etc.). Current-process buffering fix is `sys.stdout.reconfigure(line_buffering=True)` (already present in `cli.py:main()`) |
| A6 | Add `--escalate` and `--offensive` CLI flags (currently `ScanOptions.escalate` is unreachable). Fix "maximum-power" example to include them |
| B1 | `git cat-file --batch`/`--batch-check` via persistent subprocess (replace per-blob spawning) |
| B2 | Subtract pack-contained SHAs from loose-fetch queue before BFS |
| B3 | Smart-HTTP (§3) + pack-name guessing fallback |
| B4 | Pytest fixtures for index v2/v3/v4, packed-refs peeled tags (`^{}`), `objects/info/alternates` |
| B5 | Entropy 4.5 default for base64-shaped matches, per-rule tunable, allowlist for `EXAMPLE`/`xxxxx`/`changeme` |
| B6 | Already async (httpx + Semaphore + HTTP/2) — no change |

---

## 8. Safety Guardrails (Part E from review)

### E1 ScopeGuard — see §2.
### E2 Lockout protection
- `L5CredSprayHandler` (consumes `--allow-lockout-risk`):
  - Max 1 attempt per account globally
  - Never iterate same username
  - Hard-stop after first 401 cluster unless `allow_lockout_risk=True`
  - Audit-logged with full username + endpoint
- Dead-field linter test ensures `allow_lockout_risk` is consumed.

### E3 Loot at rest
- `secrets/files/*` → `chmod 0600`
- `.checkpoint.json` → 0600 always
- `--encrypt-loot` → libsodium symmetric (passphrase prompt) for both
- Default: redacted in stdout, full in files (0600)

### E4 Phase 9 hallucination control
- 3 citation-verification rounds max
- After 3 failures: scenario **dropped** from main roadmap, logged in
  `<out>/exploit-roadmap.unverified.md` with reason
- Never silently keep uncited claims

### E5 (added) OPSEC banner
- Report header: `⚠ Live-verification side effects logged on target (CloudTrail, GitHub audit log, Stripe dashboard, ...)`
- Operator awareness; no functional gate.

---

## 9. Testing & Acceptance Criteria

### 9.1 Unit tests (pytest at `/app/backend/tests/`)
- `test_canonical_form.py` — same logical artifact → same id; metadata mutation → same id; identity field mutation → different id.
- `test_scope_guard.py` — Rule 1-5 enforcement; redirect re-validation; encoded path payloads on in-scope hosts allowed; off-scope rejected.
- `test_pkt_line.py` — v1/v2 framing, sentinels, bounds, banner validation.
- `test_smart_http_v2_sections.py` — fetch response section state machine.
- `test_object_format_sha256_failclose.py` — sha256 repo without `--allow-sha256` exits cleanly.
- `test_bfs_termination.py` — visited-set termination, max_iters safety net.
- `test_priority_determinism.py` — same SEED → identical task ordering.
- `test_budget_reserve.py` — terminal handler always gets the reserve.
- `test_state_kind_promotion.py` — `key → verified_key → enumerated_key` chain.
- `test_loop_guard.py` — reenqueue_depth cap, cycle rejection.
- `test_sast_link_join.py` — sink → endpoint via L3 single-source-of-truth.

### 9.2 Integration test matrix (real targets)
- Smart-HTTP: gitea, gitlab-ce, apache+gitweb-cgit, sha256 repo
- SAST: 10-app OSS corpus (DVWA, Juice-Shop, OpenCart-leaked, Magento-leaked, ...)
- End-to-end: lab targets with known answers (Web Security Academy "Information disclosure via .git")

### 9.3 Acceptance criteria for the refactor
- All Part-A bugs (A1-A6) fixed; existing tests still pass.
- ScopeGuard intercepts 100% of HttpClient calls (verified by audit JSONL coverage).
- Smart-HTTP unlocks dumps on at least 2 of 4 lab targets where dumb-HTTP returns 403.
- SAST link rate ≥ 60% on the OSS corpus (sink → endpoint).
- Graph replay (`--replay`) produces byte-identical audit JSONL on rerun.
- Budget exhaustion always produces a (partial) report.
- No raw secret material in `.checkpoint.json` (grep-test against known wordlist).

---

## 10. Out of Scope (Explicit Rejections)

- HTTP request smuggling — can corrupt other tenants on shared proxies
- Direct IMDS pivot (169.254.169.254) from operator's host — only via
  confirmed SSRF primitive on the target
- Auto-installation of external tooling without explicit flag
- LLM-generated mutating verbs in non-TTY environments — hard deny
- SHA-256 repo support in v1 (stubbed, fail-closed; v2 work item)
- Semgrep Pro / interfile taint — pattern-mode fallback for cross-file
- Default-creds spraying without `--allow-lockout-risk`

---

## 11. Document History

| Round | Date | Topic | Outcome |
|---|---|---|---|
| 1 | Feb 2026 | Logic bugs (Part A) + bypass categories (Part D) + escalation gaps (Part C) + safety (Part E) | All accepted with corrections (B6 rejected, D5 partial) |
| 2 | Feb 2026 | E1 ScopeGuard contract draft | Q1-Q3 answered, Rule 5 critical fix |
| 3 | Feb 2026 | D1 Smart-HTTP plan | 3 protocol landmines fixed (v2 ls-refs, section state machine, sha256) |
| 4 | Feb 2026 | C1 SAST plan | 2 blockers fixed (interfile taint, HEAD-only); redundancy + OOB + noise items addressed |
| 5 | Feb 2026 | Graph refactor | 4 traps fixed (canonical_form, state-as-kind, no atomization, report reserve) |
| — | Feb 2026 | **This document** | Consolidated spec, architectural surface closed |

---

**End of architectural surface.** Further work = per-handler rule review only.
