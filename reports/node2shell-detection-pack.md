# Node2Shell Detection Pack — CVE-2026-111497 (a.k.a. HTTP2Shell / Broccoli2Shell)

_Compiled 2026-10-26. Node.js shipped fixes on October 21, 2026, and the picture is still widening from "a Node bug" to "a Brotli-everywhere bug," so expect details to shift. As of the latest public reporting there is **no confirmed in-the-wild exploitation and no published IOC set** (no IPs, user agents, scanner names, or hashes) — so unlike the PHP2Shell pack, this one leans entirely on request structure, decoder-error receipts, and process behavior, not on threat-intel lists. All SPL here is untested against live exploit traffic; validate in your environment before promoting any of it to a correlation search._

---

## Part 1 — Understanding the flaw

### Why this is a big deal

Node2Shell is a memory-safety bug in the **Brotli decompressor**, not in Node.js application code and not really in Node.js at all — Node just happens to bundle the vulnerable decoder. That framing is the whole story for a detection engineer:

- **It is remote, pre-application, and (per the ecosystem advisories) unauthenticated.** The dangerous work happens inside the native decompression routine the moment your runtime decodes attacker-supplied Brotli data — before your route handlers, your auth middleware, or your business logic see anything meaningful. A one-route Express app that merely accepts `Content-Encoding: br` bodies is in scope.
- **It is bidirectional.** This is the part that makes it different from almost every other "exploit public-facing app" bug. You are exposed when you **receive** crafted Brotli (a malicious client POSTs a `br` body your server decodes) *and* when you **consume** it (your service `fetch()`es a response and a malicious server replies with `Content-Encoding: br`). The second direction turns any SSRF, any outbound HTTP call to a half-trusted endpoint, any webhook fetch, into a client-side exploitation surface.
- **It is not just Node.** The root cause lives in Google's Brotli library, which is pulled into Python HTTP clients, Bun, Java, .NET, Envoy/Istio, curl/libcurl, and a long tail of anything that advertises Brotli. That is why the same CVE is being called **HTTP2Shell** as the blast radius is mapped out. Brotli reportedly sees ~82.8M downloads a month on PyPI alone.

Researchers (Imperva, Aikido, and others) disclosed it alongside the Node.js advisory. OpenAI is reported to have found the underlying flaw back in February; the root cause was quietly fixed in the Brotli source then but was not recognized as a security issue, so no release carried the fix until October.

### The flaw itself

| Field | Value |
|---|---|
| CVE | **CVE-2026-111497** |
| Names | Node2Shell, HTTP2Shell, Broccoli2Shell |
| CVSS v4.0 | **9.2 (Critical)** — remote, unauthenticated, works in both directions |
| Weakness | **CWE-252** (unchecked return value) + **CWE-787** (out-of-bounds write) |
| Root-cause function | `DecodeBlockTypeAndLength()` in the Brotli decoder |
| Upstream fix | google/brotli commit `0ed4268` — returns a real error code and adds `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (**-17**) |

**Mechanism in plain terms.** Brotli streams can switch "block types" partway through. The decoder function that handles the switch returned a bare boolean. `BROTLI_FALSE` had to carry two very different meanings — "the stream is malformed" and "I need more input bytes" — and callers could not tell them apart; on the fast path the return value was discarded entirely. A crafted stream declares a block type, deliberately exhausts that block's length, and then forces a block switch the stream's own structure makes impossible. The decoder, unable to distinguish "malformed" from "need more input," either asks for more input or keeps decoding with stale internal state. Continuing from that invalid state produces an **out-of-bounds write**. The upstream fix stops decoding with a format error (-17) on both the fast and slow paths.

### The two ways it reaches your runtime

Both paths end at the same native decoder; the difference is only who sends the bytes.

| Path | ATT&CK | How the bytes arrive | Concrete trigger |
|---|---|---|---|
| **Inbound (malicious client)** | T1190 | A request body with `Content-Encoding: br` that your app decodes | Express 5.0.0–5.3.0 with body-parser 2.0.0–2.3.0 using `raw()` / `json()` on a route. A **bare `http`/`https` server does not decode incoming Brotli by itself** — something has to opt in. |
| **Outbound / consumed response (malicious server)** | T1203 | A response your service fetches and decompresses | Node's built-in `fetch()` decoding a `Content-Encoding: br` response. This is the SSRF / webhook / third-party-API angle, and it is invisible to an inbound WAF. |

### Common exploit shape, and why "exploit" overstates it today

The crafted artifact is a single Brotli stream (the Python reproduction used a ~23 MB stream) carrying the impossible block switch. There is no multi-request "arm/fire" dance like PHP2Shell — one decode of one malicious stream is the whole trigger. But two things keep this from being a reliable RCE *yet*:

- **Reliability is poor.** Imperva's own proof of concept did not succeed on every attempt and needed several tries, on a Linux arm64 build. An earlier public PoC achieved code execution only against a deliberately weakened test build; on a standard build its author reported a **crash and a limited read of process memory**, not code execution.
- **The reliable outcome is a crash, not a shell.** For a detection engineer that is the key inversion versus PHP2Shell: here the *loud* event (a native abort / segfault in the Node process, trivially repeatable) is the common case, and clean RCE is the rare, quiet case. That makes a dependable **denial-of-service** the realistic near-term threat, with RCE and the memory-read primitive as the high-consequence tail.

### A note on exploitation status (as of 2026-10-26)

- Node.js released fixes on **October 21**; Vercel added inbound blocking rules the same day; Imperva published a Node.js exploitation write-up and added WAF rules.
- As of **October 22**, The Hacker News reported **no in-the-wild exploitation** and no honeypot probes or scanning activity attributed to this CVE.
- **No IOC set has been published** — no attacker IPs, no scanner user agents, no file hashes, no malicious domains. Treat everything below as behavior- and structure-based detection, and treat this status as a snapshot that will age quickly: a reliable crash primitive plus an ecosystem-wide dependency is exactly the profile that attracts opportunistic scanning fast.

### Affected and fixed versions

The CVE is one bug in Brotli, surfaced through many carriers. Patch the carrier you run; version strings can be backported without changing, so trust vendor advisories over string comparison.

| Carrier | Affected | Fixed |
|---|---|---|
| **Google Brotli (C lib)** | 1.0.3 – 1.2.0 | **1.2.1** (backports: 1.0.10, 1.1.1) |
| **Node.js** | 22.x, 24.x, 26.x (20.x and earlier are EOL, no fix) | **22.23.4 / 24.22.1 / 26.12.1** or newer in-line |
| **Bun** | pre-1.4.4 | **1.4.4** (rebuild compiled executables) |
| **Python** `Brotli` | ≤ 1.2.0 (PYSEC-2026-4322, GHSA-9v8h-qqgm-4m35) | **1.2.1** |
| **Python** `brotlicffi` | 1.2.0.x (PYSEC-2026-4323) | **1.2.1.0** |
| Python HTTP clients pulling Brotli | urllib3/requests, `httpx[brotli]`, aiohttp, Scrapy | patch the Brotli dep + regenerate lockfiles |
| **Java** brotli4j | pre-1.24.0 | **1.24.0** (ships Brotli 1.2.1) |
| **.NET** System.IO.Compression | affected; .NET 7 affected with **no fix**; .NET Framework **not** affected | 8.0.33 / 9.0.22 / 10.0.14 / 11 RC3 |
| **Envoy** | affected | 1.40.0 / 1.39.3 / 1.38.6 / 1.37.8 (1.36.12 unsupported) |
| **Istio** | affected | 1.29.9 / 1.30.6 / 1.31.2 (1.29 EOL) |
| **curl / libcurl** | links Brotli 1.0.3–1.2.0 | rebuild against Brotli 1.2.1 / vendor-patched |

Distro note: Debian 12/13, Alpine, and Amazon Linux 2023 have patched `libbrotli`/`brotli-libs`; Fedora and RHEL are partial (RHEL's `nodejs:24`/`nodejs:26` streams were still unpatched at writing); Ubuntu, SUSE, and RHEL base were lagging. Check your own vendor advisory.

---

## Part 2 — Detection strategy

### The governing principle: crashes are loud, reads and shells are quiet

This inverts the PHP2Shell mantra, and the inversion matters.

- A **failed or opportunistic attempt** reliably **crashes the Node/Bun process** (native SIGABRT/SIGSEGV from the OOB write) or throws a Brotli/zlib decode error. That is loud: process-manager restarts, container `CrashLoopBackOff`, kernel segfault lines, 500/502s, app-log stack traces.
- A **successful RCE** runs code inside the worker and can return a perfectly normal response. A **successful memory read** returns attacker-sized process bytes with no crash at all.

So split detection the same way as PHP2Shell, but aim the loud tier at *crashes and decode errors* rather than OOM fatals:

1. **Attempt / DoS detection** lives at the **request, app-log, and process-exit layer** — `Content-Encoding: br` traffic, Brotli decode-error receipts, native aborts, and crash-loops.
2. **Success detection** moves **off the request and onto the process and host** — a Node/Bun worker spawning a shell, running from memory, reading cloud creds, or making outbound connections. This is root-cause-agnostic: it looks the same whether the door was opened by Node2Shell or any other Node RCE.

And add a third axis unique to this bug: **the outbound path is nearly invisible to request-layer tooling.** A malicious server answering your `fetch()` leaves no inbound request to inspect. For that direction, exposure scoping + upgrade is the control, and the only runtime signal is a Node process crashing right after an egress call.

### Exploit lifecycle mapped to observables and log sources

| Stage | ATT&CK | What happens | Observable | Where to look |
|---|---|---|---|---|
| Recon / scan | T1595 | Probe routes that decode `br`; send small malformed `br` bodies | `Content-Encoding: br` on endpoints that never normally see it; bursts of 400/500 on `br` bodies | Web access/WAF, proxy |
| **Inbound trigger** | T1190 | Crafted Brotli request body decoded by Express 5 / body-parser 2 | Large `br` body (tens of MB); Brotli/zlib decode error; 400/500; then possibly a native crash | Web access log, app log (Node stderr/pm2/journald), proxy |
| **Outbound trigger** | T1203 | Service `fetch()`es a response; malicious server returns crafted `br` | Egress to an attacker-influenced host immediately followed by a Node crash | Egress netflow/EDR + process-exit telemetry |
| **Decode fault** | T1499 | OOB write destabilizes the process | Native **SIGABRT (134)** / **SIGSEGV (139)** / **SIGTRAP (133)**; `node[pid]: segfault`/`traps:`; pm2 `errored`/restart; k8s `CrashLoopBackOff`/exitCode | Process manager, systemd, k8s events, kernel log |
| Memory disclosure | T1005 / T1552 | Read primitive leaks worker memory | Anomalous/oversized or binary-looking response bodies on an affected route; secrets appearing where they shouldn't | Proxy/WAF response logging, app telemetry |
| **Execution** | T1059 / T1620 | Code runs in the worker | Node/Bun worker spawns sh/bash/python/curl; `memfd_create` + `execveat` (fileless); outbound connections | EDR, Sysmon for Linux, auditd, Falco |
| Discovery | T1033 / T1082 | Confirm access, enumerate | `id`, `whoami`, `uname -a`, `hostname`, `cat /etc/os-release`, `sudo -l`, `find / -perm -u=s` | EDR process telemetry |
| Credential access | T1552 | Harvest secrets | Reads of `.env`, `~/.aws/credentials`, k8s SA token, `169.254.169.254` | EDR process/file, netflow |
| Post-ex / persistence | T1505.003 / T1053 | Backdoor, cron, SSH key | New/modified `.js` in the app dir, altered `package.json` start script or new route, cron/systemd/authorized_keys writes by the node user | FIM, EDR file events |

### What does NOT work (and why)

- **Payload byte-signatures.** The malicious stream is valid Brotli framing with a tuned-impossible block switch; the bytes that matter are structural, and reliable exploitation layout varies per build. Detect the *carrier* (`Content-Encoding: br` + anomalous size + decode error), not a fixed byte pattern.
- **Changing `Accept-Encoding` alone (outbound).** Dropping `br` from your request's `Accept-Encoding` does **not** protect you — a malicious server can send `Content-Encoding: br` regardless, and a vulnerable client will decode it. You must also reject `br` responses before decoding, or upgrade.
- **Blocking only inbound `br`.** An inbound WAF rule that strips `Content-Encoding: br` closes the server path and nothing else. The `fetch()`/consumed-response path is entirely outside it.
- **`file`/body-size limits alone.** The ~23 MB figure is one reproduction, not a floor; a smaller crafted stream can plausibly reach the same decoder state. Size is a prioritization signal, not a boundary.
- **Trusting a bare Node HTTP server is safe "because it doesn't parse bodies."** True only until a middleware, framework, or your own code calls a Brotli decode. Inventory what actually decodes, don't assume.
- **Relying on threat-intel IP/UA lists.** None exist for this CVE yet. A detection that depends on them will sit silent through the first wave.

### Precision ladder (highest-fidelity signal first)

1. A Node/Bun worker spawns a shell/downloader, or runs from memfd → **confirmed RCE**
2. A Node/Bun worker reads cloud creds / metadata endpoint, or drops a backdoor → **confirmed post-ex**
3. On a **patched** host, a Brotli `BLOCK_SWITCH` / error -17 from client-supplied data → **crafted attempt by construction**
4. A native Node abort/segfault correlated with a recent `Content-Encoding: br` request → **inbound trigger**
5. A Node crash-loop (repeated SIGABRT/SIGSEGV restarts) on one service → **active DoS / repeated attempts**
6. A Node crash immediately after an egress call to a non-standard host → **possible outbound trigger**
7. `Content-Encoding: br` on a route/body-size that is abnormal for it → **probe / attempt surface**

### Log sources and the config that makes them useful

| Source | Location / sourcetype | What you must enable |
|---|---|---|
| Node app stdout/stderr | pm2 logs, `journalctl -u <svc>`, container stdout, `docker logs` | Make sure stderr is actually captured — a **native** abort prints little or nothing through V8, so the process-exit code often tells you more than the log line. |
| Process manager | pm2 (`~/.pm2/logs`, `pm2 jlist`), systemd journal | Capture restart/`errored` events and exit codes/signals. systemd: `status=11/SEGV`, `status=6/ABRT`. |
| Container orchestrator | k8s events, kubelet, `lastState.terminated` | Log `exitCode`/`reason` (`Error`, `OOMKilled`), `CrashLoopBackOff`, restartCount deltas. exitCode 134/139/133 = abort/segv/trap. |
| Kernel log | `/var/log/kern.log`, `/var/log/messages`, `journalctl -k` | Default (`node[pid]: segfault`, `traps: node[pid] …`). |
| Web access log | nginx / Apache / proxy (CIM Web) | Log the **`Content-Encoding` request header** and request body size (`$request_length` / `%I`). Most setups don't log request `Content-Encoding` by default — add it. |
| Reverse proxy / WAF | Vercel, Imperva, Cloudflare, ModSecurity, F5/ALB | Log the matched rule for this CVE; log response bodies/sizes on affected routes for the memory-read angle. |
| NIDS | Suricata / Zeek (CIM Intrusion_Detection) | TLS termination ahead of the sensor; Zeek `http.log` carries `Content-Encoding`. |
| Endpoint process | EDR, Sysmon for Linux, auditd (CIM Endpoint.Processes) | Full parent/child lineage, exe path, keyed on node/bun. |
| auditd | `linux:audit` | Rules keyed on the node service UID for `execve`, `execveat`, `memfd_create`. |
| FIM / file events | EDR, auditd, OSSEC (CIM Endpoint.Filesystem) | App directory + `.env` + persistence paths. |
| Inventory / SBOM | CIM Vulnerabilities, osquery, image SBOM | **Bundled** Node/Bun/Brotli inside images — OS package tables miss these. |

### ATT&CK coverage

T1595 (Active Scanning) · T1190 (Exploit Public-Facing Application) · T1203 (Exploitation for Client Execution — the consumed-response path) · T1499.004 (Application-exploitation DoS — the reliable outcome) · T1059.004 (Unix Shell) · T1059.006 (Python) · T1620 (Reflective Code Loading / fileless) · T1505.003 (Web Shell / backdoor) · T1105 (Ingress Tool Transfer) · T1071.001 (Web C2) · T1033 / T1082 (Discovery) · T1552.001 / T1552.005 (Creds in files / cloud metadata) · T1005 (Data from Local System — the memory-read primitive) · T1053.003 (Cron) · T1098.004 (SSH authorized_keys).

---

## Part 3 — SPL searches

> **Read before deploying.** These lean on CIM data models (Web, Endpoint, Intrusion_Detection, Vulnerabilities, Risk) where possible, and on raw sourcetypes where the data doesn't model cleanly (Node stderr, process managers, kernel). Swap index names, sourcetypes, service names, UIDs, and thresholds for your environment. Several searches depend on logging you may need to turn on first (Part 2 table) — above all, request-header `Content-Encoding` and process-exit codes. There is deliberately **no IOC-IP search** here, because no IOC list has been published; §3.10 is a placeholder to wire in once intel exists.

### 3.0 Macros — define these first

```
[node_app_logs]
definition = (index=web OR index=os OR index=container) (sourcetype="nodejs*" OR sourcetype="pm2*" OR sourcetype="bunjs*" OR source="*pm2*/logs/*" OR source="*/log/*node*" OR (sourcetype=journald _SYSTEMD_UNIT="*node*") OR (sourcetype=journald _SYSTEMD_UNIT="*bun*") OR sourcetype="kube:container:*")

[node_process_managers]
definition = (index=os OR index=container) ((sourcetype=journald (_SYSTEMD_UNIT="*node*" OR _SYSTEMD_UNIT="*bun*")) OR sourcetype="pm2*" OR source="*/.pm2/logs/*" OR sourcetype="kube:events" OR sourcetype="kubernetes:events")

[linux_kernel_logs]
definition = index=os (source="*/kern.log" OR source="*/messages" OR (sourcetype=journald _TRANSPORT=kernel))

[brotli_decode_errors]
definition = ("BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH" OR "error code -17" OR "ERR_BROTLI" OR "Brotli" OR "brotli" OR "Z_DATA_ERROR" OR "incorrect header check" OR "unexpected end of file" OR "ERR_CONTENT_DECODING")
# Tune hard to your stack. On a PATCHED host the first two tokens are the gold signal; the generic ones are noisy and only useful paired with a br request or a crash.

[node2shell_large_br_bytes]
definition = 5242880
# 5 MB floor for "unusually large Brotli body." The public repro used ~23 MB; lower this if your br bodies are normally tiny, raise it on upload-heavy routes.

[node_worker_parents]
definition = (Processes.parent_process_name="node" OR Processes.parent_process_name="node22" OR Processes.parent_process_name="node24" OR Processes.parent_process_name="node26" OR Processes.parent_process_name="nodejs" OR Processes.parent_process_name="bun" OR Processes.parent_process_name="next-server*" OR Processes.parent_process_name="pm2*" OR Processes.parent_process_name="npm*" OR Processes.parent_process_name="pnpm*" OR Processes.parent_process_name="node --*")

[node2shell_ioc_ips]
definition = (src IN ("0.0.0.0"))
# PLACEHOLDER. No IOC IPs have been published for CVE-2026-111497. Wire real intel in here when it lands; until then this macro matches nothing by design.
```

---

### Tier 1 — Attempt / DoS detection (request + app-log + process-exit layer)

#### 3.1 Inbound trigger: `Content-Encoding: br` request body, anomalous size — MEDIUM (HIGH on routes that never see it)

**Why it works.** The inbound path requires the attacker to send `Content-Encoding: br`. On most apps that header is rare inbound (clients usually send plain bodies and only *accept* `br`), so its presence on a body-decoding route is already notable; an oversized `br` body pushes it higher. Needs request-header + body-size logging.

```spl
| tstats `summariesonly` count max(Web.bytes_in) as bytes_in values(Web.url) as url values(Web.http_method) as methods values(Web.http_user_agent) as ua values(Web.status) as statuses
    from datamodel=Web.Web
    where (Web.http_content_encoding="*br*" OR Web.http_header="*content-encoding*br*")
    by _time span=1m Web.src Web.dest Web.uri_path
| `drop_dm_object_name("Web")`
| eval is_large=if(bytes_in>=`node2shell_large_br_bytes`, 1, 0)
| eval severity=case(is_large=1, "high", true(), "medium")
| where count>=1
| sort - bytes_in
```

Tuning: build a per-`uri_path` baseline of how often each route legitimately receives `br`. Routes with a baseline of zero and a sudden hit are your best leads. If your proxy can't surface the header via CIM, fall back to raw access logs with the `Content-Encoding` field added per Part 4.

#### 3.2 Crafted-attempt by construction: Brotli `BLOCK_SWITCH` / error -17 on a PATCHED host — CRITICAL

**Why it works.** This mirrors the PHP2Shell `memory_limit=-1` tier. Once a host is on fixed Brotli/Node, the decoder rejects the impossible block switch with the brand-new format error (`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`, code **-17**). That error essentially cannot occur from normal traffic — it is the fingerprint of someone sending the crafted stream. Scope to patched hosts with a lookup (`host, brotli_patched`).

```spl
`node_app_logs` ("BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH" OR "error code -17" OR "block switch")
| lookup node_patched_hosts host OUTPUT brotli_patched
| where brotli_patched="true"
| rex "(?i)(?:client|from|src)[\":=\s]+(?<src>[0-9a-fA-F\.:]+)"
| stats count min(_time) as firstTime max(_time) as lastTime values(source) as sources values(src) as srcs by host
| eval severity="critical"
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

If you cannot attribute a source IP from the app log, pivot on `_time` + `host` into the access log (§3.1) to tie the error to the request that caused it.

#### 3.3 Inbound trigger: Brotli/zlib decode failure burst (any host) — MEDIUM (HIGH when paired with a crash)

**Why it works.** On vulnerable hosts a failed exploit or a sloppy PoC often throws a generic decode error (`Z_DATA_ERROR`, `ERR_CONTENT_DECODING`, an unhandled zlib/brotli error) rather than a clean -17. A burst of these from one source, on a route that decodes bodies, is the vulnerable-host equivalent of §3.2.

```spl
`node_app_logs` `brotli_decode_errors`
| rex "(?i)(?:client|from|src|ip)[\":=\s]+(?<src>[0-9a-fA-F\.:]+)"
| eval src=coalesce(src,"unknown")
| bin _time span=5m
| stats count values(source) as sources dc(_raw) as distinct_errors by _time host src
| where count>=3
| sort - count
```

Expect application bugs and genuinely corrupt uploads here; this tier is a lead generator, promoted to HIGH only when §3.5/§3.6 shows a crash on the same host/window.

#### 3.4 Decode fault: native Node/Bun abort or segfault — HIGH (CRITICAL correlated)

**Why it works.** The OOB write destabilizes the process. A native **SIGABRT/SIGSEGV/SIGTRAP** in a Node/Bun service — seen as a kernel `segfault`/`traps:` line, a systemd `status=11/SEGV`/`6/ABRT`, or a process-manager crash — is the loudest receipt this bug produces. Baseline it: native modules and OOM can also crash Node, so correlation (§3.6) is what makes it high-confidence.

```spl
(`node_process_managers` ("SEGV" OR "SIGSEGV" OR "SIGABRT" OR "ABRT" OR "SIGTRAP" OR "signal 11" OR "signal 6" OR "signal 5" OR "status=11" OR "status=6" OR "Aborted" OR "errored" OR "CrashLoopBackOff" OR "exitCode\":134" OR "exitCode\":139" OR "exitCode\":133"))
OR (`linux_kernel_logs` "segfault at" (node OR nodejs OR bun OR "next-server"))
OR (`linux_kernel_logs` "traps:" (node OR nodejs OR bun))
| rex "(?<crash_proc>node\w*|nodejs|bun|next-server)\[(?<seg_pid>\d+)\]"
| rex "status=(?<sig_status>\d+)"
| rex "exitCode\"?[:=\s]+(?<exit_code>\d+)"
| eval signal=case(match(_raw,"SEGV|segfault|signal 11|status=11|139"),"SIGSEGV",
                   match(_raw,"ABRT|Aborted|signal 6|status=6|134"),"SIGABRT",
                   match(_raw,"TRAP|signal 5|133"),"SIGTRAP", true(),"other")
| bin _time span=5m
| stats count values(crash_proc) as procs values(signal) as signals values(source) as sources by _time host
| sort - count
```

#### 3.5 Active DoS: Node service crash-loop — HIGH

**Why it works.** The most reliable thing an attacker can do here is crash the process on demand. Repeated restarts of one service in a short window — pm2 restart counter climbing, systemd `Scheduled restart`, k8s `restartCount` jumping with `CrashLoopBackOff` — is an ongoing DoS and, often, repeated exploitation attempts.

```spl
`node_process_managers` ("restart" OR "Scheduled restart" OR "errored" OR "CrashLoopBackOff" OR "BackOff" OR "Restarting")
| rex "(?<svc>(?:[\w\-]+\.service)|(?:[\w\-]+))\b"
| bin _time span=10m
| stats count values(source) as sources by _time host svc
| where count>=5
| eval verdict="crash_loop - active DoS or repeated attempts"
| sort - count
```

Baseline deploy windows and rolling restarts out (they look identical); exclude known deployment orchestrators by host/user.

#### 3.6 Correlation: `br` request → crash (the strongest inbound detector) — CRITICAL

**Why it works.** A `Content-Encoding: br` request (or a Brotli decode error) on a host, followed within a few minutes by a native abort/segfault of that host's Node service, is the inbound trigger landing. It needs no payload bytes, so it survives HTTPS as long as the proxy logs the header.

```spl
(| tstats `summariesonly` count from datamodel=Web.Web
     where (Web.http_content_encoding="*br*") by _time span=1m Web.dest
 | `drop_dm_object_name("Web")` | rename dest as host | eval evt="br_request")
| append [ search `node_app_logs` `brotli_decode_errors` | bin _time span=1m | eval evt="decode_error" | stats count by _time host evt ]
| append [ search (`node_process_managers` ("SEGV" OR "SIGABRT" OR "SIGTRAP" OR "CrashLoopBackOff" OR "signal 11" OR "signal 6")) OR (`linux_kernel_logs` "segfault at" (node OR bun)) | bin _time span=1m | eval evt="crash" | stats count by _time host evt ]
| bin _time span=10m
| stats count(eval(evt="br_request")) as br_reqs count(eval(evt="decode_error")) as decode_errs count(eval(evt="crash")) as crashes min(_time) as firstTime by host _time
| where (br_reqs>=1 OR decode_errs>=1) AND crashes>=1
| eval verdict=if(decode_errs>=1 AND crashes>=1,"decode_error_then_crash","br_request_then_crash")
| convert ctime(firstTime)
| sort - crashes
```

#### 3.7 Outbound trigger: egress to an odd host then a Node crash — MEDIUM / HUNT

**Why it works.** The consumed-response path leaves no inbound request. The only runtime tell is your own service reaching out to a non-standard destination and then crashing moments later — the malicious server answered the `fetch()` with crafted `br`. This is a hunt, not a clean rule, and it needs egress telemetry tied to the node process.

```spl
index=os sourcetype="sysmon:linux" EventCode=3
    (Image="*node*" OR Image="*bun*" OR Image="*next-server*")
| where NOT (cidrmatch("10.0.0.0/8",DestinationIp) OR cidrmatch("172.16.0.0/12",DestinationIp) OR cidrmatch("192.168.0.0/16",DestinationIp) OR cidrmatch("127.0.0.0/8",DestinationIp))
| bin _time span=5m
| stats values(DestinationIp) as egress_ips values(DestinationPort) as ports count as egress_count by _time host Image
| join type=left _time host [ search (`node_process_managers` ("SEGV" OR "SIGABRT" OR "SIGTRAP")) OR (`linux_kernel_logs` "segfault at" (node OR bun)) | bin _time span=5m | stats count as crashes by _time host ]
| where crashes>=1
| eval verdict="egress_then_crash - possible consumed-response (outbound) trigger"
| sort - crashes
```

Pair with a `first_seen` lookup of egress destinations per service so a brand-new destination weighs more.

#### 3.8 Memory-read primitive: anomalous response on an affected route — MEDIUM / HUNT

**Why it works.** The read primitive returns worker memory in the response. Without the crash, the only signal is a response that is abnormally large, binary-looking, or carries high entropy on a route that normally returns small JSON. Needs response-size/body logging at the proxy.

```spl
index=proxy OR index=waf (uri_path=* resp_bytes=*)
| where resp_bytes>=131072 AND method IN ("POST","PUT","PATCH")
| eval looks_binary=if(match(content_type,"(?i)text|json|html")=0 AND resp_bytes>0, 1, 0)
| stats count max(resp_bytes) as max_resp avg(resp_bytes) as avg_resp values(content_type) as ctypes by dest uri_path
| eventstats avg(avg_resp) as route_avg stdev(avg_resp) as route_sd by dest uri_path
| where max_resp > (route_avg + 4*route_sd)
| sort - max_resp
```

Very environment-specific; treat as a hunting seed and confirm by eyeballing samples (never log the leaked bytes themselves into a shared index).

#### 3.9 WAF / vendor rule hits (Vercel, Imperva, ModSecurity, IDS) — HIGH

**Why it works.** Vercel and Imperva shipped rules on disclosure day; if you ingest their events, match them directly rather than reinventing the logic. Plug in the real rule IDs once you have them from your vendor console — the placeholders below key on the CVE and on `Content-Encoding: br` so the search is useful immediately.

```spl
(index=waf (cve IN ("CVE-2026-111497") OR rule_name="*node2shell*" OR rule_name="*brotli*" OR rule_name="*http2shell*"))
OR (index=waf sourcetype="modsec*" ("content-encoding" "br") "multipart/form-data"=false)
| eval src=coalesce(ClientIP, src_ip, src, client_ip)
| stats count values(action) as action values(rule_name) as rules values(uri_path) as paths min(_time) as firstTime by src dest host
| convert ctime(firstTime)
| sort - count
```

```spl
| tstats `summariesonly` count min(_time) as firstTime values(IDS_Attacks.signature) as signature
    from datamodel=Intrusion_Detection.IDS_Attacks
    where (IDS_Attacks.signature="*CVE-2026-111497*" OR IDS_Attacks.signature="*Node2Shell*" OR IDS_Attacks.signature="*Brotli*" OR IDS_Attacks.signature="*HTTP2Shell*")
    by IDS_Attacks.src IDS_Attacks.dest
| `drop_dm_object_name("IDS_Attacks")`
| convert ctime(firstTime)
```

#### 3.10 IOC match — PLACEHOLDER (no intel published yet)

**Why it works.** It doesn't, yet. No IPs, UAs, scanners, or hashes have been published for this CVE. This stub exists so the pack is ready the moment intel lands — fill `[node2shell_ioc_ips]` (§3.0) and/or a UA list and this search goes live. Until then it matches nothing on purpose.

```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    values(Web.url) as urls values(Web.http_method) as methods values(Web.status) as statuses
    from datamodel=Web.Web where `node2shell_ioc_ips` by Web.src Web.dest
| `drop_dm_object_name("Web")`
| convert ctime(firstTime) ctime(lastTime)
```

---

### Tier 2 — Success detection (process + host layer)

This is where you confirm a compromise. It's root-cause-agnostic: a Node/Bun runtime doing something a request-serving process never does. Several of these mirror Elastic's and Falco's published web-server-exploitation rules; they are the same high-value detections as the PHP2Shell pack, re-parented to Node.

#### 3.11 Node/Bun worker spawns a shell, interpreter, or downloader — CRITICAL

**Why it works.** `node`/`bun`/`next-server` do not `exec` a shell or downloader in normal request handling. This is the tightest "RCE just succeeded" signal. (Node apps legitimately shell out sometimes — build steps, `sharp`, image/PDF tooling, git — so baseline those.)

```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.parent_process) as parent_process
    from datamodel=Endpoint.Processes
    where `node_worker_parents`
      AND (Processes.process_name IN ("sh","bash","dash","zsh","ksh","ash","busybox","curl","wget","perl","ruby","nc","ncat","netcat","socat","base64","openssl","xxd","telnet","whoami","id","uname","hostname")
           OR Processes.process_name="python*")
    by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| `drop_dm_object_name("Processes")`
| search NOT process="*sharp*" NOT process="*node-gyp*" NOT process="*/git*" NOT process="*prebuild*"
| eval fileless=if(match(mvjoin(process_path," "), "memfd:|\(deleted\)"), "yes", "no")
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

Baseline your own build/runtime child processes (npm/pnpm lifecycle scripts, `sharp`, `puppeteer`/`chrome`, `ffmpeg`, `git`) and exclude them explicitly rather than widening the allowlist.

#### 3.12 Node worker runs a discovery / credential / reverse-shell command line — CRITICAL

**Why it works.** Mirrors Elastic's "Payload Execution by Web Server." After RCE, attackers run a predictable first set of commands. Keys on a Node parent launching a shell with a high-risk command line.

```spl
| tstats `summariesonly` count min(_time) as firstTime
    values(Processes.process) as process values(Processes.user) as user
    from datamodel=Endpoint.Processes
    where `node_worker_parents` AND Processes.process_name IN ("sh","bash","dash","zsh","ksh")
    by Processes.dest Processes.parent_process_name Processes.process
| `drop_dm_object_name("Processes")`
| where match(process, "(?i)(/dev/tcp/|base64\s+-d|curl\s|wget\s|/etc/shadow|/etc/passwd|\.aws/credentials|169\.254\.169\.254|mkfifo|socat|sudo\s+-l|-perm\s+-u=s|getcap|pty\.spawn|child_process|require\('child_process'\))")
| eval technique=case(match(process,"/dev/tcp/|mkfifo|socat|pty\.spawn"),"reverse_shell",
                      match(process,"\.aws/credentials|169\.254\.169\.254|/etc/shadow"),"cred_access",
                      match(process,"curl|wget|base64 -d"),"ingress_tool",
                      match(process,"sudo -l|-perm -u=s|getcap"),"privesc_enum", true(),"discovery")
| stats count values(technique) as techniques values(process) as commands min(_time) as firstTime by dest parent_process_name user
| convert ctime(firstTime)
| sort - count
```

#### 3.13 Fileless execution: memfd + execveat via auditd — CRITICAL

**Why it works.** A fileless completion path creates an anonymous `memfd` and runs it with `execveat(…, AT_EMPTY_PATH)` — nothing touches disk. A Node worker calling `memfd_create`, or a child running from `/memfd:… (deleted)`, is near-zero-FP. Needs auditd rules keyed on the node service UID (find it with `id www-data`/your app user; common app UIDs differ per deploy — set it, don't assume 33):

```
-a always,exit -F arch=b64 -S execve,execveat -F euid=<NODE_UID> -k node-child
-a always,exit -F arch=b64 -S memfd_create -F euid=<NODE_UID> -k node-memfd
```

```spl
index=os sourcetype=linux:audit type=SYSCALL (key="node-memfd" OR key="\"node-memfd\"" OR key="node-child" OR key="\"node-child\"")
| eval key=trim(key, "\""), comm=trim(comm, "\""), exe=trim(exe, "\"")
| search key="node-memfd" OR (key="node-child" NOT exe IN ("/usr/bin/git","/usr/bin/npm","/usr/bin/node"))
| eval severity=if(key="node-memfd" OR like(exe, "/memfd:%"), "critical", "high")
| stats count min(_time) as firstTime values(exe) as exe values(comm) as comm values(ppid) as ppid by host key euid severity
| convert ctime(firstTime)
| sort - severity
```

#### 3.14 Outbound connections from a Node worker — HIGH

**Why it works.** A worker opening new outbound TCP to a non-database, non-API endpoint after a trigger is C2 or a stager. Tuned for odd ports; run a separate `first_seen` hunt for new 443 destinations. (Note the overlap with §3.7 — there the egress *precedes* a crash and suggests the outbound trigger; here it *follows* execution and suggests C2.)

```spl
index=os sourcetype="sysmon:linux" EventCode=3
    (Image="*node*" OR Image="*bun*" OR Image="*next-server*")
| where NOT (cidrmatch("10.0.0.0/8", DestinationIp) OR cidrmatch("172.16.0.0/12", DestinationIp) OR cidrmatch("192.168.0.0/16", DestinationIp) OR cidrmatch("127.0.0.0/8", DestinationIp))
| where NOT DestinationPort IN ("443","80","3306","5432","6379","11211","25","587","27017")
| stats count dc(DestinationIp) as dest_count values(DestinationIp) as dest_ips values(DestinationPort) as ports by host Image User
| sort - dest_count
```

#### 3.15 Cloud metadata / credential-file access by the node user — CRITICAL

**Why it works.** A node-user process reaching the instance metadata endpoint (`169.254.169.254`) or reading `.env` / `~/.aws/credentials` / k8s service-account tokens is a strong post-ex signal and maps to T1552. The memory-read primitive makes this doubly relevant here — secrets can leak even without a shell.

```spl
(index=os sourcetype="sysmon:linux" EventCode=3 DestinationIp="169.254.169.254"
    (Image="*node*" OR Image="*bun*" OR Image="*next-server*"))
| eval sig="imds_access"
| stats count values(Image) as image min(_time) as firstTime by host User sig
| convert ctime(firstTime)
```

For file reads, pair with file-event telemetry:

```spl
| tstats `summariesonly` count values(Filesystem.file_path) as file_path
    from datamodel=Endpoint.Filesystem
    where Filesystem.action="read"
      AND Filesystem.user IN ("node","nodejs","www-data","app","nobody")
      AND (Filesystem.file_name=".env" OR Filesystem.file_path="*/.aws/credentials"
           OR Filesystem.file_path="*/secrets/kubernetes.io/*" OR Filesystem.file_name="shadow")
    by Filesystem.dest Filesystem.user Filesystem.file_name
| `drop_dm_object_name("Filesystem")`
```

Set the user list to your actual app service account(s).

#### 3.16 Backdoor drop and persistence by the node user — HIGH

**Why it works.** After running commands, attackers persist. The Node-flavored variants: a new or modified `.js`/`.mjs`/`.cjs` in the app directory, a tampered `package.json` (new `start`/`postinstall` script), a new route file, or classic cron/systemd/authorized_keys writes by the node user.

```spl
| tstats `summariesonly` count min(_time) as firstTime values(Filesystem.file_path) as file_path
    from datamodel=Endpoint.Filesystem
    where (Filesystem.action="created" OR Filesystem.action="modified")
      AND Filesystem.user IN ("node","nodejs","www-data","app","nobody")
      AND (Filesystem.file_name="*.js" OR Filesystem.file_name="*.mjs" OR Filesystem.file_name="*.cjs"
           OR Filesystem.file_name="package.json" OR Filesystem.file_name="*.ts"
           OR Filesystem.file_path="*/.ssh/authorized_keys" OR Filesystem.file_path="*/cron.d/*"
           OR Filesystem.file_path="*/systemd/system/*")
    by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name("Filesystem")`
| eval technique=case(match(file_path,"authorized_keys"),"T1098.004_ssh_key",
                      match(file_path,"cron|systemd"),"T1053_scheduled_task",
                      match(file_name,"package\.json"),"package_json_tamper",
                      true(),"T1505.003_backdoor_js")
| convert ctime(firstTime)
| sort - firstTime
```

The hard part is deployments, which also write `.js` and `package.json` as the app user. Exclude deploy windows / CI service accounts / release paths, and weight writes that happen *outside* a deploy and *by a process whose parent is a running node worker* rather than your deploy tooling.

---

### Tier 3 — Rollup, scoping, and inventory

#### 3.17 Risk-based rollup (Splunk ES) — correlation

**Why it works.** Have the searches above emit RBA risk on `src`/`dest`. A host accumulating both attempt-layer (crash/decode-error) and success-layer (shell/cred) risk, or crossing a score threshold, is your true-positive candidate.

```spl
| tstats `summariesonly` sum(All_Risk.calculated_risk_score) as risk_score dc(source) as source_count values(source) as sources
    from datamodel=Risk.All_Risk
    where All_Risk.annotations.mitre_attack.mitre_technique_id IN ("T1190","T1203","T1499.004","T1059.004","T1620","T1505.003","T1552.005")
      AND source="*Node2Shell*"
    by All_Risk.risk_object All_Risk.risk_object_type
| `drop_dm_object_name("All_Risk")`
| where source_count>=2 OR risk_score>=100
| sort - risk_score
```

#### 3.18 Exposure scoping — the whole Brotli-carrier inventory

**Why it works.** This is the most important search in the pack, because HTTP2Shell is ecosystem-wide and your exposure is almost certainly broader than "our Node services." You can't defend what you can't see; OS package tables miss **bundled** runtimes, so combine the vuln data model, osquery/SBOM, and process telemetry.

```spl
| tstats `summariesonly` count values(Vulnerabilities.severity) as severity
    from datamodel=Vulnerabilities.Vulnerabilities
    where Vulnerabilities.cve IN ("CVE-2026-111497")
    by Vulnerabilities.dest
| `drop_dm_object_name("Vulnerabilities")`
```

Osquery / package fallback — flag any carrier below its fixed version. Node: anything below 22.23.4 / 24.22.1 / 26.12.1, plus every 20.x and earlier (EOL). Bun < 1.4.4. Python `Brotli`/`brotlicffi` ≤ 1.2.0. `libbrotli` below your distro's patched build. brotli4j < 1.24.0. Envoy/Istio below the fixed trains. Watch container images especially.

```spl
index=os (sourcetype="osquery*" OR sourcetype="sbom*")
    (name="node*" OR name="nodejs*" OR name="bun*" OR name="libbrotli*" OR name="brotli*" OR name="brotlicffi*" OR name="brotli4j*" OR name="System.IO.Compression*" OR name="envoy*" OR name="istio*")
| rex field=version "(?<maj>\d+)\.(?<min>\d+)\.(?<pat>\d+)"
| eval carrier=case(match(name,"^node"),"nodejs", match(name,"^bun"),"bun",
                    match(name,"brotlicffi"),"py_brotlicffi", match(name,"^brotli$|^Brotli$"),"py_brotli",
                    match(name,"libbrotli|^brotli"),"libbrotli", match(name,"brotli4j"),"java_brotli4j",
                    match(name,"System.IO"),"dotnet", match(name,"envoy"),"envoy", match(name,"istio"),"istio", true(),"other")
| eval vuln=case(
    carrier="nodejs" AND ((maj<22) OR (maj=22 AND (min<23 OR (min=23 AND pat<4))) OR (maj=24 AND (min<22 OR (min=22 AND pat<1))) OR (maj=26 AND (min<12 OR (min=12 AND pat<1)))), "vulnerable",
    carrier="bun" AND (maj<1 OR (maj=1 AND (min<4 OR (min=4 AND pat<4)))), "vulnerable",
    (carrier="py_brotli" OR carrier="py_brotlicffi" OR carrier="libbrotli") AND (maj<1 OR (maj=1 AND min<2) OR (maj=1 AND min=2 AND pat<1)), "vulnerable_or_check_backport",
    carrier="java_brotli4j" AND (maj<1 OR (maj=1 AND min<24)), "vulnerable",
    true(),"review")
| where vuln!="review"
| stats values(version) as versions values(vuln) as status by host carrier name
| sort carrier host
```

Reminder: Debian/RHEL and others backport the fix without bumping the upstream version string, so a "vulnerable-looking" `libbrotli` on a patched distro may be fine — reconcile against the vendor advisory before alerting.

---

## Part 4 — Logging and hardening gaps to fix today

1. **Log the inbound `Content-Encoding` request header and request body size.** Most access-log formats omit request `Content-Encoding`, which is the single most useful field for §3.1/§3.6. nginx: add `ce=$http_content_encoding $request_length`. Apache: `%{Content-Encoding}i %I` (needs mod_logio). Zeek's `http.log` already carries it.
2. **Capture Node process-exit signals and codes.** A native abort prints little through V8, so the exit signal is your evidence. Make sure pm2 (`pm2 jlist`), systemd journal, and k8s `lastState.terminated.exitCode`/`reason` are all shipped. Map 134=SIGABRT, 139=SIGSEGV, 133=SIGTRAP.
3. **Don't forget the outbound/consumed-response path.** An inbound WAF rule is only half the control. Any service that `fetch()`es half-trusted URLs (webhooks, SSRF-reachable endpoints, third-party APIs) is exposed through the response direction, which no inbound rule sees. For that path, upgrading is the only real fix — and until you do, strip `br` from `Accept-Encoding` *and* reject `br` responses before decoding (changing `Accept-Encoding` alone is not enough; a malicious server sends `br` anyway).
4. **Deploy the auditd rules** in §3.13 on Node hosts, keyed on your actual app UID, so fileless execution is visible.
5. **Inventory bundled runtimes, not just OS packages.** Add Node/Bun/Brotli to your SBOM/image scanning. The exposure is almost always wider than the Node services you know about — Python clients (`httpx[brotli]`, aiohttp, Scrapy), curl built with brotli, Envoy/Istio sidecars, .NET services, Java brotli4j. Run §3.18 and act on the long tail.
6. **Rotate secrets on any internet-facing host that showed crash or decode-error activity while unpatched.** The memory-read primitive can leak live process memory — tokens, keys, session material — without a shell. If a host was taking crafted Brotli and crashing before you patched, assume a window of possible disclosure.
7. **Prioritize by direction and reachability:** internet-facing Express 5 / body-parser 2 routes that decode `br` (inbound) and services that fetch untrusted URLs (outbound) first; internal-only services last. Patch the carriers from §3.18 in that order.
