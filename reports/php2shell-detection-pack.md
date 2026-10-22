# PHP2Shell Detection Pack — CVE-2026-109618 / CVE-2026-109619

_Compiled 2026-10-22. Disclosure was October 21, 2026, and research is still moving fast, so expect details to shift. All SPL here is untested against live exploit traffic; validate in your environment before promoting any of it to a correlation search._

---

## Part 1 — Understanding the flaws

### Why this is a big deal

PHP2Shell is a pair of memory-safety bugs in the PHP engine itself, not in any application on top of it. That distinction is the whole story for a detection engineer:

- **It is pre-authentication and pre-application.** The malicious request is processed during PHP's request-startup phase, before your app's code runs. Application-level auth, a login wall, a WAF rule that keys on the app's routes — none of it sees the request in time. Even a one-line "Hello World" script on a vulnerable PHP version is exploitable.
- **It is everywhere.** PHP runs an estimated ~70% of websites. Every version back to PHP 5.4 is affected by at least one of the bugs. WordPress, Drupal, Joomla, Magento, MediaWiki, and a long tail of appliances and control panels that bundle PHP are all in scope.
- **The application logs may be nearly empty.** Because the bug fires below the app layer, your WordPress or Drupal logs often show nothing. Detection has to move down to the PHP runtime, the web server, and the host.

Researchers (Wiz, Calif, OpenAI) are comparing it to Heartbleed and Log4Shell. Like Heartbleed, one of the primitives leaks live process memory (passwords, tokens, API keys, TLS private keys) without needing code execution at all.

### The two CVEs, and the four primitives underneath them

The two CVE IDs are umbrellas. Wiz reported four distinct exploitable bugs (and says more variants exist), all stemming from the same root pattern: **PHP mishandles an out-of-memory (OOM) fatal during request startup and leaves corrupted or stale internal state behind.**

| CVE | Primitive | Mechanism in plain terms | Demonstrated impact |
|---|---|---|---|
| **109618** | OOM corruption | During multipart parsing, an allocation failure interrupts PHP while request data is half-initialized. PHP's older OOM path used `longjmp()` to bail out, skipping cleanup. Request shutdown then reads that invalid data as if valid. | Pre-auth RCE on mod_php (zero-dependency; needs no session feature) |
| **109618** | Process-memory disclosure | A stale session-ID pointer (`PS(id)`) left dangling after an OOM gets URL-encoded into the response `PHPSESSID` cookie on a later request. Works even if the app never calls `session_start()`. | Heartbleed-style leak of attacker-sized worker memory |
| **109619** | Upload-progress unserializer UAF | The session upload-progress decoder stores bookkeeping in a global (`BG(unserialize)`). An OOM interrupts it and leaves that global published, pointing at freed memory. A later request on the same worker reuses it. | Pre-auth RCE on WordPress, Drupal, Joomla |
| **109619** | Fatal-error backtrace UAF | PHP keeps the last fatal error's backtrace in `EG(last_fatal_error_backtrace)`. An OOM frees the request heap without clearing it; the next request's early diagnostic follows the dangling pointer. | Pre-auth RCE on Drupal (set `fatal_error_backtraces=0` on 8.5 to blunt this) |
| **109619** | OPcache type confusion | A persistence frontier (`CG(map_ptr_last)`) advances locally but publishes to shared memory only after persistence finishes. An OOM in between leaves slots the shared state still thinks are free. Another worker reuses the slot with the wrong type. | Cross-worker type confusion → RCE on WordPress |

**The common exploit shape.** Most chains need two requests to the same worker:

1. **The "arm" (producer):** a multipart POST crafted to exhaust `memory_limit` during parsing — many file parts, very long filenames made of one repeated character, `PHP_SESSION_UPLOAD_PROGRESS` set. The OOM fires, the worker survives with corrupt/stale state.
2. **The "fire" (consumer):** a second multipart POST that reaches the cleanup path and makes PHP act on the poisoned state.

Reliable exploitation needs several arm/fire cycles against one worker pool to defeat ASLR and line up the memory layout. That repetition is itself a detection signal.

### A note on exploitation status (as of 2026-10-22)

- Amazon (MadPot honeypots) saw a probe on **October 17**, four days before disclosure, from `103.216.220.92` (a commercial anonymization network). It advises investigating back to **at least October 17**.
- Cloudflare's CEO said they saw thousands of attempts in the ~10 hours before disclosure, rising to millions after.
- watchTowr, Hadrian, VulnCheck, and others report active exploitation **attempts**. Hadrian saw scale mostly via the session upload-progress path. VulnCheck saw at least one Chinese IP try (and fail) to drop a web shell.
- As of the last public statements, **no confirmed successful breach** of a live production system had been reported; much of the early traffic was recon or sloppy/non-working PoCs. Treat that as a snapshot that will age quickly.

---

## Part 2 — Detection strategy

### The governing principle: attempts are loud, successes are quiet

This is the single most important idea for building these detections.

- An **attempt** (the arm) throws a memory fatal, a 500/502, and error-log receipts. It's noisy.
- A **successful fire** can return a clean **HTTP 200**, with the code running silently inside the worker. The crash, if any, can even land on a *later* request to the same worker.

So you split your detection into two tiers:

1. **Attempt detection** lives at the **web and error-log layer** — multipart POSTs, OOM fatals, worker crashes, anomalous cookies.
2. **Success detection** moves **off the request and onto the process and host** — a PHP worker spawning a shell, running from memory, making outbound connections, or dropping a web shell. This is where high-confidence confirmation comes from, and it's root-cause-agnostic: it looks the same whether the door was opened by PHP2Shell or any other PHP RCE.

### Exploit lifecycle mapped to observables and log sources

| Stage | ATT&CK | What happens | Observable | Where to look |
|---|---|---|---|---|
| Recon / scan | T1595 | Probe GET then multipart POST to `index.php` | UA `php2shell-scan/109618`, `php2shell-poc`; known IOC IPs | Web access, WAF, proxy |
| **Arm** | T1190 | Huge multipart POST, long repeated filenames, `PHP_SESSION_UPLOAD_PROGRESS` | `Allowed memory size … exhausted … in Unknown on line 0`; `Failed to decode session object`; 500/502; FPM `child N exited with code 70` | PHP error log, web error log, FPM master log, access log |
| Memory leak | T1005 / T1552 | Stale `PS(id)` encoded into the response cookie | Oversized / non-hex `Set-Cookie: PHPSESSID=` | Proxy/WAF response logs, NIDS |
| **Fire** | T1190 | Second multipart POST on same worker | Worker SIGSEGV; nginx `upstream prematurely closed`; Apache `AH01075`; 502 — **or a clean 200 on success** | FPM master log, kernel log, web error log, access log |
| **Execution** | T1059 / T1620 | Code runs in the worker | Worker spawns sh/bash/python/curl; `memfd_create` + `execveat` (fileless); outbound connections | EDR, Sysmon for Linux, auditd, Falco |
| Discovery | T1033 / T1082 | Confirm access, enumerate | `id`, `whoami`, `uname -a`, `hostname`, `cat /etc/os-release`, `sudo -l`, `find / -perm -u=s` | EDR process telemetry |
| Credential access | T1552 | Harvest secrets | Reads of `.env`, `~/.aws/credentials`, k8s SA token, `169.254.169.254` | EDR process/file, netflow |
| LFI session-read chain | T1190 | Plant via upload-progress, read via `php://filter` | `?file=php://filter...`, requests for `sess_<id>` | Web access log |
| Post-ex / persistence | T1505.003 / T1053 | Web shell, cron, SSH key | New `.php`/`.phtml` in web root; high-entropy file; cron/systemd/authorized_keys writes by web user | FIM, EDR file events |

### What does NOT work (and why)

- **Payload byte-signatures.** The payload bytes are filler; the forged-struct offsets are tuned per PHP build. There's no stable byte pattern to match. Detect the *request structure*, not the bytes.
- **Rate limiting alone.** A single request can arm the worker; the fire follows in a second.
- **`session.upload_progress.enabled=0` by itself.** It closes only the confirmed session path. A second route through the multipart parser remains, and PHP parses the multipart body before your app's `ini_set()` runs. The PHP team's own guidance walked this back as a complete fix.
- **`file_uploads=Off`, `post_max_size` alone, blocking the PHPSESSID cookie.** PHP still parses the multipart body; chunked/lengthless bodies bypass `post_max_size`; `filename=""` parts bypass `max_file_uploads`; blocking the cookie breaks sessions and misses custom session names.
- **ModSecurity `REQUEST_BODY @contains PHP_SESSION_UPLOAD_PROGRESS`.** `REQUEST_BODY` is empty for multipart requests in ModSecurity, so the rule never fires. Match the parsed field name (`ARGS_POST_NAMES|FILES_NAMES`) instead.

### Precision ladder (highest-fidelity signal first)

1. A PHP worker spawns a shell/downloader, or runs from memfd → **confirmed RCE**
2. A PHP worker reads cloud creds / metadata endpoint, or drops a web shell → **confirmed post-ex**
3. A `PHPSESSID` Set-Cookie fails the expected format → **memory disclosure**
4. The OOM fatal `in Unknown on line 0` → **arm attempt** (critical if `memory_limit=-1` is enforced)
5. A `PHP_SESSION_UPLOAD_PROGRESS` field after the mitigation is applied → **attempt by construction**
6. FPM SIGSEGV correlated with #4 from same source/pool → **fire**
7. Access-log pattern: large-POST 5xx then 502 or 2xx from same source → **attempt / possible success**

### Log sources and the config that makes them useful

| Source | Location / sourcetype | What you must enable |
|---|---|---|
| PHP error log | `error_log` path, or wrapped into nginx error log (`FastCGI sent in stderr: "PHP message: …"`), Apache ErrorLog (`AH01071` / `[php:error]`), or FPM stderr in containers | `log_errors=On`. **Official `php:*-fpm` Docker images ship with no php.ini, so `log_errors` is Off and the arm fatal is never written.** Check `fastcgi.logging` and `catch_workers_output`. |
| PHP-FPM master log | `/var/log/php8.x-fpm.log` (Debian/Ubuntu), `/var/log/php-fpm/error.log` (RHEL), journal | Default. Carries `child N exited` lines even with no PHP logging. |
| Kernel log | `/var/log/kern.log`, `/var/log/messages`, `journalctl -k` | Default (`segfault at … in php-fpm`) |
| Web access log | nginx / Apache (CIM Web) | Add `$request_length` (nginx) / `%I` (Apache + mod_logio) and `$cookie_PHPSESSID` to the log format |
| Reverse proxy / WAF | Cloudflare firewall events, ModSecurity audit, F5/ALB | Response-header logging for Set-Cookie (for the disclosure rule) |
| NIDS | Suricata / Zeek (CIM Intrusion_Detection) | TLS termination ahead of the sensor |
| Endpoint process | EDR, Sysmon for Linux, auditd (CIM Endpoint.Processes) | Full parent/child lineage, exe path |
| auditd | `linux:audit` | Rules keyed on the pool UID for `execve`, `execveat`, `memfd_create` |
| FIM / file events | EDR, auditd, OSSEC (CIM Endpoint.Filesystem) | Webroot + session `save_path` monitoring |
| Vuln scanner | CIM Vulnerabilities | Tenable plugin 369483; or osquery `deb_packages`/`rpm_packages` |

### ATT&CK coverage

T1595 (Active Scanning) · T1190 (Exploit Public-Facing Application) · T1059.004 (Unix Shell) · T1059.006 (Python) · T1620 (Reflective Code Loading / fileless) · T1505.003 (Web Shell) · T1105 (Ingress Tool Transfer) · T1071.001 (Web C2) · T1033 / T1082 (Discovery) · T1552.001 / T1552.005 (Creds in files / cloud metadata) · T1005 (Data from Local System) · T1053.003 (Cron) · T1098.004 (SSH authorized_keys) · T1499.004 (Application-exploitation DoS).

---

## Part 3 — SPL searches

> **Read before deploying.** These lean on CIM data models (Web, Endpoint, Intrusion_Detection, Vulnerabilities, Risk) where possible, and on raw sourcetypes where the data doesn't model cleanly (PHP error logs). Swap index names, sourcetypes, and the tuning thresholds (arm size, UID, exclusions) for your environment. Several searches depend on logging you may need to turn on first (Part 2 table).

### 3.0 Macros — define these first

```
[php_error_logs]
definition = (index=web OR index=os) (sourcetype="nginx:plus:error" OR sourcetype="nginx:error" OR sourcetype="apache:error" OR sourcetype="php:error" OR sourcetype="php-fpm*" OR source="*php*fpm*.log" OR source="*/php-fpm/*" OR source="*php_errors.log" OR source="*/nginx/error.log" OR source="*/apache2/error.log" OR source="*/httpd/error_log")

[php_fpm_logs]
definition = (index=web OR index=os) (sourcetype="php-fpm*" OR source="*php*fpm*.log" OR source="*/php-fpm/error.log" OR (sourcetype=journald _SYSTEMD_UNIT="php*fpm*"))

[linux_kernel_logs]
definition = index=os (source="*/kern.log" OR source="*/messages" OR (sourcetype=journald _TRANSPORT=kernel))

[php2shell_arm_bytes]
definition = 8388608
# Default post_max_size = 8M. Raise on hosts that legitimately accept large uploads.

[php_worker_parents]
definition = (Processes.parent_process_name="php-fpm*" OR Processes.parent_process_name="php-cgi*" OR Processes.parent_process_name="lsphp*" OR Processes.parent_process_name="php" OR Processes.parent_process_name="php8*" OR Processes.parent_process_name="php7*" OR Processes.parent_process_name="php5*" OR Processes.parent_process_name="frankenphp" OR Processes.parent_process_name="sw-engine-fpm" OR Processes.parent_process_name="httpd" OR Processes.parent_process_name="apache2" OR Processes.parent_process_name="nginx")

[php2shell_ioc_ips]
definition = (src IN ("103.216.220.92","31.223.184.166","37.19.200.5","134.209.159.64","103.114.163.188","95.217.98.37"))
# Amazon MadPot IOCs, 2026-10-17 to 2026-10-21. SHARED anonymization infra — investigate, don't block. Refresh from threat intel.
```

---

### Tier 1 — Attempt detection (web + error-log layer)

#### 3.1 Arm stage: pre-RINIT OOM fatal (PHP error log) — HIGH

**Why it works.** A genuine memory-limit fatal names the script that overran (`in /var/www/app/index.php on line 42`). `in Unknown on line 0` means the bailout happened *outside any script* — during the multipart parse at request startup. That's the arm. The token `exhausted` plus `Unknown on line 0` together are high-precision.

```spl
`php_error_logs` "Allowed memory size of" "exhausted"
| regex _raw="in\s+(<b>)?Unknown(</b>)?\s+on line\s+(<b>)?0"
| rex "Allowed memory size of (?<memory_limit_bytes>\d+) bytes exhausted \(tried to allocate (?<alloc_bytes>\d+) bytes\)"
| rex "client: (?<src_nginx>[0-9a-fA-F\.:]+)"
| rex "\[client (?<src_apache>[0-9a-fA-F\.:]+?)(?::\d+)?\]"
| rex "\[pid (?<worker_pid>\d+)"
| eval src=coalesce(src_nginx, src_apache, "unknown")
| stats count min(_time) as firstTime max(_time) as lastTime
        values(memory_limit_bytes) as memory_limit_bytes values(worker_pid) as worker_pids values(source) as sources
        by host src
| eval severity=if(count>=3, "high", "medium")
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

Tuning: on a host that legitimately serves big uploads, correlate by source IP before alerting. On a host that should never see huge multipart POSTs, a single hit is notable.

#### 3.2 Arm stage, critical variant: OOM fatal when `memory_limit=-1` is enforced — CRITICAL

**Why it works.** PHP's official mitigation is to set `memory_limit=-1` so the allocation can't fail the vulnerable way. If you've applied that, an "Allowed memory size … exhausted" message should be *impossible* in normal operation. Any occurrence means attack or config drift. Scope to mitigated hosts with a lookup (CSV of `host, memory_limit_unlimited`).

```spl
`php_error_logs` "Allowed memory size of" "exhausted"
| lookup php_mitigated_hosts host OUTPUT memory_limit_unlimited
| where memory_limit_unlimited="true"
| rex "client: (?<src>[0-9a-fA-F\.:]+)"
| stats count values(source) as sources min(_time) as firstTime by host src
| convert ctime(firstTime)
```

#### 3.3 Arm stage: session decode failure — MEDIUM (HIGH when paired with 3.1)

**Why it works.** After the OOM interrupts the upload-progress unserializer, the follow-on receipt is `Failed to decode session object` / `Session object destruction failed`. On hosts not otherwise corrupting session files, this has near-zero false positives.

```spl
`php_error_logs` ("Failed to decode session object" OR "Session object destruction failed" OR "Session has been destroyed in Unknown")
| rex "client: (?<src_nginx>[0-9a-fA-F\.:]+)"
| rex "\[client (?<src_apache>[0-9a-fA-F\.:]+?)(?::\d+)?\]"
| eval src=coalesce(src_nginx, src_apache, "unknown")
| stats count min(_time) as firstTime max(_time) as lastTime by host src
| convert ctime(firstTime) ctime(lastTime)
```

#### 3.4 Combined arm receipt: OOM + decode failure in a short window — HIGH

**Why it works.** Seeing both receipts from the same host/source inside 2 minutes is much stronger than either alone — it's the signature of the upload-progress chain arming.

```spl
`php_error_logs` (("Allowed memory size of" "exhausted" "Unknown") OR "Failed to decode session object")
| rex "client: (?<src_nginx>[0-9a-fA-F\.:]+)"
| rex "\[client (?<src_apache>[0-9a-fA-F\.:]+?)(?::\d+)?\]"
| eval src=coalesce(src_nginx, src_apache, "unknown")
| eval sig=case(searchmatch("Failed to decode session object"), "decode_fail",
                match(_raw, "in\s+(<b>)?Unknown(</b>)?\s+on line"), "oom_unknown")
| where isnotnull(sig)
| bin _time span=2m
| stats dc(sig) as sig_types values(sig) as sigs count by _time host src
| where sig_types=2
```

#### 3.5 Fire stage: PHP worker crash (FPM master + kernel) — CRITICAL when correlated

**Why it works.** The fire can SEGV the worker. Signal 11 (SIGSEGV) in the FPM master log, or a `segfault at … in php-fpm` in the kernel log, is the crash receipt. Exit code 70 is the worker dying on the pre-RINIT fatal (the arm). Baseline both — buggy extensions also crash workers.

```spl
(`php_fpm_logs` ("exited on signal 11" OR "exited on signal 6" OR "exited on signal 7" OR "exited with code 70"))
OR (`linux_kernel_logs` "segfault at" (php OR php-fpm OR lsphp OR httpd OR apache2 OR frankenphp))
| rex "\[pool (?<pool>[^\]]+)\] child (?<child_pid>\d+) exited (?:on signal (?<signal>\d+)|with code (?<exit_code>\d+))"
| rex "(?<crash_proc>(?:php[\w\.\-]*|lsphp|httpd|apache2|frankenphp))\[(?<seg_pid>\d+)\]: segfault"
| eval stage=case(signal IN ("11","6","7") OR isnotnull(seg_pid), "fire_crash",
                  exit_code="70", "arm_worker_exit", true(), null())
| where isnotnull(stage)
| bin _time span=5m
| stats count values(pool) as pools values(crash_proc) as crash_procs by _time host stage
```

#### 3.6 Correlation: arm → fire across error logs (body-free) — CRITICAL

**Why it works.** This is the strongest body-free detector: an OOM-fatal arm followed within 15 minutes by a crash or upstream-502 on the same host. No request-body inspection, so it works over HTTPS.

```spl
(`php_error_logs` "Allowed memory size of" "exhausted" "Unknown")
OR (`php_fpm_logs` "exited on signal 11")
OR (`linux_kernel_logs` "segfault at" php)
OR (`php_error_logs` ("upstream prematurely closed connection" OR "AH01075" OR "upstream sent unexpected FastCGI record"))
| eval evt=case(match(_raw, "Allowed memory size.*Unknown"), "arm",
                searchmatch("exited on signal 11") OR searchmatch("segfault at"), "crash",
                true(), "upstream_502")
| bin _time span=15m
| stats count(eval(evt="arm")) as arms count(eval(evt="crash")) as crashes count(eval(evt="upstream_502")) as upstream_errs
        min(_time) as firstTime by host _time
| where arms>=1 AND (crashes>=1 OR upstream_errs>=1)
| eval verdict=if(crashes>=1, "fire_after_arm", "possible_fire")
| convert ctime(firstTime)
```

On mod_php you can tighten to the same worker PID via `[pid N]` in the Apache ErrorLog. On FPM the worker usually exits after the arm, so correlate by host + pool + time.

#### 3.7 Access-log arm → fire / possible success (CIM Web) — MEDIUM / HIGH

**Why it works.** Even without bodies, the arm/fire pair is visible as request size + status. Needs `bytes_in` populated (nginx `$request_length` / Apache `%I`). A 2xx after an arm *burst* is suspicious — but not proof, because a failed fire also returns 200. Confirm with Tier 2.

```spl
| tstats `summariesonly` count max(Web.bytes_in) as bytes_in values(Web.url) as url values(Web.http_user_agent) as ua
    from datamodel=Web.Web
    where Web.http_method="POST"
    by _time span=1s Web.src Web.dest Web.status
| `drop_dm_object_name("Web")`
| eval is_arm=if(status IN ("500","502","503") AND bytes_in>=`php2shell_arm_bytes`, 1, 0)
| eval is_fire502=if(status="502", 1, 0)
| eval is_2xx=if(like(status, "2%"), 1, 0)
| sort 0 _time
| streamstats time_window=10m current=f sum(is_arm) as prior_arms by src dest
| eval stage=case(is_arm=1, "arm",
                  is_fire502=1 AND prior_arms>=1, "fire_misfire",
                  is_2xx=1 AND prior_arms>=2, "2xx_after_arm_burst", true(), null())
| where isnotnull(stage)
| stats count(eval(stage="arm")) as arms count(eval(stage="fire_misfire")) as misfires
        count(eval(stage="2xx_after_arm_burst")) as post_burst_2xx
        min(_time) as firstTime max(_time) as lastTime values(url) as urls values(ua) as uas by src dest
| eval verdict=case(post_burst_2xx>=1, "SUSPICIOUS - check process layer (Tier 2)",
                    misfires>=1, "attempt - armed + fired",
                    arms>=3, "attempt - tuning burst", true(), "probe")
| convert ctime(firstTime) ctime(lastTime)
| sort - arms
```

#### 3.8 Structural fingerprint of the arm body — HIGH (needs body logging)

**Why it works.** The arm body carries many file parts with very long filenames made of one repeated character, plus many repeated array-style field names. Hundreds of identical long filenames in one body are anomalous on any normal form. This needs a WAF/proxy that logs parsed multipart part names or a Lua/ModSecurity hook.

```spl
index=waf OR index=proxy sourcetype IN ("modsec*","nginx:lua","cloudflare:*") "multipart/form-data"
| rex max_match=0 "filename=\"(?<fname>[^\"]{40,})\""
| eval part_count=mvcount(fname)
| eval has_upload_progress=if(match(_raw, "PHP_SESSION_UPLOAD_PROGRESS"), 1, 0)
| eval max_fname_len=max(mvmap(fname, len(fname)))
| eval repeated_char=mvfilter(match(fname, "^(.)\1{39,}$"))
| where part_count>=20 OR has_upload_progress=1 OR mvcount(repeated_char)>=1
| stats count max(part_count) as max_parts max(max_fname_len) as longest_filename
        values(has_upload_progress) as upload_progress by src dest uri_path
| sort - max_parts
```

#### 3.9 Known scanner UAs, LFI session-read chain, upload-progress field — HIGH

**Why it works.** Three concrete request-level IOCs: scanner user agents seen in the wild (`php2shell-scan/109618`, `php2shell-poc`); the `php://filter` / `sess_<id>` reads that follow an upload-progress web-shell plant (the LFI chain); and the upload-progress field itself.

```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    values(Web.url) as url values(Web.status) as status
    from datamodel=Web.Web
    where (Web.http_user_agent="*php2shell*"
        OR Web.url="*php://filter*" OR Web.url="*php%3A%2F%2Ffilter*" OR Web.url="*php%3a%2f%2ffilter*"
        OR Web.url="*sess_*"
        OR Web.url="*PHP_SESSION_UPLOAD_PROGRESS*")
    by Web.src Web.dest Web.http_method Web.http_user_agent
| `drop_dm_object_name("Web")`
| convert ctime(firstTime) ctime(lastTime)
```

Scanner UAs change fast — treat as a hunting seed, not a durable rule.

#### 3.10 Amazon MadPot IOC IPs — MEDIUM (investigate, don't auto-block)

**Why it works.** Amazon published six IPs tied to pre- and post-disclosure activity. They're shared anonymization infra, so a hit is a reason to investigate that source's full activity, not to block outright.

```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    values(Web.url) as urls values(Web.http_method) as methods values(Web.status) as statuses
    from datamodel=Web.Web where `php2shell_ioc_ips` by Web.src Web.dest
| `drop_dm_object_name("Web")`
| convert ctime(firstTime) ctime(lastTime)
```

#### 3.11 PHPSESSID memory-disclosure cookie — HIGH

**Why it works.** The disclosure primitive URL-encodes stale heap bytes into the response `PHPSESSID` cookie. The default SID is exactly 32 lowercase hex chars (`sid_length=32`, `sid_bits_per_character=4`). A Set-Cookie that's oversized, URL-encoded, or otherwise off-format is the leak. Response side needs proxy/WAF Set-Cookie logging.

```spl
index=proxy OR index=waf "PHPSESSID="
| rex max_match=5 "(?i)set-cookie[\"':\s=]+PHPSESSID=(?<resp_sid>[^;\s\",]+)"
| mvexpand resp_sid
| eval sid_len=len(resp_sid)
| where NOT match(resp_sid, "^[0-9a-f]{32}$")
| eval reason=case(sid_len>64, "oversized", match(resp_sid, "%[0-9A-Fa-f]{2}"), "url_encoded_bytes", true(), "bad_format")
| stats count values(reason) as reasons max(sid_len) as max_len values(resp_sid) as sample_sids by host src_ip dest
```

Adjust the regex if you changed `session.name` or the SID length/bits settings.

#### 3.12 WAF / IDS hits, including Cloudflare's published rule IDs — HIGH

**Why it works.** Cloudflare named its php2shell rule IDs (below). If you ingest Cloudflare firewall events, match them directly instead of guessing. Also covers ModSecurity/Suricata community rule IDs.

```spl
(index=waf sourcetype="cloudflare:*"
    (ruleId IN (
        "4e315666e8e344cdb64119a3b5ccf32f","00c10e6cc4da4bd08722adeebcd95984","48ddf592361e4fdb97a8a85982dab691",
        "3556683d512a47f2937899c524b1a4c6","da07c85852e34625bb478496302ede46","19373a83abb840e18ab3ce5a7975ce1b",
        "07f0b6ddaabf40b1b2042dade8d613fa",
        "c1d409ad838f47f59446f21cc438d5dd","f9a45927414245e3a64bb12d0a0c2f64","771c654ae1154d4daa72f4e1545d163c",
        "217005865f0145f392300bac212afcc9","38efdb17ea594501bb55a1d71867b12e","4148ae686fdb4d01be673fab9d9c073d",
        "1389aa259617437392ce149c48143645","afffe22785674c80a31875c848d2242a")
     OR cve IN ("CVE-2026-109618","CVE-2026-109619")))
OR (index=waf sourcetype="modsec*" ("2026106181" OR "2026106183" OR "2026106184" OR "2026106185" OR "2026106186"))
| eval src=coalesce(ClientIP, src_ip, src, client_ip)
| stats count values(Action) as action values(ruleId) as rule_ids values(ClientRequestPath) as paths by src host
```

The Cloudflare "Anomalous Execution 1–7" names are generic and their descriptions were still being updated at publish time; rely on the IDs.

```spl
| tstats `summariesonly` count min(_time) as firstTime values(IDS_Attacks.signature) as signature
    from datamodel=Intrusion_Detection.IDS_Attacks
    where (IDS_Attacks.signature="*CVE-2026-10961*" OR IDS_Attacks.signature="*php2shell*"
        OR IDS_Attacks.signature="*PHP_SESSION_UPLOAD_PROGRESS*"
        OR IDS_Attacks.signature_id IN ("2026106181","2026106184"))
    by IDS_Attacks.src IDS_Attacks.dest
| `drop_dm_object_name("IDS_Attacks")`
```

---

### Tier 2 — Success detection (process + host layer)

This is where you confirm a compromise. It's root-cause-agnostic: a web server doing something a request-serving daemon never does. Several of these mirror Elastic's and Falco's published rules.

#### 3.13 PHP worker spawns a shell, interpreter, or downloader — CRITICAL

**Why it works.** `php-fpm`/`php-cgi`/`lsphp` (and mod_php under `httpd`/`apache2`) never `exec` a shell or downloader in normal operation. This is the tightest "RCE just succeeded" signal.

```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.parent_process) as parent_process
    from datamodel=Endpoint.Processes
    where `php_worker_parents`
      AND (Processes.process_name IN ("sh","bash","dash","zsh","ksh","ash","busybox","curl","wget","perl","ruby","node","nc","ncat","netcat","socat","base64","openssl","xxd","telnet","whoami","id","uname","hostname")
           OR Processes.process_name="python*")
    by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| `drop_dm_object_name("Processes")`
| search NOT process="*sendmail*" NOT process="*/usr/sbin/postdrop*"
| eval fileless=if(match(mvjoin(process_path," "), "memfd:|\(deleted\)"), "yes", "no")
| convert ctime(firstTime) ctime(lastTime)
```

PHP `mail()` legitimately runs `/bin/sh -c sendmail` (excluded). Baseline ImageMagick, wkhtmltopdf, git, and any `exec()` your apps make.

#### 3.14 PHP worker runs a discovery/credential/reverse-shell command line — CRITICAL

**Why it works.** Mirrors Elastic's "Payload Execution by Web Server." After RCE, attackers run a predictable first set of commands. Keys on a web-server parent launching a shell with a high-risk command line.

```spl
| tstats `summariesonly` count min(_time) as firstTime
    values(Processes.process) as process values(Processes.user) as user
    from datamodel=Endpoint.Processes
    where `php_worker_parents` AND Processes.process_name IN ("sh","bash","dash","zsh","ksh")
    by Processes.dest Processes.parent_process_name Processes.process
| `drop_dm_object_name("Processes")`
| where match(process, "(?i)(/dev/tcp/|base64\s+-d|curl\s|wget\s|/etc/shadow|/etc/passwd|\.aws/credentials|169\.254\.169\.254|mkfifo|socat|sudo\s+-l|-perm\s+-u=s|getcap|pty\.spawn|fsockopen)")
| eval technique=case(match(process,"/dev/tcp/|mkfifo|socat|pty\.spawn|fsockopen"),"reverse_shell",
                      match(process,"\.aws/credentials|169\.254\.169\.254|/etc/shadow"),"cred_access",
                      match(process,"curl|wget|base64 -d"),"ingress_tool",
                      match(process,"sudo -l|-perm -u=s|getcap"),"privesc_enum", true(),"discovery")
| stats count values(technique) as techniques values(process) as commands min(_time) as firstTime by dest parent_process_name user
| convert ctime(firstTime)
```

#### 3.15 Fileless execution: memfd + execveat via auditd — CRITICAL

**Why it works.** A known completion path creates an anonymous `memfd` and runs it with `execveat(…, AT_EMPTY_PATH)` — nothing touches disk. A PHP worker calling `memfd_create`, or a child running from `/memfd:… (deleted)`, is near-zero-FP. Needs auditd rules keyed on the pool UID (33=www-data Debian/Ubuntu, 48=apache RHEL):

```
-a always,exit -F arch=b64 -S execve,execveat -F euid=33 -k php-child
-a always,exit -F arch=b64 -S memfd_create -F euid=33 -k php-memfd
```

```spl
index=os sourcetype=linux:audit type=SYSCALL (key="php-memfd" OR key="\"php-memfd\"" OR key="php-child" OR key="\"php-child\"")
| eval key=trim(key, "\""), comm=trim(comm, "\""), exe=trim(exe, "\"")
| search key="php-memfd" OR (key="php-child" NOT exe IN ("/usr/sbin/sendmail","/usr/sbin/postdrop","/usr/lib/sendmail"))
| eval severity=if(key="php-memfd" OR like(exe, "/memfd:%"), "critical", "high")
| stats count min(_time) as firstTime values(exe) as exe values(comm) as comm values(ppid) as ppid by host key euid severity
| convert ctime(firstTime)
```

#### 3.16 Outbound connections from a PHP worker — HIGH

**Why it works.** A worker opening new outbound TCP to a non-database, non-API endpoint after a fire is C2 or a stager. Tuned for odd ports; run a separate `first_seen` hunt for new 443 destinations.

```spl
index=os sourcetype="sysmon:linux" EventCode=3
    (Image="*php-fpm*" OR Image="*/php-cgi*" OR Image="*lsphp*" OR Image="*frankenphp*" OR Image="*/php")
| where NOT (cidrmatch("10.0.0.0/8", DestinationIp) OR cidrmatch("172.16.0.0/12", DestinationIp) OR cidrmatch("192.168.0.0/16", DestinationIp) OR cidrmatch("127.0.0.0/8", DestinationIp))
| where NOT DestinationPort IN ("443","80","3306","5432","6379","11211","25","587")
| stats count dc(DestinationIp) as dest_count values(DestinationIp) as dest_ips values(DestinationPort) as ports by host Image User
```

#### 3.17 Cloud metadata / credential-file access by the web user — CRITICAL

**Why it works.** Explicit credential-access coverage: a web-user process reaching the instance metadata endpoint (`169.254.169.254`) or reading `.env` / `~/.aws/credentials` / k8s service-account tokens is a strong post-ex signal and maps to T1552.

```spl
(index=os sourcetype="sysmon:linux" EventCode=3 DestinationIp="169.254.169.254"
    (Image="*php*" OR Image="*apache*" OR Image="*httpd*" OR Image="*nginx*"))
OR (`php_worker_parents`
    | `drop_dm_object_name("Processes")` )
| eval sig=if(DestinationIp="169.254.169.254","imds_access", "other")
| search sig="imds_access"
| stats count values(Image) as image by host User
```

For file reads, pair with file-event telemetry:

```spl
| tstats `summariesonly` count values(Filesystem.file_path) as file_path
    from datamodel=Endpoint.Filesystem
    where Filesystem.action="read"
      AND Filesystem.user IN ("www-data","apache","nginx","nobody","httpd")
      AND (Filesystem.file_name=".env" OR Filesystem.file_path="*/.aws/credentials"
           OR Filesystem.file_path="*/secrets/kubernetes.io/*" OR Filesystem.file_name="shadow")
    by Filesystem.dest Filesystem.user Filesystem.file_name
| `drop_dm_object_name("Filesystem")`
```

#### 3.18 Web-shell drop and persistence by the web user — HIGH

**Why it works.** Before or after running commands, attackers write a web shell (`.php`/`.phtml`, sometimes a `avatar.php.jpg` double-extension) into the web root, or establish persistence via cron/systemd/authorized_keys. A web-user process creating executable/script content there is abnormal outside a deployment.

```spl
| tstats `summariesonly` count min(_time) as firstTime values(Filesystem.file_path) as file_path
    from datamodel=Endpoint.Filesystem
    where (Filesystem.action="created" OR Filesystem.action="modified")
      AND Filesystem.user IN ("www-data","apache","nginx","nobody","httpd")
      AND (Filesystem.file_name="*.php" OR Filesystem.file_name="*.phtml" OR Filesystem.file_name="*.phar"
           OR Filesystem.file_name="*.php.*" OR Filesystem.file_name=".htaccess"
           OR Filesystem.file_path="*/.ssh/authorized_keys" OR Filesystem.file_path="*/cron.d/*"
           OR Filesystem.file_path="*/systemd/system/*" OR Filesystem.file_name="sess_*")
    by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name("Filesystem")`
| eval technique=case(match(file_path,"authorized_keys"),"T1098.004_ssh_key",
                      match(file_path,"cron|systemd"),"T1053_scheduled_task",
                      match(file_name,"sess_"),"session_file",
                      true(),"T1505.003_web_shell")
| convert ctime(firstTime)
```

#### 3.19 Session poisoning: one SID, repeated decode failures + crash — LIKELY SUCCESS

**Why it works.** A successful fire poisons the in-memory session tree, which gets re-serialized into the session file. Every later request that re-decodes that file throws `Failed to decode session object` and can SEGV — for the *same* PHPSESSID. One SID with ≥3 decode failures plus a crash in 24h is likely a live poisoned session. (Needs SID in the access log to pin the SID; this host-level version keys on the co-occurrence.)

```spl
(`php_error_logs` "Failed to decode session object") OR (`php_fpm_logs` "exited on signal 11") OR (`linux_kernel_logs` "segfault at" php)
| eval evt=if(searchmatch("Failed to decode session object"), "decode_fail", "crash")
| bin _time span=24h
| stats count(eval(evt="decode_fail")) as decode_fails count(eval(evt="crash")) as crashes by _time host
| where decode_fails>=3 AND crashes>=1
```

---

### Tier 3 — Rollup, scoping, and inventory

#### 3.20 Risk-based rollup (Splunk ES) — correlation

**Why it works.** Have the searches above emit RBA risk on `src`/`dest`. A host accumulating both attempt-layer and success-layer risk, or crossing a score threshold, is your true-positive candidate.

```spl
| tstats `summariesonly` sum(All_Risk.calculated_risk_score) as risk_score dc(source) as source_count values(source) as sources
    from datamodel=Risk.All_Risk
    where All_Risk.annotations.mitre_attack.mitre_technique_id IN ("T1190","T1059.004","T1620","T1505.003","T1552.005")
      AND source="*PHP2Shell*"
    by All_Risk.risk_object All_Risk.risk_object_type
| `drop_dm_object_name("All_Risk")`
| where source_count>=2 OR risk_score>=100
```

#### 3.21 Exposure scoping — vulnerable PHP inventory

**Why it works.** You can't defend what you can't see. Use the vuln data model (Tenable plugin 369483), or fall back to osquery package tables / process telemetry.

```spl
| tstats `summariesonly` count values(Vulnerabilities.severity) as severity
    from datamodel=Vulnerabilities.Vulnerabilities
    where Vulnerabilities.cve IN ("CVE-2026-109618","CVE-2026-109619")
    by Vulnerabilities.dest
| `drop_dm_object_name("Vulnerabilities")`
```

Osquery/process fallback — flag anything below 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, plus every 5.x–8.1 install. Watch bundled runtimes (cPanel `ea-php`, Plesk, Remi, LiteSpeed `lsphp`, FrankenPHP, Snap, Nix) and containers:

```spl
index=os sourcetype="osquery*" (name="php*" OR name="lsphp*" OR name="ea-php*" OR name="plesk-php*" OR name="libapache2-mod-php*" OR name="sw-engine")
| rex field=version "(?<maj>\d+)\.(?<min>\d+)\.(?<pat>\d+)"
| eval vuln=case(maj<8 OR (maj=8 AND min<2), "EOL_vulnerable",
                 maj=8 AND min=2 AND pat<35, "vulnerable",
                 maj=8 AND min=3 AND pat<36, "vulnerable",
                 maj=8 AND min=4 AND pat<27, "vulnerable",
                 maj=8 AND min=5 AND pat<12, "vulnerable", true(), "patched")
| where vuln!="patched"
| stats values(version) as versions values(vuln) as status by host name
```

---

## Part 4 — Logging gaps to fix today

1. **Confirm the PHP error log is actually written.** Run `php-fpm -i | grep -E 'log_errors|^error_log|fastcgi.logging'` and grep `catch_workers_output` in each pool. Official Docker `php:*-fpm` images ship with no php.ini, so `log_errors=Off` and 3.1–3.4 see nothing. There, the FPM `exited with code 70` line and the nginx upstream errors are your only body-free arm/fire signals.
2. **Add request size and session ID to access logs.**
   - nginx: `log_format php_sid '$remote_addr [$time_local] "$request" $status $request_length sid=$cookie_PHPSESSID';`
   - Apache: `LogFormat "%a %t \"%r\" %>s %I sid=%{PHPSESSID}C" php_sid` (needs mod_logio)
3. **Log response Set-Cookie** at the proxy/WAF so 3.11 can see the disclosure cookie.
4. **Deploy the auditd rules** in 3.15 on PHP hosts so fileless execution is visible.
5. **Rotate secrets** on any internet-facing PHP host that was unpatched and showed arm activity — the disclosure primitive can leak passwords, tokens, API keys, and TLS keys without RCE.
6. **Start investigations from October 17**, not disclosure day — that's Amazon's earliest observed probe.
