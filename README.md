# Optio

**A local web cockpit for pentesters. Map the attack surface, run your tools,
remember the flags, track every target — without the noise.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Optio runs your security tools, recalls the flags you used last time, tracks what
already ran against each target, and parses every result down to a few lines. You
make every decision. It has no LLM, and it depends on nothing but the tools you
already have installed.

## Why

Mid-engagement you carry three things in your head at once:

1. **The flags** each tool needs for this case.
2. **What already ran** against this target, and the result.
3. **What is still open** — the untested tools and classes.

Cheatsheet tools remember the flags. A couple of TUI consoles track one target.
None carries all three for *your own* toolset. Optio does.

## Features

- **You decide; Optio remembers.** No model, no automation firing on its own — it
  surfaces state and runs what you pick.
- **Attack-surface graph.** A Wiz-style map of the target (domain → subdomain →
  host → service → endpoint) with a "what to find" board of every applicable
  vuln class and its test status — including classes no scanner covers
  (subdomain takeover, TLS/SSL, DNS, headers), so nothing is missed by default.
- **Coverage by class, not by tool.** "Done" means every applicable class was
  tested, not "every tool ran." A class with no catalog tool still appears,
  with a manual instruction.
- **Auto-run.** One action walks recon → surface → scan in value order and
  stops before probing — the broad early work done for you, decisions left to you.
- **Your target, your headers.** Per-target custom headers / User-Agent applied
  to every request the built-in runner sends.
- **One target, tracked.** A quiet board shows coverage gaps, which tools ran vs.
  open, and your findings — not a scrolling log.
- **Flag memory.** Pick a tool, it recalls your last arguments for this target and
  pre-fills them. The exact command shows before anything runs.
- **Low noise.** Every result is summarized to a few lines; the full output is one
  keystroke away.
- **Your own arsenal.** An editable catalog of ~70 tools across recon, web scan,
  network, AD, cloud, code/secrets, and cracking. Add your own; Optio drives them.
- **Built-in request runner.** Edit and send a raw HTTP request (a repeater)
  without leaving the cockpit. Optio snapshots the request and response into its
  store as durable evidence — a finding cites a saved capture, not a volatile
  proxy index that disappears when the proxy restarts.
- **Findings become a report.** A finding carries impact, remediation, CWE, CVSS,
  reproduction, and a linked evidence capture. You promote it from *suspected* to
  *confirmed*; only confirmed findings reach the client report (no activity counts).
- **Pipelines.** Run a named chain of tools in one click (`recon-sweep`,
  `web-scan`, `full-web`, `network`, …) to cut the manual per-tool loop.
- **Long scans never block you.** Tools, pipelines, and auto-run run in the
  background: the command fires, the status shows elapsed time, and a **Cancel**
  button stops it — killing the whole process tree (a DAST and the helpers it
  spawns), not just the parent.
- **Burp Suite, both directions.** Route Optio's tools and request runner through
  Burp (a per-target proxy, one click in Config), and/or sync Burp → Optio: a
  bundled extension — or any `POST /ingest` — forwards in-scope traffic, which
  Optio records as evidence and grows the attack-surface graph from. See
  [`integrations/burp/`](integrations/burp/).
- **Standalone.** Nothing to install but your own tools. Route traffic through a
  proxy you already run (e.g. Burp) if you want — none is required.
- **Optional hint.** If a local [Haruspex](https://github.com/TyrusRC/haruspex)
  is running (`:3000`), it re-ranks the next actions by predicted value
  automatically — and stays silent when it isn't sure. You still make every call.
  Stand one up with `scripts/setup-haruspex.sh` (clones, installs, runs — no
  other tool required), then point Optio at it with `OPTIO_HARUSPEX_URL`.

## How it works

Optio is a local web app over a local store. A **catalog** defines your tools
(binary, flag template, output summarizer); a **launcher** recalls your flags
and shows the command before it runs; an **executor** spawns the tool and
captures its output; a **summarizer** turns that output into a few lines. Your
targets, the attack-surface graph, the by-class coverage, your flag memory, and
your findings live in a local store keyed by target, so your habits follow you
across engagements. The browser is the surface; the same process also serves a
JSON API (below) for scripts.

## Run from source

Optio uses [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/TyrusRC/optio
cd optio
uv run optio           # serves the web UI on http://127.0.0.1:8788 and opens your browser
```

Flags: `--host`, `--port`, `--no-browser`. `uv run` creates the environment and
installs on first use. Run the tests with `uv run pytest`.

The UI renders the target as a **Wiz-style attack-surface graph** — domain →
subdomains → hosts → services → endpoints, with nodes lit by the worst finding
on them — next to a **"what to find" board**: every applicable vuln class and
whether it is tested. The board tracks classes that have **no scanner** —
subdomain takeover, TLS/SSL config, DNS, security headers — so they are never
silently missed the way a tool-only checklist misses them.

- **Your flow, not a fixed sequence.** Run any tool, any pipeline, any raw
  request, in any order. The advisor only *suggests* a value-ordered next step —
  it never gates you.
- **Auto-run.** One click walks recon → surface → scan for you, in value order,
  and stops before the probe phase so you decide the targeted tests.
- **Config.** Set a proxy (e.g. Burp), TLS verification, custom headers, and a
  User-Agent per target; the request runner and the tools Optio launches inherit
  them (explicit per-request headers still win).
- The graph library (Cytoscape.js) is vendored under
  `src/optio/web/static/vendor/` (MIT) — the UI works offline. The server binds
  to loopback.

State lives in your XDG dirs: config and your catalog in `~/.config/optio/`, the
SQLite store in `~/.local/share/optio/`. Set `OPTIO_HOME` to point all of it
somewhere else.

## Automation API

The same `uv run optio` server exposes a JSON API on the same port (stdlib
`http.server`, no extra dependencies) for scripts and CI:

```sh
curl -s localhost:8788/targets -d '{"name":"ex.com","tech":["php"]}'
curl -s localhost:8788/targets/ex.com/next           # ranked next actions
curl -s localhost:8788/targets/ex.com/auto-run -d '{}'          # smart early flow (blocking)
curl -s localhost:8788/targets/ex.com/run -d '{"tool":"nuclei"}'          # blocking
curl -s localhost:8788/targets/ex.com/run-async -d '{"tool":"nuclei"}'    # -> {job_id}, non-blocking
curl -s localhost:8788/jobs/<id>                     # run status: {status, elapsed_ms, results}
curl -s localhost:8788/jobs/<id>/cancel -d '{}'      # stop a run (kills the process tree)
curl -s localhost:8788/targets/ex.com/surface        # attack-surface graph
curl -s localhost:8788/targets/ex.com/coverage-classes          # what to find
curl -s localhost:8788/targets/ex.com/request -d '{"method":"GET","url":"https://ex.com/"}'
curl -s localhost:8788/ingest -d '{"method":"GET","url":"https://ex.com/login","status":200}'  # Burp/any proxy -> surface
curl -s localhost:8788/targets/ex.com/findings
curl -s localhost:8788/targets/ex.com/report         # {markdown} client report
```

It binds to loopback by default — it runs tools and reads findings, so it stays
local unless you pass `--host` to open it.

## Status

Early but runnable. In place: a web UI with a live attack-surface graph and a
by-class "what to find" board; the next-action advisor (a value-ordered,
findings-first ladder that skips domain-only tools on a bare IP and is re-ranked
automatically by Haruspex when it is up); coverage tracked by vuln class
(tool-less classes included); smart
auto-run; flag memory; a subprocess runner with optional proxy; background runs
that are non-blocking, show progress, and can be cancelled (killing the process
tree); a built-in HTTP request runner with durable request/response capture;
bidirectional Burp integration (route out, sync in via `/ingest`); per-target
proxy/TLS/headers/User-Agent; pipelines; findings that carry impact/CVSS/evidence,
promote suspected → confirmed, and render to a client report; and a catalog of
~70 tools (with `vigil` and `groma` as the default web and network scanners). Add
your own in `~/.config/optio/catalog/`. The catalog format and the UI will still change.

## Contributing

Issues and pull requests are welcome. The catalog is designed to be extended, so
new tool definitions and output summarizers are a good first contribution.

## License

Apache-2.0. See [LICENSE](LICENSE).
