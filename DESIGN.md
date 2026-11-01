# Optio — Design

Optio is a human-driven terminal cockpit for the Praetor pentest engine.
Praetor runs the same flow under Claude. Optio runs it under a human. The
operator makes every decision. Optio remembers the tools, the flags, and what
already ran against each target, and it keeps the screen quiet.

Status: design. No product code yet. This document is the agreed description a
builder plans from.

---

## 1. Intent and why

A working pentester drives dozens of tools in one engagement. Each tool has its
own flags, its own output shape, and its own idea of a "target". The operator
carries three loads in their head at once:

1. **Which flags** a tool needs for this case (the `sqlmap` risk/level, the
   `ffuf` match codes, the `nmap` script set).
2. **What already ran** against this target, and what the result was.
3. **What is still open** — the untested classes, the next step in the flow.

Human memory is the weak link. The operator forgets a flag, re-runs a scan
already done, or misses a class because no screen showed the gap. Notes drift
into scattered text files and spreadsheets (a real practitioner setup:
"Obsidian for notes, spreadsheets for coverage, random text files for commands I
reuse").

Praetor already solved loads 2 and 3 for the Claude-driven flow: per-target
state (`findings.json`, `coverage.json`, `endpoints.json`), a tool-run ledger,
a WSTG/OWASP checklist, and `tool_coverage_gaps`. The decision-making is
Claude's. Optio keeps the engine and the state, drops the model, and gives the
three loads to a human through a TUI built for low noise.

### Why now

Praetor's engine is mature — 600+ tool wrappers, a stable per-target state model,
and a coverage ledger. The only part that is Claude-specific is the host that
decides which tool to call next. That host can be a human.

### What success looks like

- The operator opens Optio, sees one target, sees the coverage gaps, picks a
  tool, confirms a pre-filled command, and reads a three-line result — without
  leaving the terminal and without remembering a flag.
- A target handed between Optio and Claude keeps the same state. The human and
  the model read and write the same files.
- The screen never shows a raw scanner firehose unless the operator asks for it.

---

## 2. Goals, non-goals, anti-goals

### Goals

- Drive the full Praetor tool catalog from a TUI, human-decided.
- Recall per-target, per-tool arguments ("flags") and pre-fill them.
- Show a live coverage board: which lanes and tools ran, which are open.
- Parse each tool result to a short summary; keep the full output one keystroke
  away.
- Share state with Praetor — read and write the same `.burp-intel/<domain>/`
  files, through the same tools.
- Show the flow (recon → surface → probe → verify → report) as a rail that
  surfaces the next open step. The human chooses; Optio never auto-runs.

### Non-goals

- No generative LLM in the loop. Optio does not decide, generate, or auto-act.
  It surfaces state and runs what the operator picks. It MAY show a ranking hint
  from Haruspex (a small, local, calibrated scorer that abstains when unsure —
  see §10); that is an optional ordering aid, not a decider.
- No new tool wrappers. Optio calls Praetor's existing tools; it does not
  re-implement `sqlmap`/`nmap`/`ffuf` runners.
- No second state model. Optio reads and writes Praetor's state, plus one small
  local store for its own flag memory and UI preferences.
- No report engine of its own. Reports come from Praetor's `generate_report`.

### Anti-goals (these make it a failure even if it runs)

- Becoming a second automation framework that fires tools on its own. The human
  decides every send. An Optio that auto-chains is a worse Praetor.
- Dumping raw tool output to the screen. Noise is the problem Optio exists to
  kill; re-introducing it is failure.
- Forking Praetor's engine. Optio must stay a thin host, or it rots the moment
  Praetor adds a tool.

---

## 3. Prior art

Two tool families circle this problem. Neither joins the two halves.

### Flag-recall cockpits

- [arsenal](https://github.com/Orange-Cyberdefense/arsenal) — search a command,
  fill the `<args>` once, it pre-fills the finished command at your prompt. It
  injects the command by emulating keystrokes through the TTY (the `TIOCSTI`
  ioctl), so it works in any shell and lands in history. It has a tmux mode
  (`-t`) and global variables (`set ip=10.10.10.10`).
- [navi](https://github.com/denisidoro/navi/wiki) — the older interactive
  cheatsheet, `fzf`/`skim` under the hood.
- [nock](https://github.com/jessn-dev/nock/wiki) — a Go successor; shows the
  command before it runs and hands it to the shell or an AI agent over MCP.
  Early-stage.

These solve "remember the flags". They know nothing about the target or what
already ran.

Note on `TIOCSTI`: modern kernels disable it by default
(`dev.tty.legacy_tiocsti=0`) for security. Arsenal's keystroke-injection trick
breaks on those systems. **Optio does not need it** — Optio owns execution. It
spawns the tool itself (through Praetor), so it never injects into another
shell. This removes arsenal's central fragility.

### TUI pentest consoles

- [Pentool](https://github.com/DrXOps/pentool) — Textual-based; HTTP proxy, a
  scanner, a scope manager, and a site map built from proxy traffic. The scope
  and site-map features are the closest match to target tracking.
- [overpowered-pentest-suite](https://github.com/sudo-DC404/overpowered-pentest-suite)
  — Python TUI; scan progress bars, finding-detail modals, filtering.

These track a target but ship their own small tool set and no coverage model.

### Note/coverage practice

- [piratemoo/pentestchecklist](https://github.com/piratemoo/pentestchecklist)
  and [DasPhero reference guide](https://github.com/DasPhero/Pentesting-Reference-Guide)
  — living checklists and Obsidian vaults. Tick-as-you-go, by hand.

### Where Optio sits

Optio is the first of these that is **both** a flag-recall cockpit **and**
target/coverage-aware, on a 600+ tool engine, sharing state with an LLM-driven
sibling. It takes arsenal's "recall and confirm the exact command" and Pentool's
"one target, tracked" and binds them to Praetor's coverage ledger and state.

---

## 4. Architecture — Optio is a human-driven MCP host

Claude drives Praetor as an MCP host: it connects to the Praetor MCP server over
stdio, discovers tools, and calls them. **Optio is the same host with a human in
the loop instead of a model.** This is the central design decision.

```
   Claude Code  ─┐
                 ├─(MCP stdio)─>  praetor-mcp  ─>  Burp / CLIs / state files
   Optio (TUI)  ─┘                    │
     ▲  human decides                 └─ .burp-intel/<domain>/  (shared state)
     │
   operator  ·····(optional ranking hint)·····>  haruspex  /v1/evaluate
                                                  (local, keyless, abstains)
```

The dotted line is advisory only. Haruspex orders the open candidates for the
operator; the operator still makes every call. Optio runs fully without it.

Consequences of this choice:

- **Zero coupling to Praetor internals.** Optio speaks MCP, the same contract
  Claude uses. When Praetor adds a tool, Optio sees it through `list_tier1_tools`
  / `pick_tool` / `get_profile` with no code change.
- **The full catalog, free.** All 600+ tools are reachable. Optio does not wrap
  any of them.
- **State is shared by construction.** Optio reads coverage and findings through
  the same tools that write them (`load_target_intel`, `coverage_summary`,
  `tool_coverage_gaps`, `get_findings`, `checklist_gaps`). A target handed
  between human and model stays consistent.
- **`praetor_bootstrap()` already exists for non-Claude hosts.** It returns the
  operating context (rules, skills, knowledge, flows, tool profile). Optio calls
  it on connect to self-configure — this path was built for exactly this case.

### Why not the alternatives

- **Import Praetor as a Python library and call functions directly.** Tighter
  coupling to private internals, breaks on refactors, and re-implements the MCP
  host loop Praetor already supports. Rejected.
- **Shell out to raw CLIs with Optio's own flag store (pure arsenal model).**
  Loses Burp routing, loses the shared state and coverage, duplicates the tool
  layer. Rejected — it would be a worse arsenal, not a better Praetor front-end.

### Generic-host stretch

Because Optio is a plain MCP host, it can connect to any MCP server, not only
Praetor. That is a stretch goal, not a v1 requirement. v1 targets Praetor and
reads its tool shapes.

---

## 5. The screens

Four screens, one target in focus at a time. Layouts are described here; the
visual mockups follow this document and are where the UX is judged.

### 5.1 Target board (home)

The quiet dashboard. For the focused target:

- Header: domain, tech stack, auth model, scope mode (from `load_target_intel`
  profile + `get_scope`).
- **Coverage rail**: the flow phases (recon → surface → probe → verify → report)
  with a done/open mark per phase, driven by `coverage_summary` and
  `tool_coverage_gaps`. This is the "what is still open" load, on screen.
- **Lane/tool grid**: per lane (recon, web-scan, network, cloud, secrets-sast),
  which tools ran (green) vs. open (dim), straight from `tool_coverage_gaps`.
- Findings count by severity (from `get_findings(summary_only=True)`).
- A target switcher (the list of domains with on-disk state).

### 5.2 Tool launcher (the flag-recall half)

Open from the board or a hotkey.

- Search/filter the catalog (`list_tier1_tools`, `pick_tool(task)`), or jump to a
  tool the coverage grid flagged open.
- The tool's argument schema, with **the operator's last-used args for this
  target pre-filled** (Optio's local flag memory), and the target's own values
  (domain, endpoints) injected like arsenal's global variables.
- The exact call shown before anything runs. Nothing executes until the operator
  confirms (arsenal's "show the command first" rule).
- Favorites (`Ctrl+F`) and a per-target history (`Ctrl+R`), mirroring arsenal's
  keymap so the muscle memory carries over.

### 5.3 Activity log (the noise filter)

- Each run shows a **three-line summary**: tool, target, and the parsed result
  (ok/error, the key delta or counts). Example: `sqlmap · shop.example.com ·
  200→500, len +1842, "pg_query" — candidate`.
- A per-tool summarizer maps the tool's JSON result to those lines. v1 ships a
  generic summarizer (status, error, obvious counts); tool-specific summarizers
  are added over time.
- Full raw result on one keystroke (drill-down modal). The firehose is available,
  never forced.

### 5.4 Findings board

- `get_findings` list, severity-sorted, with a detail modal.
- The operator moves a finding through its lifecycle by hand; Optio writes the
  change through Praetor's tools (`save_finding`, `record_retest`). Optio does
  not assess or auto-verdict.

---

## 6. State and flag memory

Two stores, clearly split:

- **Praetor state (shared, source of truth).** `.burp-intel/<domain>/` —
  findings, coverage, endpoints, profile, the tool-run ledger. Optio reads and
  writes this only through Praetor tools, never by editing files directly. This
  keeps the human and the model consistent.
- **Optio-local store (this tool's own).** A small store (e.g. `~/.optio/` or a
  per-project `.optio/`) holding what Praetor does not track: last-used args per
  `(target, tool)`, favorites, command history, and UI preferences. This is the
  arsenal half — the flag memory.

The split matters: engagement truth stays in Praetor so nothing is lost on a
hand-off; the operator's personal recall stays local and never pollutes the
shared state.

---

## 7. Noise reduction — the core UX rule

The problem statement is "track target without many output noise". The rule:

- **Every tool result is summarized before it reaches the screen.** The summary
  is a delta against the target's baseline where one exists (status/length/hash
  change, error strings, counts), not an absolute dump.
- **The full output is always one keystroke away**, never on screen by default.
- **The board shows state, not activity.** No scrolling logs on the home screen
  — gaps and findings, which are decisions the operator must make, not a record
  of what the machine did.

---

## 8. Tech stack (builder's call unless noted)

- **Python 3.11+**, to match Praetor and to speak MCP with the same client
  libraries. (Decided: the engine and the MCP contract are Python-first.)
- **[Textual](https://textual.textualize.io/)** for the TUI — the same framework
  Pentool and OPS use, with a `DataTable`, a worker API for background calls, and
  a message system for thread-safe UI updates. (Decided: it is the mature Python
  TUI and keeps one language across the project.)
- **MCP client** over stdio to `praetor-mcp`. Long-running tool calls run in
  Textual workers so the UI stays responsive; results post back as messages.
- Its own repo (`TyrusRC/optio`, Apache-2.0), depending on a running Praetor MCP
  server at runtime, not vendoring it.

Open implementation points left to the builder and the plan: the exact MCP
client library, the local-store format (JSON vs SQLite), and the summarizer
plug-in shape.

---

## 9. Scope and phases

A project. After this design is approved, the next step is a written plan, not
code.

- **Phase 1 — connect and read.** MCP host loop + `praetor_bootstrap`. Target
  board rendering real `coverage_summary` / `tool_coverage_gaps` / `get_findings`
  for an on-disk target. Read-only. Proves the shared-state and low-noise claims
  before any tool runs.
- **Phase 2 — launch and recall.** Tool launcher with the arg schema, flag
  memory, confirm-before-run, and the three-line activity summary with
  drill-down.
- **Phase 3 — findings and flow.** Findings board with lifecycle writes through
  Praetor; the coverage rail nudging the next open step.
- **Later / stretch.** Tool-specific summarizers; generic multi-MCP-server host;
  tmux-style multi-pane for watching a long scan live.

---

## 10. Optional decision aid — Haruspex

[Haruspex](https://github.com/TyrusRC/haruspex) is a small, local, calibrated
decision layer. It reads a situation and a bounded set of options and returns a
typed verdict — boolean (`P(yes)`), choice (one option), or score (a rubric
level) — with the full probability distribution. It is built on a
non-autoregressive decision encoder, not a generative model, so it ranks and
scores; it never writes text or takes an action. Most important for Optio: it is
**selectively calibrated and abstains** when its confidence does not clear a
certified threshold.

That abstain property is why Haruspex fits a human-decides tool. It is a hint
that appears only when it is trustworthy and stays silent otherwise. It never
replaces the operator's judgment.

### How Optio uses it

- **Rank the open candidates (choice).** The coverage board shows open
  lanes/classes/tools. Optio can ask Haruspex to order them by predicted value
  for this target, so the highest-value gap sits at the top. The operator still
  picks.
- **Triage findings (boolean, `P(real)`).** Haruspex already scores security
  findings real-vs-noise. The findings board can show a dim `P(real)` column as a
  sort hint. Optio does not change a finding's status from it.
- **Severity sanity (score).** A rubric-level hint beside a finding's
  operator-set severity. A hint, never an auto-set.

### Contract and rules

- **Transport.** `POST /v1/evaluate` over local HTTP, keyless by default. Request
  carries `{question, candidates: {key: label}, target}` and an optional
  `domain` to route to the right adapter.
- **Optional and fail-open.** Haruspex is not required. If it is not running, is
  slow, or errors, Optio drops the hint and works unchanged. A fast-connect check
  with a short timeout and a circuit breaker means a dead Haruspex never stalls
  the TUI — the same rule Praetor already applies to it.
- **Abstention is shown as "no call", not guessed.** When Haruspex abstains or
  returns no accepted answer, Optio shows nothing in the hint slot. It never
  invents a ranking to fill the gap.
- **Advisory only — read §2 anti-goals.** Haruspex ordering never moves a
  finding, never runs a tool, never fills a flag. It changes the ORDER the
  operator sees, nothing else.

### Why this keeps Optio human-driven

A generative LLM in the loop would make Optio a second Praetor. Haruspex does
not generate and does not act — it scores a bounded option set and abstains when
unsure. The operator reads the hint, agrees or ignores it, and makes the call.
The decision seat stays human.

## 11. Open questions for the operator

1. **Run model.** Should Optio launch and manage the Praetor MCP server itself
   (spawn it on start), or attach to one the operator already runs? Attaching
   matches the Burp-already-up workflow; launching is one less step.
2. **Local store scope.** Flag memory per project directory (`.optio/` beside the
   engagement) or one global store (`~/.optio/`) keyed by target? Per-project
   travels with the engagement; global recalls across engagements.
3. **First target.** Which on-disk target should Phase 1 render first for the
   proof — the `pentest-ground.com` engagement (9 findings, richest state) is the
   strongest demo of the board.
