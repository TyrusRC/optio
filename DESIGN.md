# Optio — Design

Optio is a standalone, human-driven terminal cockpit for a pentest operator. It
runs the operator's security tools, remembers the flags, tracks what already ran
against each target, and keeps the screen quiet.

Optio depends on nothing but itself. It is not a front-end for another engine
and it embeds no model. One operator, one terminal, their own tools.

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
3. **What is still open** — the untested tools and classes, the next step in the
   flow.

Human memory is the weak link. The operator forgets a flag, re-runs a scan
already done, or misses a class because no screen showed the gap. Notes drift
into scattered text files and spreadsheets — a real practitioner setup is
"Obsidian for notes, spreadsheets for coverage, random text files for commands I
reuse".

Existing tools pick up one load each (see §3): command cheatsheets remember the
flags; a few TUI consoles track one target. None carries all three in one place
for the operator's *own* toolset. Optio does.

### Why now

The operator's pain is constant and the pieces are proven separately. Binding
flag recall, a per-target coverage ledger, and quiet output into one cockpit is
a small, sharp tool, not a research project.

### What success looks like

- The operator opens Optio, sees one target, sees the coverage gaps, picks a
  tool, confirms a pre-filled command, and reads a three-line result — without
  leaving the terminal and without remembering a flag.
- Nothing runs twice by accident. The board shows what ran and what is open.
- The screen never shows a raw scanner firehose unless the operator asks for it.

---

## 2. Goals, non-goals, anti-goals

### Goals

- Run the operator's security tools from a TUI, every call human-decided.
- Recall per-target, per-tool arguments ("flags") and pre-fill them; show the
  exact command before it runs.
- Keep a live coverage board: which tools and classes ran against this target,
  which are open.
- Parse each tool's output to a short summary; keep the full output one keystroke
  away.
- Hold the engagement state — targets, coverage, findings/notes — in Optio's own
  local store.
- Show the flow (recon → surface → probe → verify → report) as a rail that
  surfaces the next open step. The human chooses; Optio never auto-runs.
- Ship an extensible tool catalog; let the operator add their own tools and flag
  templates.

### Non-goals

- No generative LLM in the loop. Optio does not decide, generate, or auto-act. It
  MAY show an optional ranking hint from Haruspex (a small, local, calibrated
  scorer that abstains when unsure — see §10); that is an ordering aid, not a
  decider.
- No dependency on any external engine or server. Optio is self-contained. It MAY
  route tool traffic through a proxy the operator already runs (e.g. Burp), but it
  requires none.
- No report-writing engine in v1. Optio records findings and notes; polished
  report generation is out of scope for the first version.

### Anti-goals (these make it a failure even if it runs)

- Becoming an automation framework that fires tools on its own. The human decides
  every send. An Optio that auto-chains is just a noisy scanner.
- Dumping raw tool output to the screen. Noise is the problem Optio exists to
  kill; re-introducing it is failure.
- Re-implementing the tools. Optio runs `nmap`/`sqlmap`/`ffuf`; it does not
  rebuild them. It is a cockpit, not a scanner.

---

## 3. Prior art

Two tool families circle this problem. Neither carries all three loads.

### Flag-recall cockpits (load 1)

- [arsenal](https://github.com/Orange-Cyberdefense/arsenal) — search a command,
  fill the `<args>` once, it pre-fills the finished command at your prompt. It
  injects the command by emulating keystrokes through the TTY (the `TIOCSTI`
  ioctl), so it works in any shell and lands in history. It has a tmux mode
  (`-t`) and global variables (`set ip=10.10.10.10`).
- [navi](https://github.com/denisidoro/navi/wiki) — the older interactive
  cheatsheet, `fzf`/`skim` under the hood.
- [nock](https://github.com/jessn-dev/nock/wiki) — a Go successor; shows the
  command before it runs. Early-stage.

These remember the flags. They know nothing about the target or what already ran.

Note on `TIOCSTI`: modern kernels disable it by default
(`dev.tty.legacy_tiocsti=0`) for security, so arsenal's keystroke-injection trick
breaks on those systems. **Optio does not need it** — Optio owns execution. It
spawns the tool itself as a subprocess, so it never injects into another shell.
This removes arsenal's central fragility.

### TUI pentest consoles (load 2)

- [Pentool](https://github.com/DrXOps/pentool) — Textual-based; HTTP proxy, a
  scanner, a scope manager, and a site map built from proxy traffic.
- [overpowered-pentest-suite](https://github.com/sudo-DC404/overpowered-pentest-suite)
  — Python TUI; scan progress bars, finding-detail modals, filtering.

These track a target but ship their own fixed, small tool set. They do not drive
the operator's own arsenal, and they do not model coverage.

### Note/coverage practice (load 3, by hand)

- [piratemoo/pentestchecklist](https://github.com/piratemoo/pentestchecklist)
  and the [DasPhero reference guide](https://github.com/DasPhero/Pentesting-Reference-Guide)
  — living checklists and Obsidian vaults, ticked by hand.

### Where Optio sits

Optio is the first that is **all three at once, standalone, over the operator's
own toolset**: arsenal's "recall and confirm the exact command", Pentool's "one
target, tracked", and a coverage ledger that marks which tool ran where — bound
into one quiet cockpit with no engine behind it.

---

## 4. Architecture — a self-contained cockpit

Optio is one application with four parts and one local store. It owns execution
end to end: it holds the tool definitions, builds the command, runs it, parses
the result, and records what ran.

```
                        ┌──────────────── Optio (one process) ────────────────┐
                        │                                                      │
   operator ──TUI──────>│  Catalog ──> Launcher ──> Executor ──> Summarizer    │
     ▲  decides         │  (tool defs  (recall +    (subprocess  (output ->    │
     │  every call      │   + flags)    confirm)     + opt proxy) 3 lines)      │
     │                  │       \___________________________________/          │
     │                  │                        │                             │
     └── reads board ───│  State store <─────────┘  (targets, coverage ledger, │
                        │  (local, Optio-owned)      flag memory, findings)     │
                        └──────────────────────────────────────────────────────┘
                                 │
                                 ·····(optional ranking hint)·····> haruspex
                                       local HTTP /v1/evaluate (keyless, abstains)
```

The four parts:

- **Catalog** — the tool definitions. Each entry names the binary, an argument
  template with placeholders (target, wordlist, output path), the lane it belongs
  to (recon / web-scan / network / …), and a summarizer. Optio ships a starter
  catalog; the operator adds their own tools and templates. This is the
  arsenal-style content, but structured and target-aware.
- **Launcher** — picks a tool (search, or jump from a coverage gap), fills the
  template with this target's values and the operator's last-used flags, and
  shows the exact command. Nothing runs until the operator confirms.
- **Executor** — spawns the tool as a subprocess, streams its output, and
  optionally routes its HTTP traffic through a proxy the operator configured
  (`HTTP(S)_PROXY`, e.g. Burp). No proxy required.
- **Summarizer** — turns the tool's output into the three-line result (§7) and
  stashes the full output for drill-down.

### The store is Optio's own

There is no external state and no shared engine. Everything Optio tracks —
targets, the coverage ledger, flag memory, findings/notes — lives in Optio's own
local store (§6). This is the standalone decision: Optio starts and works with
nothing else installed but the operator's tools.

### Why not the alternatives

- **Be a front-end for an existing engine.** Couples Optio to another project's
  lifecycle and shape, and makes it useless without that engine installed.
  Rejected — Optio is standalone by requirement.
- **Pure arsenal model (only flag recall, no state).** Drops loads 2 and 3, which
  are the reason Optio exists. Rejected — that tool already exists.

---

## 5. The screens

Four screens, one target in focus at a time. Layouts are described here; the
visual mockups follow this document and are where the UX is judged.

### 5.1 Target board (home)

The quiet dashboard. For the focused target:

- Header: target, tech/notes the operator recorded, and the active proxy (if any).
- **Coverage rail**: the flow phases (recon → surface → probe → verify → report)
  with a done/open mark per phase. This is the "what is still open" load, on
  screen.
- **Lane/tool grid**: per lane, which catalog tools ran (green) vs. open (dim),
  from the coverage ledger. Un-run applicable tools are the gaps.
- Findings count by severity.
- A target switcher (the list of targets in the store).

### 5.2 Tool launcher (the flag-recall half)

- Search/filter the catalog, or jump to a tool the coverage grid flagged open.
- The tool's argument template, with **the operator's last-used flags for this
  target pre-filled**, and the target's own values (host, URL, wordlist) injected
  like arsenal's global variables.
- The exact command shown before anything runs. Nothing executes until the
  operator confirms.
- Favorites (`Ctrl+F`) and a per-target command history (`Ctrl+R`), mirroring
  arsenal's keymap so the muscle memory carries over.

### 5.3 Activity log (the noise filter)

- Each run shows a **three-line summary**: tool, target, and the parsed result
  (ok/error, the key finding or counts). Example: `ffuf · shop.example.com ·
  3 hits: /admin 301, /api 200, /.git 403`.
- A per-tool summarizer maps the tool's output to those lines. v1 ships a generic
  summarizer (exit status, matched lines, obvious counts); tool-specific
  summarizers are added over time.
- Full raw output on one keystroke (drill-down). The firehose is available, never
  forced.

### 5.4 Findings board

- The findings/notes the operator recorded, severity-sorted, with a detail view.
- The operator writes and edits findings by hand. Optio stores them; it does not
  assess, score, or auto-verdict.

---

## 6. State — one local store, Optio-owned

Optio holds everything in its own store, split by XDG data type: config and the
tool catalog in `~/.config/optio/`, the state store (SQLite) in
`~/.local/share/optio/`, captured raw tool output in `~/.cache/optio/`. The store
is **global and keyed by target, not bound to the current directory** — flag
memory is cross-engagement by nature, so it must follow the operator to the next
target. One per-target `artifacts_dir` setting points at the operator's own
engagement tree, so raw files can live beside their other work while the index
stays global. The store contains:

- **Targets** — the list, plus per-target notes, tech, scope, and the proxy to
  use.
- **Coverage ledger** — which catalog tool ran against which target, when, with
  the parsed result. This is the engine of the coverage board and the "ran
  twice" guard. (The idea is a per-target `(tool, target) -> last result` record;
  the gap list is the catalog minus what ran.)
- **Flag memory** — the operator's last-used arguments per `(target, tool)`, plus
  favorites and command history. This is the arsenal half.
- **Findings / notes** — operator-written, with severity and free text.

Store location is decided (§11): one global store keyed by target, split by XDG
data type, with a per-target `artifacts_dir` for raw output that travels with the
engagement.

---

## 7. Noise reduction — the core UX rule

The problem statement is "track target without many output noise". The rule:

- **Every tool result is summarized before it reaches the screen.** The summary
  is the parsed signal — hits, status, error strings, counts — not the raw
  stream.
- **The full output is always one keystroke away**, never on screen by default.
- **The board shows state, not activity.** No scrolling logs on the home screen —
  gaps and findings, which are decisions the operator must make, not a record of
  what the machine did.

---

## 8. Tech stack (builder's call unless noted)

- **Python 3.11+.** (Decided: it matches the Textual choice and the pentest tool
  ecosystem's scripting norm.)
- **[Textual](https://textual.textualize.io/)** for the TUI — the same framework
  Pentool and OPS use, with a `DataTable`, a worker API for background calls, and
  a message system for thread-safe UI updates. (Decided: it is the mature Python
  TUI.)
- **`subprocess` executor** run inside Textual workers so a long scan does not
  freeze the UI; output streams back as messages. Optional proxy via
  `HTTP(S)_PROXY` env on the child.
- Its own repo (`TyrusRC/optio`, Apache-2.0). No runtime dependency beyond the
  operator's own installed tools.

Decided formats (research-backed):

- **Catalog = YAML.** The audience already writes YAML (nuclei templates) and it
  handles multiline command templates well. One dependency (PyYAML), read-only at
  runtime.
- **Store = SQLite** (stdlib `sqlite3`). The coverage ledger is append-heavy and
  queried ("did tool X run against target Y?"); a single SQLite file is
  concurrent-safe and avoids the rewrite-races of a JSON blob. Small config stays
  YAML; the ledger, flag memory, and findings go in SQLite.

Left to the plan: the summarizer plug-in shape, and the catalog entry schema
detail.

---

## 9. Scope and phases

A project. After this design is approved, the next step is a written plan, not
code.

- **Phase 1 — store and board.** The local store (targets + coverage ledger) and
  the target board rendering it. Add a target, see empty coverage. Proves the
  tracking and low-noise claims before any tool runs.
- **Phase 2 — catalog, launcher, executor.** A starter tool catalog; the launcher
  with flag memory and confirm-before-run; the subprocess executor; the
  three-line activity summary with drill-down; the coverage ledger updated on each
  run.
- **Phase 3 — findings and flow.** The findings board with operator-written
  entries; the coverage rail nudging the next open step; operator-extensible
  catalog entries.
- **Later / stretch.** More tool-specific summarizers; optional Haruspex ranking
  hints (§10); tmux-style multi-pane for watching a long scan live; report export.

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
  lanes/tools. Optio can ask Haruspex to order them by predicted value for this
  target, so the highest-value gap sits at the top. The operator still picks.
- **Triage findings (boolean, `P(real)`).** Haruspex can score a finding
  real-vs-noise; the findings board can show a dim `P(real)` sort hint. Optio does
  not change a finding from it.
- **Severity sanity (score).** A rubric-level hint beside an operator-set
  severity. A hint, never an auto-set.

### Contract and rules

- **Transport.** `POST /v1/evaluate` over local HTTP, keyless by default — not
  MCP, not an LLM. Request carries `{question, candidates: {key: label}, target}`
  and an optional `domain` to route to the right adapter.
- **Optional and fail-open.** Haruspex is not required. If it is not running, is
  slow, or errors, Optio drops the hint and works unchanged. A fast-connect check
  with a short timeout and a circuit breaker means a dead Haruspex never stalls
  the TUI.
- **Abstention is shown as "no call", not guessed.** When Haruspex abstains, Optio
  shows nothing in the hint slot. It never invents a ranking to fill the gap.
- **Advisory only — read §2 anti-goals.** Haruspex ordering never records a
  finding, never runs a tool, never fills a flag. It changes the ORDER the
  operator sees, nothing else.

---

## 11. Decided calls (were open; resolved by research)

1. **Store scope → global, keyed by target.** The field splits between
   per-engagement folder trees ([TrustedSec](https://trustedsec.com/blog/workflow-improvements-for-pentesters),
   [kage](https://skills.sh/workersio/spec/kage), Pensar) and a central user-level
   store ([pentestcode](https://pypi.org/project/pentestcode/): "global store, NOT
   per-directory, security work isn't tied to a cwd"). The central store wins for
   Optio because flag memory is cross-engagement — a cwd-bound store loses your
   recalled flags the moment you `cd`. Split by
   [XDG](https://claudeissues.com/issue/2350-follow-xdg-base-directory-specification-properly-move-runtime-cache-files-out-of)
   data type (§6), with a per-target `artifacts_dir` for raw output that travels
   with the engagement.
2. **Starter catalog → narrow core, operator-extensible.** Community lists
   converge on the ProjectDiscovery stack plus classics
   ([WebHackersWeapons](https://github.com/pikpikcu/WebHackersWeapons),
   [top-50](https://www.securitylab.ru/analytics/559686.php)). Ship one tool per
   job across the flow (~9): `subfinder`, `httpx`, `katana`, `gau`, `ffuf`,
   `nuclei`, `sqlmap`, `dalfox`, `nmap`. A wider arsenal is a summarizer and
   maintenance burden with no payoff; the operator grows the catalog from there.
3. **Proxy default → direct, per-target opt-in, auto-detected.** Silently routing
   every tool through Burp is a footgun (TLS breaks without the CA, Burp may be
   down, scan volume floods it). Default direct; detect a reachable proxy on
   `:8080` and offer a one-key per-target toggle. Explicit, never silent.

These were the operator's three open questions; the research above settles each.
They remain overridable in the plan.
