# Optio

A standalone terminal cockpit for a pentest operator. It runs your security
tools, remembers the flags, tracks what already ran against each target, and
keeps the screen quiet.

**You** make every decision. Optio has no LLM and depends on no other engine —
one operator, one terminal, your own tools.

## The problem

Mid-engagement you carry three things in your head at once:

1. **The flags** each tool needs for this case.
2. **What already ran** against this target, and the result.
3. **What is still open** — the untested tools and classes.

Cheatsheet tools (arsenal, navi) remember the flags. A couple of TUI consoles
track one target. None carries all three for *your own* toolset. Optio does.

## What it does

- **You decide; Optio remembers.** No generative model. It surfaces state and
  runs what you pick.
- **One target, tracked.** A quiet board shows coverage gaps, which tools ran vs.
  open, and findings — not a scrolling log.
- **Flag memory.** Pick a tool, it recalls your last arguments for this target
  and pre-fills them. The exact command shows before anything runs.
- **Low noise.** Every tool result is summarized to a few lines; the full output
  is one keystroke away.
- **Standalone.** Nothing to install but your own tools. It can route tool
  traffic through a proxy you already run (e.g. Burp), but requires none.
- **Optional hint.** It can show a ranking hint from
  [Haruspex](https://github.com/TyrusRC/haruspex) — a small, local, calibrated
  scorer that abstains when unsure — but you make every call.

## How it works

Optio is one process with four parts over its own local store: a **catalog** of
tool definitions (binary + flag template + summarizer), a **launcher** that
recalls your flags and shows the command before it runs, an **executor** that
spawns the tool as a subprocess, and a **summarizer** that turns the output into
a few lines. The store holds your targets, the coverage ledger, your flag
memory, and your findings.

See [DESIGN.md](DESIGN.md) for the full design.

## Status

Design stage. No product code yet. The design is agreed first, then a plan, then
code.

## License

Apache-2.0. See [LICENSE](LICENSE).
