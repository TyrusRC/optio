# Optio

A human-driven terminal cockpit for the Praetor pentest engine.

Praetor runs the pentest flow under Claude. **Optio runs it under a human.** The
operator makes every decision. Optio remembers the tools, the flags, and what
already ran against each target — and keeps the screen quiet.

> In a Roman century, the *optio* was the centurion's deputy — the one who kept
> the roster, remembered the standing orders, and handled the bookkeeping so the
> commander could decide. That is this tool's job. (It also puns on CLI
> **opt**ions.)

## What it does

- **Human in the decision seat.** No generative LLM. Optio surfaces state and
  runs what you pick. It can show an optional ranking hint from
  [Haruspex](https://github.com/TyrusRC/haruspex) — a small, local, calibrated
  scorer that abstains when unsure — but you make every call.
- **One target, tracked.** A quiet board shows coverage gaps, lanes/tools run
  vs. open, and findings by severity — not a scrolling log.
- **Flag memory.** Pick a tool, it recalls your last arguments for this target
  and pre-fills them. The exact command shows before anything runs.
- **Low noise.** Every tool result is summarized to a few lines; the full output
  is one keystroke away.
- **Shared state with Praetor.** Optio reads and writes the same
  `.burp-intel/<domain>/` state through the same tools, so a target hands off
  cleanly between you and Claude.

## How it works

Optio is a **human-driven MCP host**. Claude drives Praetor as an MCP host;
Optio is the same host with a human in the loop. It connects to the Praetor MCP
server, discovers the full tool catalog, and calls tools on your command — so it
reuses the whole engine with no coupling to its internals.

See [DESIGN.md](DESIGN.md) for the full design.

## Status

Design stage. No product code yet. The design is agreed first, then a plan, then
code.

## License

Apache-2.0. See [LICENSE](LICENSE).
