# Optio

**A terminal cockpit for pentesters. Run your tools, remember the flags, track
every target — without the noise.**

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
- **One target, tracked.** A quiet board shows coverage gaps, which tools ran vs.
  open, and your findings — not a scrolling log.
- **Flag memory.** Pick a tool, it recalls your last arguments for this target and
  pre-fills them. The exact command shows before anything runs.
- **Low noise.** Every result is summarized to a few lines; the full output is one
  keystroke away.
- **Your own arsenal.** An editable catalog defines each tool, its flags, and how
  to read its output. Add your tools; Optio drives them.
- **Standalone.** Nothing to install but your own tools. Route traffic through a
  proxy you already run (e.g. Burp) if you want — none is required.

## How it works

Optio is a single terminal app over a local store. A **catalog** defines your
tools (binary, flag template, output summarizer); a **launcher** recalls your
flags and shows the command before it runs; an **executor** spawns the tool and
streams its output; a **summarizer** turns that output into a few lines. Your
targets, the coverage ledger, your flag memory, and your findings live in a local
store keyed by target, so your habits follow you across engagements.

## Run from source

Optio uses [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/TyrusRC/optio
cd optio
uv run optio
```

`uv run` creates the environment and installs on first use. Run the tests with
`uv run pytest`.

**Keys:** `a` add a target · `r` run the next suggested action (review the
command, then confirm) · `f` show the full output of the last run · `q` quit.

State lives in your XDG dirs: config and your catalog in `~/.config/optio/`, the
SQLite store in `~/.local/share/optio/`. Set `OPTIO_HOME` to point all of it
somewhere else.

## Status

Early but runnable. In place: the target and coverage board, the next-action
advisor (a deterministic, findings-first priority ladder over the flow), flag
memory, a subprocess runner with optional proxy, and a catalog of ~30 common web
and network tools. Add your own in `~/.config/optio/catalog/`. The catalog format
and the UI will still change.

## Contributing

Issues and pull requests are welcome. The catalog is designed to be extended, so
new tool definitions and output summarizers are a good first contribution.

## License

Apache-2.0. See [LICENSE](LICENSE).
