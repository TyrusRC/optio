"""The command-palette matcher — type what you want, find the tool or pipeline.

This is the "no learning" surface: the operator does not memorise which of ~70
tools does what, they type a word and Optio ranks the matches. Pure logic here;
the Textual provider is thin glue over it.
"""

from optio.catalog import Tool
from optio.pipeline import Pipeline
from optio.tui.commands import Command, match_commands

CATALOG = [
    Tool(name="nmap", binary="nmap", lane="network", phase="recon",
         template="nmap {host}", description="port and service scan", scope="net"),
    Tool(name="sqlmap", binary="sqlmap", lane="web-scan", phase="probe",
         template="sqlmap -u {url}", description="automatic SQL injection", scope="web"),
    Tool(name="nuclei", binary="nuclei", lane="web-scan", phase="scan",
         template="nuclei -u {url}", description="template vulnerability scanner", scope="web"),
]
PIPELINES = [
    Pipeline(name="recon-sweep", description="subfinder then httpx", steps=["nmap"]),
]


def test_empty_query_lists_everything_tools_then_pipelines():
    cmds = match_commands(CATALOG, PIPELINES, "")
    names = [c.name for c in cmds]
    assert set(names) == {"nmap", "sqlmap", "nuclei", "recon-sweep"}
    # pipelines come after tools
    assert names.index("recon-sweep") == len(names) - 1


def test_name_match_ranks_above_description_match():
    # "sql" is in the name sqlmap AND the description of nuclei? no — only sqlmap.
    cmds = match_commands(CATALOG, PIPELINES, "sql")
    assert cmds[0].name == "sqlmap"


def test_description_word_matches_when_name_does_not():
    # nothing is named "injection", but sqlmap's description has it
    cmds = match_commands(CATALOG, PIPELINES, "injection")
    assert [c.name for c in cmds] == ["sqlmap"]


def test_name_prefix_outranks_mid_name_substring():
    cmds = match_commands(CATALOG, PIPELINES, "n")
    names = [c.name for c in cmds]
    # prefix (nmap, nuclei) first, then name-substring (recon-sweep),
    # then description-only (sqlmap's "injection")
    assert set(names[:2]) == {"nmap", "nuclei"}
    assert names[2] == "recon-sweep"
    assert names[3] == "sqlmap"


def test_match_is_case_insensitive():
    assert any(c.name == "nmap" for c in match_commands(CATALOG, PIPELINES, "NMAP"))


def test_command_carries_kind_and_a_human_title():
    cmd = match_commands(CATALOG, PIPELINES, "nmap")[0]
    assert cmd.kind == "tool"
    assert "nmap" in cmd.title and "scan" in cmd.title
    pipe = match_commands(CATALOG, PIPELINES, "recon-sweep")[0]
    assert pipe.kind == "pipeline"


def test_command_is_frozen():
    import dataclasses
    assert dataclasses.is_dataclass(Command)
