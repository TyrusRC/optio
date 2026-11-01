"""Haruspex re-ranks the flow automatically — no manual trigger.

The deterministic ladder decides WHICH tools are open; Haruspex reorders the
runnable ones by predicted value when it is available, and abstains silently
otherwise. rerank is pure: it takes a ranker callable, so the flow stays
testable without a network. Fail-open — a None ranking leaves the order alone.
"""

from optio.advisor import Suggestion, rerank


def _sug(tool, priority, phase="probe"):
    return Suggestion(action=f"Run {tool}", reason="", priority=priority,
                      tool=tool, command=None, phase=phase)


def test_rerank_orders_tool_suggestions_by_ranker():
    sugs = [_sug("nmap", 2), _sug("httpx", 3), _sug("nuclei", 4)]
    out = rerank(sugs, lambda opts: ["nuclei", "nmap", "httpx"])
    assert [s.tool for s in out] == ["nuclei", "nmap", "httpx"]


def test_rerank_keeps_non_tool_suggestions_in_place():
    verify = Suggestion(action="Verify lead", reason="", priority=0, tool=None, phase="verify")
    sugs = [verify, _sug("nmap", 2), _sug("httpx", 3)]
    out = rerank(sugs, lambda opts: ["httpx", "nmap"])
    assert out[0] is verify                      # manual step stays first
    assert [s.tool for s in out[1:]] == ["httpx", "nmap"]


def test_rerank_abstain_leaves_order_unchanged():
    sugs = [_sug("nmap", 2), _sug("httpx", 3)]
    out = rerank(sugs, lambda opts: None)        # Haruspex offline / unsure
    assert [s.tool for s in out] == ["nmap", "httpx"]


def test_rerank_no_tools_is_a_noop():
    verify = Suggestion(action="Verify", reason="", priority=0, tool=None, phase="verify")
    out = rerank([verify], lambda opts: ["x"])
    assert out == [verify]
