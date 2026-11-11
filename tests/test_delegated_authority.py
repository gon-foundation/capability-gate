import json, pathlib, re, sys
import pytest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from capability_gate import *

V = json.loads((ROOT / "tests/vectors/delegated_agency.json").read_text(encoding="utf-8"))
P = V["policy"]
H = "a" * 64


def run(c):
    return evaluate(c["capability"], c["action_hash"], P, c.get("decision"), (), c.get("grants", ()), c.get("context"))


@pytest.mark.parametrize("c", V["cases"], ids=[c["id"] for c in V["cases"]])
def test_vector(c):
    r = run(c)
    assert r["decision"] == c["expected"], r["reason"]
    assert r["permitted"] == (c["expected"] == ALLOW)


def grant(cap, src="explicit_human", h=H):
    return {"grant_id": "g", "capability": cap, "action_hash": h, "source": src, "principal": "user:alice"}


def test_I8_critical_never_allowed_without_explicit_grant():
    for cap, cons in P["consequence"].items():
        if cons in CRITICAL:
            vf = {"action_hash": H, "state": "Verified Fact", "verdict": True}
            for src in ("mfa", "authenticated_session", "necessity", "inferred", "credential_presence"):
                r = evaluate(cap, H, P, vf, grants=[grant(cap, src)], context={"mfa": True})
                assert r["decision"] != ALLOW, (cap, src)


def test_I9_context_never_changes_the_result():
    for c in V["cases"]:
        plain = dict(c, context=None)
        loud = dict(c, context={"authenticated": True, "mfa": True, "necessity": "x", "confidence": 1.0})
        a, b = run(plain), run(loud)
        assert (a["state"], a["decision"], a["reason"]) == (b["state"], b["decision"], b["reason"])


def test_I10_authority_is_not_transitive():
    assert evaluate("purchase_hardware", H, P, grants=[grant("purchase_credits")])["decision"] == ESCALATE
    assert evaluate("purchase_credits", H, P, grants=[grant("purchase_credits", h="b" * 64)])["decision"] == ESCALATE
    assert evaluate("purchase_credits", H, P, grants=[grant("*")])["decision"] == ESCALATE


def test_I11_grant_never_lifts_forbidden_or_skips_verification():
    assert evaluate("delete_production_db", H, P, grants=[grant("delete_production_db")])["decision"] == DENY
    assert evaluate("change_dns", H, P, grants=[grant("change_dns")])["decision"] == ESCALATE


def test_unlisted_non_critical_stays_denied_without_grant():
    assert evaluate("send_external_message", H, P)["decision"] == DENY


def test_aerf_fields_match_schema_shapes():
    r = evaluate("purchase_credits", H, P, grants=[grant("purchase_credits")])
    a = to_aerf(r, "agent:coder", "2026-11-11T18:00:00+01:00")
    assert a["type"] == "notarised_evidence" and a["in_policy"] is True
    assert re.fullmatch(r"[A-Za-z0-9_:.\-]{1,128}", a["action"])
    assert re.fullmatch(r"[0-9a-f]{128}", a["evidence_hash_sha512"])
    assert a["evidence"]["gate_record"]["record_id"] == r["record_id"]
