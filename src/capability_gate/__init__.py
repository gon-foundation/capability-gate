"""Capability Gate: a fail-closed frontier state for agent capabilities.

State is a deterministic function of (capability, policy revision, evidence, overrides,
grants). Only SAFE permits an action. Every evaluation yields a content-addressed record.

v0.2 adds delegated authority (HP-0001 section 7): consequence classes, explicit human
grants bound to one action, and the rule that a critical action is never permitted
without such a grant. Capability, authentication, MFA, task necessity and model
confidence are not authority; they may be passed as context and are recorded as ignored.
"""
import hashlib
import json

SAFE, FRONTIER, UNSAFE, UNKNOWN = "SAFE", "FRONTIER", "UNSAFE", "UNKNOWN"
ALLOW, DENY, ESCALATE = "ALLOW", "DENY", "ESCALATE"

# Consequence classes whose actions are never permitted without explicit human authority.
CRITICAL = frozenset({"financial", "identity", "legal", "irreversible"})
# Grant sources that count as authority. Everything else (authenticated_session, mfa,
# credential_presence, necessity, inferred, ...) is evidence of access, not of intent.
EXPLICIT_SOURCES = frozenset({"explicit_human", "signed_delegation"})


class PolicyError(ValueError):
    pass


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha3(obj):
    return hashlib.sha3_256(canonical(obj)).hexdigest()


def check_policy(policy):
    """Policy: {revision, allowed, frontier, forbidden, override_quorum}. The three sets must be disjoint."""
    a, f, u = (set(policy[k]) for k in ("allowed", "frontier", "forbidden"))
    if a & f or a & u or f & u:
        raise PolicyError("allowed, frontier and forbidden must be disjoint")
    if int(policy.get("override_quorum", 2)) < 2:
        raise PolicyError("override_quorum must be at least 2")
    return a, f, u


def classify(capability, policy):
    """Base state from policy alone. Not listed means UNKNOWN, never SAFE."""
    a, f, u = check_policy(policy)
    if capability in a:
        return SAFE
    if capability in u:
        return UNSAFE
    if capability in f:
        return FRONTIER
    return UNKNOWN


def consequence_of(capability, policy):
    """Consequence class from the policy's optional "consequence" map; "unclassified" if absent."""
    return policy.get("consequence", {}).get(capability, "unclassified")


def explicit_grant(capability, action_hash, grants):
    """The first grant that is explicit authority for exactly this capability and this action.

    Non-transitive: a grant names one capability (no wildcard) and one action hash; a grant
    for another capability or another action does not apply. Sources outside
    EXPLICIT_SOURCES never count, however strong the authentication behind them.
    """
    for g in grants:
        if (g.get("capability") == capability and g.get("action_hash") == action_hash
                and g.get("source") in EXPLICIT_SOURCES and g.get("principal")):
            return g
    return None


def decision_for(state, critical):
    if state == SAFE:
        return ALLOW
    if state == UNSAFE:
        return DENY
    if state == FRONTIER:
        return ESCALATE
    return ESCALATE if critical else DENY  # UNKNOWN: a human may decide a critical one


def evaluate(capability, action_hash, policy, decision=None, overrides=(), grants=(), context=None):
    """Resolve the state for one concrete action.

    decision: a verifier decision record bound to action_hash, with
      {"action_hash", "state": "Verified Fact" | ..., "verdict": True | False | None}.
    overrides: signed approvals [{"authority": id, "action_hash"}]; distinct authorities
      at or above override_quorum lift UNSAFE to FRONTIER only, never to SAFE.
    grants: delegations [{"grant_id", "capability", "action_hash", "source", "principal"}].
      An explicit grant lifts UNKNOWN to SAFE and is required for SAFE on a critical action.
      It never lifts UNSAFE and never replaces the Verified Fact a FRONTIER action needs.
    context: anything else the agent reports (authenticated, mfa, necessity, confidence).
      It never changes the result; its keys are recorded as ignored.
    """
    base = classify(capability, policy)
    state, reason = base, "policy"
    consequence = consequence_of(capability, policy)
    critical = consequence in CRITICAL
    grant = explicit_grant(capability, action_hash, grants)

    bound = decision if decision and decision.get("action_hash") == action_hash else None
    if decision and not bound:
        reason = "decision not bound to this action; ignored"

    if state == UNSAFE:
        auth = {o["authority"] for o in overrides if o.get("action_hash") == action_hash}
        if len(auth) >= int(policy.get("override_quorum", 2)):
            state, reason = FRONTIER, f"override by {len(auth)} distinct authorities"

    if state == FRONTIER and bound:
        v = bound.get("verdict")
        if v is False:
            state, reason = UNSAFE, "verifier verdict false"
        elif v is True and bound.get("state") == "Verified Fact":
            state, reason = SAFE, "verified fact for this action"
        else:
            reason = "no sufficient verdict; stays FRONTIER"

    if state == UNKNOWN and grant:
        state, reason = SAFE, "explicit authority for this action"

    if critical and state == SAFE and not grant:
        state, reason = FRONTIER, f"{consequence} action: explicit human authority required"
    elif critical and state == UNKNOWN:
        reason = f"{consequence} action not delegated: escalate to a human"

    record = {
        "capability": capability,
        "action_hash": action_hash,
        "policy_revision": policy["revision"],
        "base_state": base,
        "state": state,
        "permitted": state == SAFE,
        "decision": decision_for(state, critical),
        "consequence": consequence,
        "reason": reason,
        "decision_id": bound.get("decision_id") if bound else None,
        "grant_id": grant.get("grant_id") if grant and state == SAFE else None,
        "context_ignored": sorted(context) if context else [],
    }
    record["record_id"] = sha3(record)
    return record


def to_aerf(record, agent, observed_at):
    """Map a gate record onto the fields of an AERF evidence receipt (aerf-spec v0.1 draft).

    Returns the fields the gate can fill. The caller adds id, plan_id, key_id and the
    Ed25519 signature with its own key; signing is outside this package.
    """
    evidence = {"gate_record": record}
    return {
        "type": "notarised_evidence",
        "agent": agent,
        "action": ("gate:" + record["capability"])[:128],
        "in_policy": record["permitted"],
        "policy_reason": f'{record["decision"]}: {record["reason"]}',
        "evidence": evidence,
        "evidence_hash_sha512": hashlib.sha512(canonical(evidence)).hexdigest(),
        "observed_at": observed_at,
        "compliance_tags": ["capability-gate-0.2", record["consequence"]],
    }


class Journal:
    """Append-only, hash-chained log of evaluations."""

    def __init__(self):
        self.entries, self.head = [], "0" * 64

    def append(self, record):
        entry = {"prev": self.head, "record": record}
        self.head = sha3(entry)
        self.entries.append(entry)
        return self.head

    def verify(self):
        h = "0" * 64
        for e in self.entries:
            if e["prev"] != h:
                return False
            h = sha3(e)
        return h == self.head
