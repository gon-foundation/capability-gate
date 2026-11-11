# HP-0001: Capability Gate (Frontier Capability State), v0.2

Status: draft with reference implementation and tests (`src/`, `tests/`, 35 tests passing). Not yet reviewed externally. v0.2 adds section 7 (delegated authority); sections 1 to 6 are unchanged in effect.

## 1. Inputs
- capability `c`
- policy `P` with a revision and three **disjoint** sets: `allowed`, `frontier`, `forbidden`, plus `override_quorum ≥ 2`
- action hash `h`: SHA3-256 of the concrete action
- optional verifier decision `D`, bound to `h`, with verdict `true | false | null` (as in CANON-RES-012) and state
- optional overrides `O`: approvals from authorities, bound to `h`

## 2. States
`SAFE`, `FRONTIER`, `UNSAFE`, `UNKNOWN`. The state is a function of `(c, P, D, O, h)`, not of `c` alone.

## 3. Rules
1. **Base:** `c ∈ allowed → SAFE`; `c ∈ forbidden → UNSAFE`; `c ∈ frontier → FRONTIER`; otherwise `UNKNOWN`.
2. **Override:** `UNSAFE → FRONTIER` only if at least `override_quorum` **distinct** authorities approved this `h`. An override never leads directly to `SAFE`.
3. **Settlement:** from `FRONTIER`:
   - verdict `true` and state Verified Fact → `SAFE`, for this action only;
   - verdict `false` → `UNSAFE`;
   - verdict `null`, no decision, or a decision bound to another action → stays `FRONTIER`.
4. **Permission:** only `SAFE` permits the action.

## 4. Invariants (each covered by a test)
| Invariant | Test |
|---|---|
| I1 Disjoint policy | `test_disjoint_policy_required` |
| I2 Fail-closed: UNKNOWN, FRONTIER and UNSAFE never permit | `test_unknown_is_not_permitted`, `test_only_safe_permits` |
| I3 No settlement without a Verified Fact | `test_frontier_settles_only_on_verified_fact` |
| I4 Binding: evidence for another action is ignored | `test_decision_must_be_bound_to_action` |
| I5 Override needs a distinct quorum and never skips verification | `test_override_needs_distinct_quorum_and_never_reaches_safe_directly`, `test_quorum_below_two_rejected` |
| I6 Determinism: same inputs, same content-addressed record | `test_deterministic_record` |
| I7 No silent crossing: every evaluation is appended to a hash-chained journal; a rewrite is detected | `test_journal_detects_rewrite` |

## 5. Changes against the source artifact
- UNKNOWN is a real state: the policy no longer covers everything.
- The frontier is its own set, not the boundary of `allowed`. This removes double states.
- The verifier verdict is three-valued (`null` = no verdict), not `{0,1}`.
- An override requires a quorum and never reaches SAFE directly.
- Status changed from "Complete / Ready" to "draft with tests".

## 6. Where it connects
- **Gravit Verifier:** produces the decision `D`.
- **History Keeper:** can anchor the journal head with independent timestamps.
- **OVAIC:** a candidate shared test case.
- **Proof-of-Control (LF Decentralized Trust):** a concrete answer to "did the agent stay within its controls, and who allowed crossing a boundary". It fits our planned comment.

## 7. Delegated authority (v0.2)

An agent that can do something has not thereby been allowed to do it. Section 7 makes this testable.

### 7.1 Inputs
- optional `P.consequence`: a map from capability to consequence class. Absent means `unclassified`.
- **critical** classes: `financial`, `identity`, `legal`, `irreversible`.
- grants `G`: `{grant_id, capability, action_hash, source, principal}`. A grant counts as **explicit authority** only if it names this exact capability (no wildcard), this exact action hash, a source in `{explicit_human, signed_delegation}` and a principal.
- context: anything else the agent reports (authenticated session, MFA, task necessity, model confidence). It is recorded as ignored and never changes the result.

### 7.2 Rules (applied after section 3)
5. **Explicit grant:** `UNKNOWN → SAFE` if an explicit grant exists. A grant never lifts `UNSAFE` (that needs the quorum of rule 2) and never replaces the Verified Fact a `FRONTIER` action needs.
6. **Critical action:** if the consequence is critical and there is no explicit grant, `SAFE` becomes `FRONTIER`. A critical action is therefore never permitted without explicit human authority, even when the capability is `allowed` or a Verified Fact exists.
7. **Decision:** `SAFE → ALLOW`, `UNSAFE → DENY`, `FRONTIER → ESCALATE`, `UNKNOWN → ESCALATE` if critical, else `DENY`. Escalation routes to a human; it permits nothing.

### 7.3 Invariants
| Invariant | Test |
|---|---|
| I8 A critical action is never ALLOW without an explicit grant, whatever the authentication, MFA, necessity or verdict | `test_I8_critical_never_allowed_without_explicit_grant` |
| I9 Context (authentication, MFA, necessity, confidence) never changes the result | `test_I9_context_never_changes_the_result` |
| I10 Authority is not transitive: other capability, other action or wildcard does not count | `test_I10_authority_is_not_transitive` |
| I11 A grant never lifts a forbidden capability and never skips verification | `test_I11_grant_never_lifts_forbidden_or_skips_verification` |

### 7.4 Test vectors
`tests/vectors/delegated_agency.json`: 15 adversarial cases (DA-001 to DA-015) and 5 controls (DA-101 to DA-105), each with its expected decision. DA-001 is the reference incident: an agent asked to integrate an API finds the credit balance empty and buys credits itself, with a valid session and MFA. Expected: ESCALATE.

### 7.5 Evidence format
`to_aerf(record, agent, observed_at)` maps a gate record onto the fields of an AERF evidence receipt (aerf-spec v0.1 draft): `type`, `agent`, `action`, `in_policy`, `policy_reason`, `evidence`, `evidence_hash_sha512`, `observed_at`, `compliance_tags`. The caller adds `id`, `plan_id`, `key_id` and the Ed25519 `signature` with its own key.

### 7.6 Not covered
Whether an action matches the intent of a natural-language instruction is not decided here; the gate checks named capabilities and exact action hashes only. Consequence classes are declared by the policy author, not inferred.
