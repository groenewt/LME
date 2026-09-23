"""Static regression guard for the Fleet collection contract (E domain).

These are pure-YAML structural assertions over ansible/roles/fleet/tasks/main.yml -- no
deploy, no ansible-playbook. They lock the fail-closed contract added in response to the
Codex 0315 E-audit so a later edit cannot silently regress it:

  * E-REQUIRED-SECURITY: endpoint-security is REQUIRED, waivable only by an explicit declared
    opt-out (never derived from offline_mode).
  * E-FLEET-REACHABILITY: the D1 assert is a STATIC topology check that does not claim a route;
    reachability is proven by a FRESH, agent-filtered data-flow gate.
  * E-EXISTING-WEAK-GATES: the data-flow gate requires actual documents (via _count) indexed
    since run start and attributed to the fleet-server agent -- not merely that an index NAME
    exists (the removed _cat/indices check).

They do NOT prove runtime behavior (that needs a deploy); they prevent the contract's structure
from being removed.
"""

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]
FLEET_MAIN = REPO_ROOT / "ansible" / "roles" / "fleet" / "tasks" / "main.yml"


def _tasks():
    docs = list(yaml.safe_load_all(FLEET_MAIN.read_text()))
    tasks = docs[0] if docs else []
    assert isinstance(tasks, list) and tasks, "fleet main.yml did not parse to a task list"
    return tasks


def _find(tasks, name_substr):
    return [t for t in tasks if isinstance(t, dict) and name_substr.lower() in str(t.get("name", "")).lower()]


def _mod(task, key):
    """Return a module's args whether it uses the short or the ansible.builtin.-prefixed key."""
    if key in task:
        return task[key]
    return task.get("ansible.builtin." + key, {})


def _dump(obj):
    return yaml.safe_dump(obj, default_flow_style=False, sort_keys=False)


def test_endpoint_security_is_required_not_offline_derived():
    tasks = _tasks()
    matches = _find(tasks, "required endpoint-security")
    assert matches, "missing the fail-closed required-endpoint-security assert"
    task = matches[0]
    that = _dump(_mod(task, "assert").get("that", []))
    # Waivable ONLY by the explicit declared opt-out ...
    assert "fleet_endpoint_security_optional" in that
    # ... and never by an implicit offline derivation.
    assert "offline_mode" not in that, "offline_mode must not gate required endpoint security"


def test_run_start_timestamp_is_captured_from_target_host():
    tasks = _tasks()
    setters = [t for t in tasks if isinstance(t, dict) and "fleet_run_start" in _dump(_mod(t, "set_fact"))]
    assert setters, "fleet_run_start fact is not set"
    # captured from a target-host `date` command (not the controller clock)
    date_cmds = [t for t in tasks if isinstance(t, dict) and "date -u" in _dump(_mod(t, "command"))]
    assert date_cmds, "run-start timestamp must come from a target-host `date -u` command"


def test_topology_assert_does_not_claim_reachability():
    tasks = _tasks()
    matches = _find(tasks, "Validate the resolved Fleet default output topology")
    assert matches, "the D1 assert must be reframed to static topology validation"
    success = str(_mod(matches[0], "assert").get("success_msg", "")).lower()
    assert "not asserted" in success, "static topology assert must not claim a usable route"
    # the old over-claiming name must be gone
    assert not _find(tasks, "is reachable by shipping agents")


def test_dataflow_gate_requires_fresh_agent_attributed_documents():
    tasks = _tasks()
    count_gates = [
        t for t in tasks
        if isinstance(t, dict) and "_count" in _dump(_mod(t, "uri")).lower()
        and ("elastic_agent" in _dump(_mod(t, "uri")).lower())
    ]
    assert len(count_gates) >= 2, "expected metrics + logs elastic_agent _count gates"
    for g in count_gates:
        body = _dump(g)
        assert "fleet_run_start" in body, "data-flow gate must filter on freshness (fleet_run_start)"
        assert ("agent.id" in body) or ("fleet_server_agent_ids" in body), \
            "data-flow gate must attribute documents to the fleet-server agent"
        assert "count" in _dump(g.get("until", "")), "gate must require a document count, not index existence"


def test_agent_ids_are_captured_from_the_fleet_server_policy():
    tasks = _tasks()
    setters = [t for t in tasks if isinstance(t, dict) and "fleet_server_agent_ids" in _dump(_mod(t, "set_fact"))]
    assert setters, "fleet_server_agent_ids must be captured for the data-flow proof"
    assert "fleet-server-policy" in _dump(setters[0])


def test_stale_index_name_gate_is_removed():
    tasks = _tasks()
    for t in tasks:
        if isinstance(t, dict):
            url = _dump(_mod(t, "uri")).lower()
            assert "_cat/indices/metrics-elastic_agent" not in url, \
                "the index-name-only _cat/indices gate must not return"
