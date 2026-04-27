"""
Policy Analyzer — local analysis of cached security rules.
Works entirely from the local DB cache, no NGFW API calls required.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional, Set, Tuple


def _is_any(field: Optional[Dict]) -> bool:
    if not field:
        return True
    kind = field.get("kind", "")
    if "ANY" in kind:
        return True
    objects = field.get("objects", [])
    if isinstance(objects, dict):
        objects = objects.get("array", [])
    return not objects


def _get_ids(field: Optional[Dict]) -> Optional[Set[str]]:
    """Return set of object IDs, or None if field is ANY."""
    if _is_any(field):
        return None  # None = ANY
    objects = field.get("objects", [])
    if isinstance(objects, dict):
        objects = objects.get("array", [])
    ids: Set[str] = set()
    for item in objects:
        if not isinstance(item, dict):
            continue
        if "id" in item:
            ids.add(item["id"])
        else:
            for v in item.values():
                if isinstance(v, dict) and "id" in v:
                    ids.add(v["id"])
                    break
    return ids or None  # empty list treated as ANY too


def _covers(a_field: Optional[Dict], b_field: Optional[Dict]) -> bool:
    """True if field A is a superset of field B (A covers all traffic that B would match)."""
    a_ids = _get_ids(a_field)
    b_ids = _get_ids(b_field)
    if a_ids is None:   # A is ANY — covers everything
        return True
    if b_ids is None:   # A is specific, B is ANY — A cannot cover all of B
        return False
    return b_ids.issubset(a_ids)


def _action_norm(data: Dict) -> str:
    raw = data.get("action", "")
    return raw.split("_")[-1].upper() if "_" in raw else raw.upper()


def _fields(data: Dict) -> Dict[str, Optional[Dict]]:
    return {
        "srcZone": data.get("sourceZone"),
        "dstZone": data.get("destinationZone"),
        "srcAddr": data.get("sourceAddr"),
        "dstAddr": data.get("destinationAddr"),
        "service": data.get("service"),
    }


# ------------------------------------------------------------------
# Issue types
# ------------------------------------------------------------------

def find_disabled(rules: List[Dict]) -> List[Dict]:
    """Rules that are disabled (enabled=False)."""
    result = []
    for r in rules:
        d = r.get("data") or {}
        if not d.get("enabled", True):
            result.append({
                "rule_id": r["id"],
                "ext_id":  r["ext_id"],
                "name":    r["name"],
                "folder":  r.get("folder_name", ""),
                "device":  r.get("device_group_id", ""),
            })
    return result


def find_too_broad(rules: List[Dict]) -> List[Dict]:
    """Enabled rules with srcAddr=ANY AND dstAddr=ANY AND action=ALLOW."""
    result = []
    for r in rules:
        d = r.get("data") or {}
        if not d.get("enabled", True):
            continue
        action = _action_norm(d)
        if action not in ("ALLOW", "PASS"):
            continue
        if _is_any(d.get("sourceAddr")) and _is_any(d.get("destinationAddr")):
            result.append({
                "rule_id": r["id"],
                "ext_id":  r["ext_id"],
                "name":    r["name"],
                "folder":  r.get("folder_name", ""),
                "device":  r.get("device_group_id", ""),
                "reason":  "Source=Any & Destination=Any & Action=Allow",
            })
    return result


def find_shadowed(rules: List[Dict]) -> List[Dict]:
    """
    Find rules that are potentially fully shadowed by an earlier rule.
    A rule B is shadowed by rule A (A < B in position) if:
    - A is enabled
    - A covers B in every traffic dimension (srcZone, dstZone, srcAddr, dstAddr, service)
    - Same action (or A=DENY/DROP and B=ALLOW — total shadow)
    """
    result = []
    for i, b in enumerate(rules):
        b_data = b.get("data") or {}
        if not b_data.get("enabled", True):
            continue
        b_action = _action_norm(b_data)
        b_f = _fields(b_data)

        for a in rules[:i]:
            a_data = a.get("data") or {}
            if not a_data.get("enabled", True):
                continue
            a_action = _action_norm(a_data)
            a_f = _fields(a_data)

            # Check all dimensions
            if not all(_covers(a_f[k], b_f[k]) for k in a_f):
                continue

            # Determine shadow type
            if a_action == b_action:
                reason = f"Fully covered by «{a['name']}» (same action={a_action})"
            elif a_action in ("DENY", "DROP") and b_action == "ALLOW":
                reason = f"Traffic blocked by «{a['name']}» (DENY) — Allow rule never reached"
            else:
                continue  # different actions, not a simple shadow

            result.append({
                "rule_id":        b["id"],
                "ext_id":         b["ext_id"],
                "name":           b["name"],
                "folder":         b.get("folder_name", ""),
                "device":         b.get("device_group_id", ""),
                "shadowed_by_id": a["id"],
                "shadowed_by":    a["name"],
                "reason":         reason,
            })
            break  # report first shadow only per rule

    return result


def find_redundant(rules: List[Dict]) -> List[Dict]:
    """
    Adjacent rules with the same action that could potentially be merged.
    Simplified: rules with identical action + identical srcZone + identical dstZone,
    but different srcAddr/dstAddr (suggests they could be grouped into one).
    We look for pairs where zones+action match and one covers the other partially.
    """
    result = []
    seen_pairs: Set[Tuple[str, str]] = set()

    for i, a in enumerate(rules):
        a_data = a.get("data") or {}
        if not a_data.get("enabled", True):
            continue
        a_action = _action_norm(a_data)

        for b in rules[i+1:i+20]:  # check next 20 only — close neighbours
            b_data = b.get("data") or {}
            if not b_data.get("enabled", True):
                continue
            if _action_norm(b_data) != a_action:
                continue

            pair = tuple(sorted([a["id"], b["id"]]))
            if pair in seen_pairs:
                continue

            # Same zones + same service → candidate for merge
            a_f = _fields(a_data)
            b_f = _fields(b_data)

            sz_same = (_get_ids(a_f["srcZone"]) == _get_ids(b_f["srcZone"])
                       or _is_any(a_f["srcZone"]) and _is_any(b_f["srcZone"]))
            dz_same = (_get_ids(a_f["dstZone"]) == _get_ids(b_f["dstZone"])
                       or _is_any(a_f["dstZone"]) and _is_any(b_f["dstZone"]))
            svc_same = (_get_ids(a_f["service"]) == _get_ids(b_f["service"]))

            if sz_same and dz_same and svc_same:
                # Addresses differ — potential merge
                a_src = _get_ids(a_f["srcAddr"])
                b_src = _get_ids(b_f["srcAddr"])
                if a_src != b_src:
                    seen_pairs.add(pair)
                    result.append({
                        "rule_id": a["id"],
                        "ext_id":  a["ext_id"],
                        "name":    a["name"],
                        "folder":  a.get("folder_name", ""),
                        "device":  a.get("device_group_id", ""),
                        "pair_id": b["id"],
                        "pair_name": b["name"],
                        "reason":  f"Same zones, service, action={a_action} — consider merging source addresses",
                    })

    return result[:50]  # cap at 50 pairs


def run_analysis(rules_with_meta: List[Dict]) -> Dict[str, Any]:
    """Run all checks and return combined results."""
    disabled   = find_disabled(rules_with_meta)
    too_broad  = find_too_broad(rules_with_meta)
    shadowed   = find_shadowed(rules_with_meta)
    redundant  = find_redundant(rules_with_meta)

    total_issues = len(disabled) + len(too_broad) + len(shadowed) + len(redundant)

    return {
        "total_rules":   len(rules_with_meta),
        "total_issues":  total_issues,
        "disabled":      disabled,
        "too_broad":     too_broad,
        "shadowed":      shadowed,
        "redundant":     redundant,
    }
