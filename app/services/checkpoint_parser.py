"""Checkpoint HTML export parser — produces import plan for NGFW Manager."""

import re
import ipaddress

_PRIVATE = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
]

KNOWN_SERVICES = {
    "http":          (6,  80,   80),
    "https":         (6,  443,  443),
    "ftp":           (6,  21,   21),
    "ftp-pasv":      (6,  21,   21),
    "ssh":           (6,  22,   22),
    "smtp":          (6,  25,   25),
    "smtps":         (6,  465,  465),
    "imap":          (6,  143,  143),
    "imaps":         (6,  993,  993),
    "pop3":          (6,  110,  110),
    "pop3s":         (6,  995,  995),
    "telnet":        (6,  23,   23),
    "dns":           (17, 53,   53),
    "domain-udp":    (17, 53,   53),
    "domain-tcp":    (6,  53,   53),
    "snmp":          (17, 161,  161),
    "syslog":        (17, 514,  514),
    "ntp":           (17, 123,  123),
    "ldap":          (6,  389,  389),
    "ldaps":         (6,  636,  636),
    "rdp":           (6,  3389, 3389),
    "ms-rdp":        (6,  3389, 3389),
    "vnc":           (6,  5900, 5900),
    "mssql":         (6,  1433, 1433),
    "mysql":         (6,  3306, 3306),
    "oracle":        (6,  1521, 1521),
    "postgresql":    (6,  5432, 5432),
    "bgp":           (6,  179,  179),
    "ospf":          (89, 0,    0),
    "icmp":          (1,  0,    0),
    "ping":          (1,  0,    0),
    "kerberos":      (6,  88,   88),
    "kerberos_v5_tcp": (6, 88,  88),
    "kerberos_v5_udp": (17, 88, 88),
    "radius":        (17, 1812, 1812),
    "radius-acct":   (17, 1813, 1813),
    "tftp":          (17, 69,   69),
    "dhcp":          (17, 67,   68),
    "http-proxy":    (6,  8080, 8080),
    "https_proxy":   (6,  8080, 8080),
    "http_and_https_proxy": (6, 8080, 8080),
}

SKIP_NAMES = {"any", "internet", "internet-ipv4", "internet-ipv6"}


def _is_private(addr: str) -> bool:
    try:
        net = ipaddress.ip_network(addr, strict=False)
        return any(net.subnet_of(p) or p.subnet_of(net) for p in _PRIVATE)
    except ValueError:
        return True


def _zone_for_names(names: list, objects: dict) -> str:
    for name in names:
        if name.lower() in SKIP_NAMES - {"any"}:
            return "untrust"
        obj = objects.get(name)
        if obj:
            for val in obj.get("values", []):
                if not _is_private(val):
                    return "untrust"
        elif not _is_private(name):
            return "untrust"
    return "trust"


def _text(html_fragment: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html_fragment)).strip()


def _hrefs(html_fragment: str) -> list:
    return [m.group(1) for m in re.finditer(r'href="#[^:]+:([^"]+)"', html_fragment)]


def _parse_services(html: str) -> dict:
    services = {}
    m = re.search(r'<caption>Объекты Service</caption>(.*?)</table>', html, re.DOTALL)
    if not m:
        return services
    for row in re.finditer(
            r'<tr><td id="service:([^"]+)"[^>]*>.*?<td>(.*?)</td></tr>',
            m.group(0), re.DOTALL):
        name = row.group(1)
        ports = [i.group(1).strip()
                 for i in re.finditer(r'<li>(.*?)</li>', row.group(2))]
        services[name] = {"ports": ports}
    return services


def _parse_objects(html: str) -> dict:
    objects = {}
    for label in ("Source", "Destination", "Additional"):
        m = re.search(rf'<caption>Объекты {label}</caption>(.*?)</table>', html, re.DOTALL)
        if not m:
            continue
        for row in re.finditer(
                r'<tr><td id="[^:]+:([^"]+)"[^>]*>.*?<td>(.*?)</td></tr>',
                m.group(0), re.DOTALL):
            name = row.group(1)
            if name in objects:
                continue
            values = [i.group(1).strip()
                      for i in re.finditer(r'<li>(.*?)</li>', row.group(2))]
            obj_type = "host"
            for v in values:
                if "/" in v:
                    obj_type = "network"; break
                if re.match(r'^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$', v):
                    obj_type = "range"; break
            if len(values) > 1:
                obj_type = "group"
            objects[name] = {"type": obj_type, "values": values}
    return objects


def _parse_policy_rules(policy_name: str, html: str, objects: dict) -> list:
    table_m = re.search(r'<table>(.*?)</table>', html, re.DOTALL)
    if not table_m:
        return []
    rows = re.split(r'(?=<tr>)', table_m.group(1))
    rules = []
    current_inline = None
    for row in rows:
        if not row.strip() or "<th>" in row:
            continue
        inline_m = re.search(r'<td colspan="\d+"><i>(.*?)</i></td>', row)
        if inline_m:
            current_inline = inline_m.group(1).strip()
            continue
        cells = re.findall(r'<td(?:[^>]*)>(.*?)</td>', row, re.DOTALL)
        if len(cells) < 6:
            continue
        num = _text(cells[0])
        if not num or not num.isdigit():
            continue
        rule_name = _text(cells[1]).strip() or f"{policy_name}_{num}"
        action_raw = _text(cells[2]).strip().lower()
        action = "allow" if action_raw == "accept" else "deny"

        svc_names = _hrefs(cells[3])
        if not svc_names and _text(cells[3]).lower() == "any":
            svc_names = []

        src_names = _hrefs(cells[4]) or ([_text(cells[4])] if _text(cells[4]) else [])
        dst_names = _hrefs(cells[5]) or ([_text(cells[5])] if _text(cells[5]) else [])

        # Filter out Any
        src_names = [n for n in src_names if n.lower() != "any"]
        dst_names = [n for n in dst_names if n.lower() != "any"]

        add_cell = cells[6] if len(cells) > 6 else ""
        uuid_m = re.search(r'<div>uuid:</div>\s*([a-f0-9\-]{36})', add_cell, re.IGNORECASE)

        rules.append({
            "number":          int(num),
            "name":            rule_name,
            "action":          action,
            "services":        svc_names,
            "source":          src_names,
            "destination":     dst_names,
            "src_zone":        _zone_for_names(src_names, objects),
            "dst_zone":        _zone_for_names(dst_names, objects),
            "logging":         "log" in _text(cells[11] if len(cells) > 11 else "").lower(),
            "inline_layer":    current_inline,
            "checkpoint_uuid": uuid_m.group(1) if uuid_m else "",
        })
    return rules


def parse_html(html: str) -> dict:
    services = _parse_services(html)
    objects = _parse_objects(html)
    policies = []

    chunks = re.split(r'(<h3 id="policy:[^"]*">[^<]*</h3>)', html)
    i = 0
    while i < len(chunks):
        hdr_m = re.match(r'<h3 id="policy:[^"]*">\d+\.\s*(.*?)</h3>', chunks[i])
        if hdr_m and i + 1 < len(chunks):
            name = hdr_m.group(1).strip()
            rules = _parse_policy_rules(name, chunks[i + 1], objects)
            policies.append({"name": name, "rules": rules})
            i += 2
        else:
            i += 1

    # Build import plan
    folders = []
    for policy in policies:
        layers, seen = [], set()
        for r in policy["rules"]:
            il = r["inline_layer"]
            if il and il not in seen:
                layers.append(il); seen.add(il)

        blocks = [{"name": l, "rules": []} for l in layers]
        bidx = {l: i for i, l in enumerate(layers)}
        unblocked = []
        for r in policy["rules"]:
            entry = {k: v for k, v in r.items() if k != "inline_layer"}
            if r["inline_layer"]:
                blocks[bidx[r["inline_layer"]]]["rules"].append(entry)
            else:
                unblocked.append(entry)

        folders.append({
            "name":            policy["name"],
            "blocks":          blocks,
            "unblocked_rules": unblocked,
        })

    all_rules = sum(len(f["unblocked_rules"]) + sum(len(b["rules"]) for b in f["blocks"])
                    for f in folders)

    return {
        "services": services,
        "objects":  objects,
        "folders":  folders,
        "stats": {
            "folders":  len(folders),
            "blocks":   sum(len(f["blocks"]) for f in folders),
            "rules":    all_rules,
            "services": len(services),
            "objects":  len(objects),
        },
    }
