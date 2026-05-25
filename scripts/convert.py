"""Convert every rule to SQL (for the tests), Splunk SPL and Sentinel KQL. Writes out/<target>/<rule>.txt and out/catalog.md."""
from __future__ import annotations

from pathlib import Path

from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.pipelines.splunk import splunk_windows_pipeline

RULES = sorted(Path("rules").rglob("*.yml"))


def load(path: Path) -> SigmaCollection:
    return SigmaCollection.from_yaml(path.read_text())


def sql_for(path: Path, table: str = "events") -> str:
    q = sqliteBackend().convert(load(path))[0]
    return q.replace("<TABLE_NAME>", table)


# Sentinel table to query when a rule has no ASIM mapping (security log, Sysmon pipe/registry, Linux syslog).
SENTINEL_TABLE = {"security": "SecurityEvent", "sshd": "Syslog", "sudo": "Syslog", "auth": "Syslog"}


def kql_for(coll: SigmaCollection) -> str:
    rule = coll.rules[0]
    try:
        return KustoBackend(processing_pipeline=sentinel_asim_pipeline()).convert(coll)[0]
    except Exception:
        table = SENTINEL_TABLE.get(rule.logsource.service or "", "Event")
        return KustoBackend(processing_pipeline=azure_monitor_pipeline(query_table=table)).convert(load_path(rule))[0]


def load_path(rule) -> SigmaCollection:
    return load(next(p for p in RULES if load(p).rules[0].id == rule.id))


def main() -> None:
    backends = {
        "sql": lambda c: sqliteBackend().convert(c)[0].replace("<TABLE_NAME>", "events"),
        "splunk": lambda c: SplunkBackend(processing_pipeline=splunk_windows_pipeline()).convert(c)[0],
        "kql": kql_for,
    }
    rows = []
    for path in RULES:
        coll = load(path)
        rule = coll.rules[0]
        for name, fn in backends.items():
            out = Path("out") / name / f"{path.stem}.txt"
            out.parent.mkdir(parents=True, exist_ok=True)
            try:
                out.write_text(fn(load(path)) + "\n")
                status = "ok"
            except Exception as exc:  # a backend may not support a logsource; record it rather than fail the pack
                out.write_text(f"-- not converted: {exc}\n")
                status = "n/a"
            rows.append((path.stem, name, status))
        techniques = ", ".join(t.name.upper() for t in rule.tags if t.namespace == "attack" and t.name.startswith("t"))
        tactics = ", ".join(t.name.replace("-", " ").title() for t in rule.tags if t.namespace == "attack" and not t.name.startswith("t"))
        rule.custom_attributes["_row"] = (path, rule.title, str(rule.level.name).lower() if rule.level else "", tactics, techniques)

    lines = ["# Rule catalog", "", "| Rule | Level | ATT&CK tactic | Technique | SQL | Splunk | KQL |", "|---|---|---|---|---|---|---|"]
    for path in RULES:
        rule = load(path).rules[0]
        techniques = ", ".join(t.name.upper() for t in rule.tags if t.namespace == "attack" and t.name.startswith("t"))
        tactics = ", ".join(t.name.replace("-", " ").title() for t in rule.tags if t.namespace == "attack" and not t.name.startswith("t"))
        st = {name: s for p, name, s in rows if p == path.stem}
        lines.append(f"| [{rule.title}]({path.as_posix()}) | {rule.level.name.lower()} | {tactics} | {techniques} | {st['sql']} | {st['splunk']} | {st['kql']} |")
    Path("out/catalog.md").write_text("\n".join(lines) + "\n")
    print(f"converted {len(RULES)} rules to {len(backends)} targets")


if __name__ == "__main__":
    main()
