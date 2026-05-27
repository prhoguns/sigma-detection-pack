"""Every rule must match exactly its planted events in the corpus: no misses, no false positives."""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.convert import RULES, load, sql_for  # noqa: E402

DATA = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture(scope="session")
def db() -> sqlite3.Connection:
    events = [json.loads(line) for line in (DATA / "events.jsonl").read_text().splitlines()]
    cols = sorted({k for e in events for k in e})
    con = sqlite3.connect(":memory:")
    con.execute(f"create table events ({', '.join(f'[{c}] TEXT' for c in cols)})")
    con.executemany(
        f"insert into events ({', '.join(f'[{c}]' for c in cols)}) values ({', '.join('?' for _ in cols)})",
        [[str(e[c]) if c in e and e[c] is not None else None for c in cols] for e in events],
    )
    return con


@pytest.fixture(scope="session")
def expected() -> dict[str, list[int]]:
    return json.loads((DATA / "expected.json").read_text())


@pytest.mark.parametrize("rule_path", RULES, ids=[p.stem for p in RULES])
def test_rule_matches_exactly_the_planted_events(rule_path: Path, db, expected):
    rule = load(rule_path).rules[0]
    sql = sql_for(rule_path)
    matched = {row[0] for row in db.execute(sql.replace("SELECT *", "SELECT CAST(id AS INTEGER)", 1))}
    want = set(expected.get(str(rule.id), []))
    assert want, f"{rule_path.stem}: no planted positives in corpus - every rule must be exercised"
    missed = want - matched
    extra = matched - want
    assert not missed, f"{rule_path.stem} MISSED planted events {sorted(missed)}\nSQL: {sql}"
    assert not extra, f"{rule_path.stem} FALSE POSITIVES on events {sorted(extra)}\nSQL: {sql}"


def test_every_rule_has_required_metadata():
    for path in RULES:
        rule = load(path).rules[0]
        assert rule.title and rule.description and rule.level and rule.tags, path
        assert any(t.namespace == "attack" for t in rule.tags), f"{path}: no ATT&CK tag"
        assert rule.falsepositives, f"{path}: document expected false positives"
