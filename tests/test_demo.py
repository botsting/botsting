"""`promptproof demo`: the practice bot behind the drop-in harness, scanned over HTTP on this machine."""

import json
import os

import promptproof.harness as pp
from promptproof.cli import main
from promptproof.demo import LIVE_CAP
from promptproof.seal import check


def test_the_demo_catches_the_vulnerable_build_and_clears_the_fixed_one(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(pp.KEY_ENV, raising=False)
    assert main(["demo", "--replays", "1"]) == 0
    printed = capsys.readouterr().out
    assert "== The vulnerable build ==" in printed and "verified violation(s)" in printed
    assert "== The fixed build ==" in printed and "No verified violations observed" in printed
    for variant, status in (("vulnerable", "violations_verified"), ("fixed", "no_verified_violations")):
        folder = tmp_path / "promptproof-demo" / variant
        report = json.loads((folder / "scan.promptproof.json").read_text(encoding="utf-8"))
        assert report["status"] == status and (folder / "report.html").exists()
        assert report["authorization"]["authorized_by"] == "the promptproof demo command"
        assert report["authorization"]["live_tools"].startswith("none") and report["target_config"]["description_digest"]
        assert "recorded, never carried out" in (folder / "report.md").read_text(encoding="utf-8")
        check(tmp_path / "promptproof-demo" / f"{variant}.sealed.zip")
    # Nothing is left behind: no key in the environment, no authorization or target file on disk.
    assert pp.KEY_ENV not in os.environ and pp.LIVE_ENV not in os.environ
    assert sorted(p.name for p in tmp_path.iterdir()) == ["promptproof-demo"]


def test_the_live_demo_carries_out_small_refunds_and_stops_large_ones(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["demo", "--live", "--replays", "1", "--dir", "live"]) == 0
    printed = capsys.readouterr().out
    assert f"all within the cap of {LIVE_CAP}" in printed and "NOT all" not in printed
    stopped = int(printed.split("Tool calls stopped by the cap and kept as evidence: ")[1].split(".")[0])
    assert stopped > 0
    assert str((tmp_path / "live" / "vulnerable" / "report.html").resolve()) in printed  # a path that exists from anywhere
    report = (tmp_path / "live" / "vulnerable" / "report.md").read_text(encoding="utf-8")
    assert "ran for real within the caps" in report
    assert f"is outside the cap of 0 to {LIVE_CAP}" in report  # the attempt is evidence; nothing ran
    assert "Tools that could be carried out for real, inside the bot's own caps: issue" in report
    html = (tmp_path / "live" / "vulnerable" / "report.html").read_text(encoding="utf-8")
    assert "carried out for real" in html and "issue_refund" in html
    assert pp.LIVE_ENV not in os.environ


def test_the_demo_will_not_mix_with_old_reports(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "promptproof-demo").mkdir()
    (tmp_path / "promptproof-demo" / "old.txt").write_text("x", encoding="utf-8")
    assert main(["demo"]) == 2 and "not empty" in capsys.readouterr().out
