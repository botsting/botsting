"""`promptproof ci`: one command for a build pipeline. Uses the built-in practice bots only."""

import pytest

from promptproof.cli import main
from promptproof.seal import check


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "output.txt"))
    return tmp_path


def outputs(folder) -> dict[str, str]:
    lines = (folder / "output.txt").read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines)


def test_a_vulnerable_bot_fails_the_build_and_leaves_sealed_evidence(pipeline):
    assert main(["ci", "--target", "toy:vulnerable", "--replays", "1"]) == 1
    out = outputs(pipeline)
    assert out["status"] == "violations_verified" and int(out["findings"]) > 0
    for name in ("scan.promptproof.json", "report.md", "report.html"):
        assert (pipeline / "promptproof-report" / name).exists()
    manifest = check(pipeline / out["bundle"], out["seal"])
    assert len(manifest["files"]) == 3
    summary = (pipeline / "summary.md").read_text(encoding="utf-8")
    assert summary.startswith("## Promptproof: ") and "proven finding(s)" in summary and out["seal"] in summary


def test_a_fixed_bot_passes(pipeline):
    assert main(["ci", "--target", "toy:fixed", "--replays", "1", "--dir", "out"]) == 0
    out = outputs(pipeline)
    assert out["status"] == "no_verified_violations" and out["findings"] == "0"
    assert "no verified violations" in (pipeline / "summary.md").read_text(encoding="utf-8")
    check(pipeline / "out.sealed.zip", out["seal"])


def test_fail_on_never_reports_without_failing(pipeline):
    assert main(["ci", "--target", "toy:vulnerable", "--replays", "1", "--fail-on", "never"]) == 0
    assert outputs(pipeline)["status"] == "violations_verified"


def test_a_scan_that_could_not_run_never_looks_green(pipeline, capsys):
    assert main(["ci", "--target", "http:nothing-here"]) == 2
    assert "NOT RUN. Nothing was tested" in capsys.readouterr().out
    assert outputs(pipeline)["status"] == "not_run"
    assert main(["ci", "--target", "http:nothing-here", "--fail-on", "inconclusive", "--dir", "second"]) == 2
    assert main(["ci", "--target", "http:nothing-here", "--fail-on", "never", "--dir", "third"]) == 0


def test_an_inconclusive_scan_is_said_to_be_not_clean(pipeline, capsys, monkeypatch):
    from promptproof import cli

    real = cli._scan

    def inconclusive(args):
        real(args)  # writes real reports
        return cli.EXIT_INCONCLUSIVE

    monkeypatch.setattr(cli, "_scan", inconclusive)
    assert main(["ci", "--target", "toy:fixed", "--replays", "1"]) == 0  # the default fails only on proven findings
    assert "INCONCLUSIVE. This is not a clean result" in capsys.readouterr().out
    assert main(["ci", "--target", "toy:fixed", "--replays", "1", "--fail-on", "inconclusive", "--dir", "second"]) == 2


def test_old_evidence_is_never_mixed_in(pipeline, capsys):
    (pipeline / "promptproof-report").mkdir()
    (pipeline / "promptproof-report" / "old.md").write_text("an earlier run", encoding="utf-8")
    assert main(["ci", "--target", "toy:fixed"]) == 2
    assert "not empty" in capsys.readouterr().err


def test_it_works_outside_github(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    assert main(["ci", "--target", "toy:fixed", "--replays", "1"]) == 0
    assert (tmp_path / "promptproof-report.sealed.zip").exists()
