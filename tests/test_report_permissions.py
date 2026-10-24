import os

import pytest

from cloudoyabun.cli import main


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission semantics")
@pytest.mark.parametrize("existing", [False, True])
def test_cli_report_is_private_even_when_replacing_public_file(service, assessment, content, tmp_path, existing):
    service.import_artifact(assessment["id"], "scan.json", content)
    finding = service.findings(assessment["id"])["items"][0]
    service.triage(finding["id"], {"selected": True}, 0)
    destination = tmp_path / "report.md"
    if existing:
        destination.write_text("old public report")
        destination.chmod(0o644)
    previous = os.umask(0o022)
    try:
        assert main(["--db", str(service.db.path), "report", assessment["id"], "--output", str(destination)]) == 0
    finally:
        os.umask(previous)
    assert destination.stat().st_mode & 0o777 == 0o600
    assert "Technical assessment report" in destination.read_text()
    assert not list(tmp_path.glob(".cloudoyabun-report-*"))
