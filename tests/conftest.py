import json
from pathlib import Path

import pytest

from cloudoyabun.db import Database
from cloudoyabun.service import Service


@pytest.fixture
def service(tmp_path):
    return Service(Database(tmp_path / "assessment.sqlite3"))


@pytest.fixture
def assessment(service):
    return service.create_assessment("Test assessment", "Synthetic resources only")


@pytest.fixture
def content():
    return (Path(__file__).parents[1] / "cloudoyabun/fixtures/demo.ocsf.json").read_bytes()


@pytest.fixture
def record(content):
    return json.loads(content)[0]
