"""Explicit parser registry; additional tools can supply independent adapters."""

from .prowler import ProwlerOCSF
from .kubescape import KubescapeJSON
from .common import load_json

PARSERS = {"prowler-ocsf": ProwlerOCSF(), "kubescape-json": KubescapeJSON()}


def detect_parser(content):
    doc = load_json(content)
    if isinstance(doc, list):
        if not doc or any(isinstance(r, dict) and isinstance(r.get("metadata"), dict) and
                          isinstance(r["metadata"].get("product"), dict) and
                          str(r["metadata"]["product"].get("name", "")).lower() == "prowler" for r in doc):
            return "prowler-ocsf"
    if isinstance(doc, dict):
        if isinstance(doc.get("meta"), dict) and doc["meta"].get("type") == "azure":
            raise ValueError("AzureHound is collection-only. Import its JSON into BloodHound, not CloudOyabun.")
        if isinstance(doc.get("summaryDetails"), dict):
            return "kubescape-json"
    raise ValueError("Could not identify the tool output. Choose prowler-ocsf or kubescape-json explicitly.")
