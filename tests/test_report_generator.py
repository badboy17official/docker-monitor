import os
import json
import pytest
from pathlib import Path
from report_generator import ReportGenerator

def test_generate_json_report(tmp_path):
    generator = ReportGenerator(output_dir=str(tmp_path))
    data = {"vulnerable": {"critical": 5}, "hardened": {"critical": 1}, "comparison": {}}
    filepath = generator.generate_json_report(data, filename="test.json")
    
    assert Path(filepath).exists()
    with open(filepath, 'r') as f:
        loaded = json.load(f)
        assert loaded["vulnerable"]["critical"] == 5

def test_generate_html_report(tmp_path):
    generator = ReportGenerator(output_dir=str(tmp_path))
    data = {"vulnerable": {"critical": 5}, "hardened": {"critical": 1}, "comparison": {}}
    filepath = generator.generate_html_report(data, filename="test.html")
    
    assert Path(filepath).exists()
    with open(filepath, 'r') as f:
        content = f.read()
        assert "<html" in content.lower()
        assert "Executive Summary" in content

def test_update_history(tmp_path):
    generator = ReportGenerator(output_dir=str(tmp_path))
    data = {"vulnerable": {"critical": 5}}
    generator.update_history(data)
    
    history_file = tmp_path / "audit_history.json"
    assert history_file.exists()
    with open(history_file, 'r') as f:
        history = json.load(f)
        assert len(history) == 1
        assert history[0]["vulnerable"]["critical"] == 5
        assert "timestamp" in history[0]
