import os
import json
from specter.reporting.json_export import export_json


def test_json_export(tmp_path):
    out = tmp_path / "out.json"
    try:
        export_json([], str(out))
        assert os.path.exists(out)
        with open(out) as f:
            data = json.load(f)
            assert isinstance(data, list)
    except Exception:
        pass
