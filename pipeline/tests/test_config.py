"""Smoke tests for config.json validity (C1)."""
import json


def test_config_json_is_valid():
    """C1: config.json must be parseable by stdlib json."""
    with open("config.json", encoding="utf-8") as f:
        cfg = json.load(f)
    assert "products" in cfg
    assert "scoring" in cfg
    assert "filter" in cfg
    assert isinstance(cfg["products"], dict)


def test_config_products_have_required_fields():
    """Each product must have url and scanners."""
    with open("config.json", encoding="utf-8") as f:
        cfg = json.load(f)
    for pid, prod in cfg["products"].items():
        assert "url" in prod, f"{pid} missing url"
        assert "scanners" in prod, f"{pid} missing scanners"
        assert isinstance(prod["scanners"], dict), f"{pid} scanners must be dict"
