from __future__ import annotations

import pytest
from tools.check_licenses import LicenseGateError, check_records


def test_许可证_allowlist_接受_0bsd_别名和合法表达式() -> None:
    records = [
        {"Name": "chardet", "Version": "5.0", "License": "0BSD"},
        {"Name": "demo", "Version": "1.0", "License": "MIT OR Apache-2.0"},
        {"Name": "alias", "Version": "1.0", "License": "MIT License"},
    ]
    checked = check_records(records)
    assert checked[0]["licenses"] == ["0BSD"]
    assert checked[1]["licenses"] == ["MIT", "Apache-2.0"]


@pytest.mark.parametrize("license_value", ["unknown", "custom", "GPL-3.0-only", "MIT; BSD"])
def test_许可证门拒绝未知或未批准值(license_value: str) -> None:
    records = [{"Name": "bad", "Version": "1.0", "License": license_value}]
    with pytest.raises(LicenseGateError):
        check_records(records)


def test_许可证记录缺字段时拒绝() -> None:
    with pytest.raises(LicenseGateError, match="缺少"):
        check_records([{"Name": "bad", "Version": "1.0"}])


def test_锁定旧包的宽泛_bsd_元数据使用版本绑定映射() -> None:
    records = [{"Name": "Jinja2", "Version": "3.1.6", "License": "BSD License"}]

    assert check_records(records)[0]["licenses"] == ["BSD-3-Clause"]


def test_未知包的宽泛_bsd_元数据继续_fail_closed() -> None:
    records = [{"Name": "other", "Version": "1.0", "License": "BSD License"}]

    with pytest.raises(LicenseGateError):
        check_records(records)
