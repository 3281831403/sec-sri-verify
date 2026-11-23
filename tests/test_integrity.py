import pytest

from sri import (
    compute_digest,
    parse_integrity,
    requires_credentials,
    resource_batch,
    strongest,
    validate_policy,
    verify_attribute,
    verify_one,
)

SHA256_HELLO = "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="
SHA256_GOOD = "dw5gdiTWiSZcpsRIhNCAfZsFTSPEc8EGxyvp3gi3N2w="
SHA384_HELLO = "WeF0h3dEjGnea4ANejO7+5/xtGPkQ1TDVTvNucZm+pASWjx5+QOXvfX2oT3oKGhP"
SHA384_GOOD = "w/3ZqVJ6tDRolbwMeN5KgbVrhGR5rqZPS4ix7+dF1s2baxP5JgOAi2sulngCwQxO"
SHA384_EVIL = "45xktjF1r7NysKRxgzmD2MgqMokr2sXBVdzPIkh44sTSpGY5or0XiGpuMJwuMWQr"
SHA512_HELLO = (
    "m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXa"
    "DEZjR1wuXDre9G9zvN7AQw=="
)
SHA512_GOOD = (
    "ECWb/hpBBY5GcdBaO5Yrd0xLFpRrQEC8BVBZ0YWdXxXsTX8Byj91YWMtAK3WEi0zc"
    "CKhURdOW5zr9DAlS46fpw=="
)
MD5_HELLO = "XUFAKrxLKna5cZ2REBfFkg=="


class _EqualitySpy(str):
    """A string that records ordinary equality checks against it."""

    def __new__(cls, value):
        instance = super().__new__(cls, value)
        instance.eq_calls = 0
        return instance

    def __eq__(self, other):
        self.eq_calls += 1
        return super().__eq__(other)

    __hash__ = str.__hash__


def test_defect_01_parse_keeps_all_digests():
    parsed = parse_integrity(
        f"sha384-{SHA384_HELLO} sha256-{SHA256_HELLO} sha512-{SHA512_HELLO}"
    )
    assert [item["algorithm"] for item in parsed] == ["sha384", "sha256", "sha512"]
    assert [item["digest"] for item in parsed] == [
        SHA384_HELLO,
        SHA256_HELLO,
        SHA512_HELLO,
    ]


def test_defect_02_parse_handles_options():
    parsed = parse_integrity(
        f"sha384-{SHA384_HELLO}?report=block&mode=strict"
    )
    assert len(parsed) == 1
    assert parsed[0]["algorithm"] == "sha384"
    assert parsed[0]["digest"] == SHA384_HELLO
    assert parsed[0]["options"] == {"report": "block", "mode": "strict"}


def test_defect_03_strength_uses_algorithm_not_length():
    assert strongest(["sha256", "sha512"]) == "sha512"
    assert strongest(["sha512", "sha256"]) == "sha512"
    assert strongest(["sha384", "sha256"]) == "sha384"


def test_defect_04_weak_algorithm_cannot_win():
    assert strongest(["md5", "sha256"]) == "sha256"
    assert strongest(["sha1", "sha384"]) == "sha384"
    with pytest.raises(ValueError):
        strongest(["md5", "sha1"])


def test_defect_05_verify_one_uses_constant_time_compare():
    matching = _EqualitySpy(SHA384_HELLO)
    token = {"algorithm": "sha384", "digest": matching, "options": {}}
    assert verify_one(token, b"hello") is True
    assert matching.eq_calls == 0

    mismatching = _EqualitySpy(SHA384_HELLO[:-2] + "AA")
    token = {"algorithm": "sha384", "digest": mismatching, "options": {}}
    assert verify_one(token, b"hello") is False
    assert mismatching.eq_calls == 0


def test_defect_06_compute_digest_has_standard_padding():
    assert compute_digest(b"hello", "sha256") == SHA256_HELLO
    assert compute_digest(b"hello", "sha384") == SHA384_HELLO
    assert compute_digest(b"hello", "sha512") == SHA512_HELLO
    assert compute_digest(b"hello", "SHA256") == SHA256_HELLO
    assert SHA256_HELLO.endswith("=")
    assert SHA512_HELLO.endswith("==")


def test_defect_07_only_strongest_digest_can_pass():
    value = f"sha512-{SHA512_HELLO} sha256-{SHA256_GOOD}"
    result = verify_attribute(value, b"good")
    assert result["valid"] is False
    assert result["algorithm"] == "sha512"
    assert result["checked"] == 1
    assert result["reason"] == "mismatch"


def test_defect_08_cross_origin_requires_credentials():
    policy = {
        "origin": "https://app.example",
        "allowed_cross_origins": ["https://cdn.example"],
        "allow_any_cross_origin": False,
    }
    assert requires_credentials("https://cdn.example/app.js", policy) is True
    assert requires_credentials("https://app.example/app.js?v=1", policy) is False
    assert requires_credentials("http://app.example/app.js", policy) is True
    assert requires_credentials("https://app.example:8443/app.js", policy) is True


def test_defect_09_policy_flags_missing_integrity():
    policy = {
        "allow_weak_algorithms": False,
        "allow_missing_integrity": True,
        "allow_any_cross_origin": False,
    }
    assert validate_policy(policy) == ["missing_integrity_allowed"]


def test_defect_10_batch_does_not_reuse_previous_digest():
    policy = {"origin": "https://app.example"}
    resources = [
        {
            "url": "https://app.example/a.js",
            "integrity": f"sha384-{SHA384_GOOD}",
            "content": b"good",
        },
        {
            "url": "https://app.example/b.js",
            "integrity": f"sha384-{SHA384_GOOD}",
            "content": b"evil",
        },
    ]
    results = resource_batch(resources, policy)
    assert results["https://app.example/a.js"]["valid"] is True
    assert results["https://app.example/b.js"]["valid"] is False


def test_correct_digest_passes():
    parsed = parse_integrity(f"sha384-{SHA384_HELLO}")
    assert verify_one(parsed[0], b"hello") is True


def test_tampered_content_fails():
    parsed = parse_integrity(f"sha384-{SHA384_HELLO}")
    assert verify_one(parsed[0], b"hello!") is False


def test_weak_algorithm_is_rejected():
    parsed = parse_integrity(f"md5-{MD5_HELLO}")
    assert parsed[0]["algorithm"] == "md5"
    assert verify_one(parsed[0], b"hello") is False
    result = verify_attribute(f"md5-{MD5_HELLO}", b"hello")
    assert result["valid"] is False
    assert result["algorithm"] is None
    assert result["checked"] == 0
    assert result["reason"] == "unsupported"


def test_multiple_digests_only_strongest_counts():
    value = f"sha512-{SHA512_GOOD} sha384-{SHA384_HELLO}"
    result = verify_attribute(value, b"good")
    assert result["valid"] is True
    assert result["algorithm"] == "sha512"
    assert result["checked"] == 1
    assert result["reason"] == "ok"


def test_batches_match_individual_checks():
    policy = {
        "origin": "https://app.example",
        "allowed_cross_origins": ["https://cdn.example"],
        "allow_weak_algorithms": False,
        "allow_missing_integrity": False,
        "allow_any_cross_origin": False,
    }
    resources = [
        {
            "url": "https://app.example/a.js",
            "integrity": f"sha384-{SHA384_GOOD}",
            "content": b"good",
        },
        {
            "url": "https://cdn.example/b.js",
            "integrity": f"sha384-{SHA384_EVIL}",
            "content": b"evil",
        },
        {
            "url": "https://cdn.example/c.js",
            "integrity": f"sha384-{SHA384_GOOD}",
            "content": b"evil",
        },
    ]
    first = resource_batch(resources, policy)
    second = resource_batch(resources, policy)
    assert first == second

    for resource in resources:
        single = verify_attribute(resource["integrity"], resource["content"])
        batch_entry = first[resource["url"]]
        assert batch_entry["valid"] == single["valid"]
        assert batch_entry["algorithm"] == single["algorithm"]
        assert batch_entry["checked"] == single["checked"]
        assert batch_entry["reason"] == single["reason"]
        assert batch_entry["credentials_required"] == requires_credentials(
            resource["url"], policy
        )