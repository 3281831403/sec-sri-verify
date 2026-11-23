"""Core SRI verification primitives.

This is the only implementation module. All public functions below are stubs;
each one must be implemented using the Python standard library only.
"""


def parse_integrity(value: str) -> list[dict]:
    """Parse a Subresource Integrity attribute.

    Integrity metadata is a whitespace separated sequence of tokens. A token
    has the shape ALGORITHM-BASE64DIGEST with an optional question mark and
    OPTION suffix. The suffix contains key=value pairs separated by an
    ampersand. Every well formed token is returned, including tokens that use
    weak algorithms; malformed tokens are skipped. A semicolon is neither a
    digest separator nor an option separator.

    Each result is a dict with exactly these keys:
    algorithm: lowercase algorithm name
    digest: base64 digest text, padding preserved
    options: dict of option names to values, empty when no suffix exists

    If an option name repeats, the last value wins. A bare option without an
    equals sign maps to the empty string. An empty or all malformed attribute
    returns an empty list.
    """
    raise NotImplementedError("parse_integrity")


def strongest(algorithms: list[str]) -> str:
    """Return the strongest supported algorithm from algorithms.

    Strength order is sha512, then sha384, then sha256, independent of input
    order, string length or spelling case. Unsupported and weak names such as
    md5 and sha1 are ignored. Raise ValueError when algorithms contains no
    supported name, including when it is empty.
    """
    raise NotImplementedError("strongest")


def compute_digest(data: bytes, algorithm: str) -> str:
    """Compute an SRI digest and return standard base64 text.

    data is bytes-like. algorithm is case-insensitive and must be sha256,
    sha384 or sha512. The output uses the RFC 4648 standard alphabet and all
    required equals-sign padding, exactly as SRI compares it. Comparison
    tolerance is zero: no prefix match, rounding or alternate encoding is
    accepted. Raise ValueError for an unsupported algorithm or non-bytes data.
    """
    raise NotImplementedError("compute_digest")


def verify_one(token: dict, data: bytes) -> bool:
    """Verify one parsed metadata token against bytes.

    token is a mapping with algorithm, digest and options as returned by
    parse_integrity. Return True only when the recomputed digest equals the
    token digest. Compare the complete decoded digest values in constant time;
    do not use ordinary equality and do not exit per byte. Tolerance is zero:
    every digest byte must match. Invalid tokens, unsupported algorithms and
    malformed base64 return False. Options never relax the digest comparison.
    """
    raise NotImplementedError("verify_one")


def verify_attribute(value: str, data: bytes) -> dict:
    """Verify a complete integrity attribute against bytes.

    Parse value, select the strongest supported algorithm present and check
    only tokens using that algorithm. Return a dict with these keys:
    valid: True when at least one strongest algorithm token matches
    algorithm: selected algorithm name or None
    checked: number of strongest algorithm tokens evaluated
    reason: one of ok, empty, unsupported, malformed or mismatch

    A match from a weaker algorithm never makes valid True, and a weaker match
    cannot rescue a mismatch of every strongest token. Tolerance is zero for
    every strongest token. Unknown options do not relax verification. Never
    raise for malformed attribute input.
    """
    raise NotImplementedError("verify_attribute")


def requires_credentials(url: str, policy: dict) -> bool:
    """Return True when a resource URL needs a credentials restricted mode.

    policy has an origin key with the document origin. Compare scheme, host
    and port; any difference makes url cross-origin. Every cross-origin
    resource must use a credentials restricted mode, even if the policy lists
    its origin as allowed, so return True. Same-origin URLs return False.
    Raise ValueError if policy does not provide a usable origin.
    """
    raise NotImplementedError("requires_credentials")


def validate_policy(policy: dict) -> list[str]:
    """Return security problems in a policy as machine readable codes.

    Inspect allow_weak_algorithms, allow_missing_integrity and
    allow_any_cross_origin. Append one code for each true flag in this order:
    weak_algorithms_allowed
    missing_integrity_allowed
    arbitrary_cross_origin_allowed
    Missing flags count as false. A secure policy returns an empty list. Do not
    mutate the input policy.
    """
    raise NotImplementedError("validate_policy")


def resource_batch(resources: list[dict], policy: dict) -> dict:
    """Verify a batch of resources independently under policy.

    resources is a sequence of mappings with url, integrity and content.
    Return a dict keyed by url. Each value is the verify_attribute result for
    that resource plus credentials_required from requires_credentials. Every
    resource is parsed and verified from its own content; no digest, token or
    result may be cached or reused across resources. URLs must be unique;
    raise ValueError on a duplicate. Preserve input order.
    """
    raise NotImplementedError("resource_batch")