"""Core SRI verification primitives.

This is the only implementation module. All public functions below are
implemented using the Python standard library only (hashlib, base64, re).
"""

import base64
import hashlib
import re

# Fixed strength order, strongest first. Weak/legacy digests (md5, sha1) are
# deliberately absent so they can never win a strength comparison.
_STRENGTH_ORDER = ("sha512", "sha384", "sha256")
_SUPPORTED_ALGORITHMS = frozenset(_STRENGTH_ORDER)

# One SRI metadata token: ALGORITHM-BASE64DIGEST with an optional ?OPTIONS
# suffix. Whitespace separates tokens, so it never appears inside a token; a
# semicolon is not a separator and simply makes the whole token malformed.
_TOKEN_RE = re.compile(
    r"^(?P<algorithm>[A-Za-z0-9]+)-(?P<digest>[A-Za-z0-9+/]+={0,2})"
    r"(?:\?(?P<options>.+))?$"
)

# scheme://host[:port] origin shape, used for policy and resource URLs.
_ORIGIN_RE = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<host>[^:/?#]+)"
    r"(?::(?P<port>\d+))?"
)

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}


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
    results = []
    if not isinstance(value, str):
        return results

    # Defect 1 fix: split on whitespace and keep every well formed token,
    # rather than returning only the first digest.
    for token in value.split():
        match = _TOKEN_RE.match(token)
        if match is None:
            continue

        algorithm = match.group("algorithm").lower()
        digest = match.group("digest")
        options = {}

        suffix = match.group("options")
        if suffix is not None:
            # Defect 2 fix: parse the ?key=value&... option suffix instead of
            # treating the suffixed token as malformed. A bare "?" with an
            # empty suffix is malformed, as are empty segments (e.g. "a=b&&c").
            valid_suffix = True
            for pair in suffix.split("&"):
                if not pair:
                    valid_suffix = False
                    break
                name, sep, opt_value = pair.partition("=")
                if not name:
                    valid_suffix = False
                    break
                # A bare option (no "=") maps to the empty string; repeated
                # option names keep the last value.
                options[name] = opt_value if sep else ""
            if not valid_suffix:
                continue

        results.append(
            {
                "algorithm": algorithm,
                "digest": digest,
                "options": options,
            }
        )

    return results


def strongest(algorithms: list[str]) -> str:
    """Return the strongest supported algorithm from algorithms.

    Strength order is sha512, then sha384, then sha256, independent of input
    order, string length or spelling case. Unsupported and weak names such as
    md5 and sha1 are ignored. Raise ValueError when algorithms contains no
    supported name, including when it is empty.
    """
    # Defect 3 fix: consult a fixed strength table instead of comparing string
    # lengths. Defect 4 fix: the table contains no weak algorithms, so names
    # like md5/sha1 can never be selected.
    present = {name.lower() for name in algorithms if isinstance(name, str)}
    for candidate in _STRENGTH_ORDER:
        if candidate in present:
            return candidate
    raise ValueError("no supported algorithm present")


def compute_digest(data: bytes, algorithm: str) -> str:
    """Compute an SRI digest and return standard base64 text.

    data is bytes-like. algorithm is case-insensitive and must be sha256,
    sha384 or sha512. The output uses the RFC 4648 standard alphabet and all
    required equals-sign padding, exactly as SRI compares it. Comparison
    tolerance is zero: no prefix match, rounding or alternate encoding is
    accepted. Raise ValueError for an unsupported algorithm or non-bytes data.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError("data must be bytes-like")
    if not isinstance(algorithm, str):
        raise ValueError("unsupported algorithm")

    name = algorithm.lower()
    if name not in _SUPPORTED_ALGORITHMS:
        raise ValueError(f"unsupported algorithm: {algorithm!r}")

    hasher = hashlib.new(name)
    hasher.update(bytes(data))
    # Defect 6 fix: base64.b64encode always emits the full RFC 4648 alphabet
    # with the required "=" padding, matching standard SRI digest text.
    return base64.b64encode(hasher.digest()).decode("ascii")


def _constant_time_equal(left: bytes, right: bytes) -> bool:
    """Compare two byte strings without ordinary equality or early exit."""
    # The length check cannot be made constant time, but it never compares
    # individual bytes and no per-byte shortcut is taken afterwards.
    if len(left) != len(right):
        return False
    difference = 0
    for left_byte, right_byte in zip(left, right):
        difference |= left_byte ^ right_byte
    return difference == 0


def verify_one(token: dict, data: bytes) -> bool:
    """Verify one parsed metadata token against bytes.

    token is a mapping with algorithm, digest and options as returned by
    parse_integrity. Return True only when the recomputed digest equals the
    token digest. Compare the complete decoded digest values in constant time;
    do not use ordinary equality and do not exit per byte. Tolerance is zero:
    every digest byte must match. Invalid tokens, unsupported algorithms and
    malformed base64 return False. Options never relax the digest comparison.
    """
    try:
        algorithm = token["algorithm"]
        digest_text = token["digest"]
        token["options"]
    except (TypeError, KeyError):
        return False

    if not isinstance(algorithm, str) or not isinstance(digest_text, str):
        return False
    name = algorithm.lower()
    if name not in _SUPPORTED_ALGORITHMS:
        return False

    try:
        # Strict decoding: missing padding, stray characters or non-base64
        # text raise instead of being silently truncated. binascii.Error is a
        # ValueError subclass, so ValueError covers every decoding failure.
        expected = base64.b64decode(digest_text, validate=True)
    except (ValueError, TypeError):
        return False

    actual = base64.b64decode(compute_digest(data, name), validate=True)

    # Defect 5 fix: compare every byte without "==" and without short
    # circuiting, so no ordinary string equality is used on the digest.
    return _constant_time_equal(actual, expected)


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
    if not isinstance(value, str) or not value.strip():
        return {
            "valid": False,
            "algorithm": None,
            "checked": 0,
            "reason": "empty",
        }

    tokens = parse_integrity(value)
    if not tokens:
        # Non-empty attribute whose tokens are all malformed.
        return {
            "valid": False,
            "algorithm": None,
            "checked": 0,
            "reason": "malformed",
        }

    try:
        selected = strongest([token["algorithm"] for token in tokens])
    except ValueError:
        # Well formed tokens exist, but none name a supported algorithm.
        return {
            "valid": False,
            "algorithm": None,
            "checked": 0,
            "reason": "unsupported",
        }

    # Defect 7 fix: only tokens at the strongest supported algorithm are
    # evaluated; a matching weaker token can never make valid True.
    strongest_tokens = [
        token for token in tokens if token["algorithm"] == selected
    ]
    matched = any(verify_one(token, data) for token in strongest_tokens)

    return {
        "valid": matched,
        "algorithm": selected,
        "checked": len(strongest_tokens),
        "reason": "ok" if matched else "mismatch",
    }


def _parse_origin(origin: str):
    """Split an origin into (scheme, host, normalized port) or None."""
    if not isinstance(origin, str):
        return None
    match = _ORIGIN_RE.match(origin)
    if match is None:
        return None

    scheme = match.group("scheme").lower()
    host = match.group("host").lower()
    port_text = match.group("port")
    if port_text is not None:
        port = int(port_text)
    else:
        port = _DEFAULT_PORTS.get(scheme)
    return scheme, host, port


def requires_credentials(url: str, policy: dict) -> bool:
    """Return True when a resource URL needs a credentials restricted mode.

    policy has an origin key with the document origin. Compare scheme, host
    and port; any difference makes url cross-origin. Every cross-origin
    resource must use a credentials restricted mode, even if the policy lists
    its origin as allowed, so return True. Same-origin URLs return False.
    Raise ValueError if policy does not provide a usable origin.
    """
    try:
        document_origin = policy["origin"]
    except (TypeError, KeyError):
        raise ValueError("policy must provide an origin") from None

    document = _parse_origin(document_origin)
    if document is None:
        raise ValueError("policy origin is not usable")

    resource = _parse_origin(url)
    if resource is None:
        # Fail closed: an unparseable location cannot be proven same-origin.
        return True

    # Defect 8 fix: any scheme/host/port difference forces the credentials
    # restricted mode; allow lists never exempt a cross-origin resource.
    return resource != document


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
    problems = []
    # Defect 9 fix: the missing-integrity flag is inspected alongside the
    # other two instead of being silently skipped.
    if policy.get("allow_weak_algorithms"):
        problems.append("weak_algorithms_allowed")
    if policy.get("allow_missing_integrity"):
        problems.append("missing_integrity_allowed")
    if policy.get("allow_any_cross_origin"):
        problems.append("arbitrary_cross_origin_allowed")
    return problems


def resource_batch(resources: list[dict], policy: dict) -> dict:
    """Verify a batch of resources independently under policy.

    resources is a sequence of mappings with url, integrity and content.
    Return a dict keyed by url. Each value is the verify_attribute result for
    that resource plus credentials_required from requires_credentials. Every
    resource is parsed and verified from its own content; no digest, token or
    result may be cached or reused across resources. URLs must be unique;
    raise ValueError on a duplicate. Preserve input order.
    """
    results = {}
    for resource in resources:
        url = resource["url"]
        if url in results:
            raise ValueError(f"duplicate resource url: {url!r}")

        # Defect 10 fix: each resource is parsed and verified afresh from its
        # own content; nothing computed for an earlier resource is consulted.
        result = dict(
            verify_attribute(resource["integrity"], resource["content"])
        )
        result["credentials_required"] = requires_credentials(url, policy)
        results[url] = result

    return results
