"""Identify likely hash formats without attempting to verify or crack them."""
from __future__ import annotations

import re

import rclib

MAX_INPUT_LENGTH = 4096

_HEX_CANDIDATES = {
    32: ["MD5", "MD4", "NTLM"],
    40: ["SHA-1", "RIPEMD-160"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "Whirlpool", "BLAKE2b"],
}

_STRUCTURED_FORMATS = (
    (re.compile(r"\$2[aby]\$(?:0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}"), "bcrypt"),
    (re.compile(r"\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}"), "md5crypt"),
    (re.compile(r"\$5\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}"), "sha256crypt"),
    (re.compile(r"\$6\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}"), "sha512crypt"),
    (re.compile(r"\$argon2(?:id|i|d)\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+"), "Argon2"),
)


def identify_hash(value: str) -> dict:
    """Return candidate formats and the evidence supporting the classification."""
    if len(value) > MAX_INPUT_LENGTH:
        return {
            "candidates": [],
            "basis": f"input exceeds the {MAX_INPUT_LENGTH}-character limit",
        }
    value = value.strip()
    if not value:
        return {"candidates": [], "basis": "empty input"}

    if re.fullmatch(r"\*[0-9A-Fa-f]{40}", value):
        return {"candidates": ["MySQL 4.1+"], "basis": "recognized prefix and structure"}

    for pattern, name in _STRUCTURED_FORMATS:
        if pattern.fullmatch(value):
            return {"candidates": [name], "basis": "recognized prefix and structure"}

    if re.fullmatch(r"[0-9A-Fa-f]+", value):
        candidates = _HEX_CANDIDATES.get(len(value), [])
        return {
            "candidates": candidates,
            "basis": (
                "hexadecimal encoding and length only; these candidates are ambiguous"
                if candidates
                else "hexadecimal encoding and unsupported length"
            ),
        }

    return {"candidates": [], "basis": "no supported format pattern matched"}


def run(ctx):
    value = ctx.target.strip()
    result = identify_hash(ctx.target)
    ctx.data.update(result)
    ctx.data["input_length"] = len(ctx.target)

    if len(ctx.target) > MAX_INPUT_LENGTH:
        ctx.warn(result["basis"])
        return 2
    if not result["candidates"]:
        ctx.warn(result["basis"])
        return 0

    ctx.good(f"{len(value)} characters; {result['basis']}")
    for candidate in result["candidates"]:
        ctx.finding(f"possible format: {candidate}", "info")
    return 0


if __name__ == "__main__":
    raise SystemExit(
        rclib.main(
            "hash-ident",
            "Identify likely hash formats",
            run,
            max_target_length=MAX_INPUT_LENGTH,
        )
    )
