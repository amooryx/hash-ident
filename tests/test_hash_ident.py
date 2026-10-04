import unittest
from contextlib import redirect_stderr
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

import rclib
from hash_ident import MAX_INPUT_LENGTH, identify_hash, run


class HashIdentificationTests(unittest.TestCase):
    def test_hex_digest_lengths_are_ambiguous_candidates(self):
        result = identify_hash("a" * 64)
        self.assertEqual(result["candidates"], ["SHA-256", "SHA3-256", "BLAKE2s"])
        self.assertIn("ambiguous", result["basis"])

    def test_unprefixed_length_does_not_claim_a_single_algorithm(self):
        result = identify_hash("A" * 40)
        self.assertEqual(result["candidates"], ["SHA-1", "RIPEMD-160"])
        self.assertIn("length only", result["basis"])

    def test_recognizes_mysql_prefix_structure(self):
        self.assertEqual(
            identify_hash("*" + "A" * 40)["candidates"],
            ["MySQL 4.1+"],
        )

    def test_recognizes_structured_hash_formats(self):
        samples = (
            ("$2b$12$" + "A" * 53, "bcrypt"),
            ("$1$salt$" + "A" * 22, "md5crypt"),
            ("$5$salt$" + "A" * 43, "sha256crypt"),
            ("$6$salt$" + "A" * 86, "sha512crypt"),
            ("$argon2id$v=19$m=65536,t=2,p=1$c2FsdA$aGFzaA", "Argon2"),
        )
        for value, expected in samples:
            with self.subTest(expected=expected):
                self.assertEqual(identify_hash(value)["candidates"], [expected])

    def test_malformed_structured_formats_are_not_guessed(self):
        self.assertEqual(identify_hash("$2b$99$" + "A" * 53)["candidates"], [])
        self.assertEqual(identify_hash("$6$salt$short")["candidates"], [])

    def test_rejects_inputs_over_the_limit_including_whitespace(self):
        result = identify_hash(" " * (MAX_INPUT_LENGTH + 1))
        self.assertEqual(result["candidates"], [])
        self.assertIn("exceeds", result["basis"])

    def test_run_surfaces_input_limit_as_an_error(self):
        messages = []
        ctx = SimpleNamespace(
            target="x" * (MAX_INPUT_LENGTH + 1),
            data={},
            warn=messages.append,
            good=messages.append,
            finding=lambda *args, **kwargs: self.fail("unexpected finding"),
        )
        self.assertEqual(run(ctx), 2)
        self.assertEqual(ctx.data["input_length"], MAX_INPUT_LENGTH + 1)
        self.assertIn("exceeds", messages[0])

    def test_cli_rejects_oversized_target_before_authorization(self):
        stderr = StringIO()
        with patch("sys.argv", ["hash-ident", "too-long"]), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as result:
                rclib.main(
                    "hash-ident",
                    "test",
                    lambda ctx: self.fail("run must not be called"),
                    max_target_length=3,
                )
        self.assertEqual(result.exception.code, 2)
        self.assertIn("at most 3 characters", stderr.getvalue())

    def test_empty_and_unsupported_input_are_unrecognized(self):
        self.assertEqual(identify_hash("  ")["candidates"], [])
        self.assertEqual(identify_hash("not-a-hash")["candidates"], [])


if __name__ == "__main__":
    unittest.main()
