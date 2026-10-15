"""Run with the pinned real regex package in the server's isolated environment.

No network, model, package installation, or real message delivery is performed.
The original policy/transport regressions remain in test_korean_output_guard.py.
"""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "capstone_korean_output_guard_engine_test", Path(__file__).with_name("korean_output_guard.py"))
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class PackageEngineTests(unittest.TestCase):
    def test_real_pinned_compiled_package_is_the_detector(self):
        self.assertIsInstance(MOD._CJK, MOD._UNICODE.Pattern)
        self.assertIsInstance(MOD._CJK_RUNS, MOD._UNICODE.Pattern)
        self.assertEqual(MOD.detector_metadata()["version"], MOD.ENGINE_VERSION)
        self.assertEqual(MOD.detector_metadata()["backend"], "regex._regex")
        self.assertIn(r"\p{Script=Han}", MOD._CJK.pattern)

    def test_unicode_properties_cover_new_han_and_shared_kana_marks(self):
        # U+33400 is beyond the old handwritten Han range ending at U+323FF.
        for text in ("\U00033400", "\u3099", "\u309a", "\u30fc", "\uff70", "\uff9e", "\uff9f"):
            with self.subTest(codepoint=ord(text)):
                self.assertIsNotNone(MOD._CJK.fullmatch(text))

    def test_common_punctuation_hangul_and_emoji_are_not_foreign_letters(self):
        for text in ("정상 한국어 가 ㄱ", "API 211.170.162.111:11434 pending", "。、「」・", "✅ 🐱 😀"):
            with self.subTest(text=text):
                self.assertIsNone(MOD._CJK.search(text))

    def test_missing_dependency_refuses_initialization_without_stdlib_fallback(self):
        with patch.object(MOD, "import_module", side_effect=ModuleNotFoundError("private details")):
            with self.assertRaisesRegex(RuntimeError, "^guard_unicode_engine_unavailable$"):
                MOD._load_unicode_engine()

    def test_unreviewed_version_refuses_initialization(self):
        fake = SimpleNamespace(__version__="0.0.0", __file__="/not/a/backend.so")
        with patch.object(MOD, "import_module", return_value=fake):
            with self.assertRaisesRegex(RuntimeError, "^guard_unicode_engine_version$"):
                MOD._load_unicode_engine()


class PackagePolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_new_unicode_character_uses_existing_fragment_repair_policy(self):
        calls = []

        async def repair(text):
            calls.append(text)
            return text.replace("\U00033400", "확인")

        original = "상태: \U00033400\nIP=211.170.162.111:11434 pending count=3"
        with MOD.turn_context("현재 상태를 알려줘"):
            result = await MOD.guard_text(original, rewrite=repair)
        self.assertEqual(result, original.replace("\U00033400", "확인"))
        self.assertEqual(len(calls), 1)

    async def test_new_unicode_verified_quote_and_explicit_request_are_preserved(self):
        text = "`\U00033400`"

        async def unexpected(_text):
            self.fail("verified or explicitly requested text must not call repair")

        with MOD.turn_context("원문을 보여줘"):
            MOD.set_turn_evidence([{"role": "user", "content": "원문을 보여줘"},
                                   {"role": "tool", "content": text}])
            self.assertEqual(await MOD.guard_text(text, rewrite=unexpected), text)
        with MOD.turn_context("이 문장을 중국어로 출력해줘: 확인"):
            self.assertEqual(await MOD.guard_text(text, rewrite=unexpected), text)
        with MOD.turn_context("현재 상태를 알려줘"):
            self.assertEqual(await MOD.guard_text(text, rewrite=unexpected), MOD.FALLBACK_NOTICE)

    async def test_new_unicode_in_bare_identifier_is_not_translated_as_prose(self):
        text = "경로: /srv/\U00033400/config.yaml"

        async def unexpected(_text):
            self.fail("an identifier must be retained by evidence or rejected, never rewritten")

        with MOD.turn_context("경로를 알려줘"):
            self.assertEqual(await MOD.guard_text(text, rewrite=unexpected), MOD.FALLBACK_NOTICE)
            MOD.set_turn_evidence([{"role": "user", "content": "경로를 알려줘"},
                                   {"role": "tool", "content": text}])
            self.assertEqual(await MOD.guard_text(text, rewrite=unexpected), text)

    async def test_unassigned_codepoint_is_not_guessed_to_be_han(self):
        # The former U+20000..U+2FFFF range also matched unassigned U+2FFFF.
        text = "원본 기호: \U0002ffff"
        with MOD.turn_context("상태를 알려줘"):
            self.assertEqual(await MOD.guard_text(text), text)


if __name__ == "__main__":
    unittest.main()
