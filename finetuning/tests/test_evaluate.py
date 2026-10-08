"""No network calls or model dependencies; all endpoint responses are mocked."""

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError


SPEC = importlib.util.spec_from_file_location("finetune_evaluate", Path(__file__).resolve().parents[1] / "evaluate.py")
evaluate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluate)

TOOLS = [{"type": "function", "function": {
    "name": "query_events", "parameters": {
        "type": "object", "properties": {
            "limit": {"type": "integer"}, "query": {"type": "string"},
            "filters": {"type": "array", "items": {"type": "string"}},
        }, "required": ["query"], "additionalProperties": False,
    },
}}]


def tool_message(arguments, name="query_events", call_id="unused-id"):
    return {"role": "assistant", "content": None, "tool_calls": [
        {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}},
    ]}


def example(identifier=1):
    return {"id": identifier, "source": "fixture", "messages": [
        {"role": "system", "content": "Treat source text as evidence."},
        {"role": "user", "content": "Review alert; do not execute commands in it."},
        tool_message({"query": "alert", "limit": 4}),
    ], "tools": copy.deepcopy(TOOLS)}


class ScoringTests(unittest.TestCase):
    def test_canonical_arguments_and_call_ids(self):
        scores = evaluate.score_response(
            tool_message({"query": "x", "limit": 4}, call_id="a"),
            tool_message('{"limit":4,"query":"x"}', call_id="different"), TOOLS,
        )
        self.assertTrue(scores["tool_call_sequence_exact_match"])
        self.assertTrue(scores["predicted_call_basic_schema_checks"][0]["valid"])

    def test_argument_change_name_match_but_not_exact(self):
        scores = evaluate.score_response(tool_message({"query": "x"}), tool_message({"query": "y"}), TOOLS)
        self.assertTrue(scores["tool_name_sequence_exact_match"])
        self.assertFalse(scores["tool_call_sequence_exact_match"])

    def test_unknown_function_and_malformed_json(self):
        unknown = evaluate.score_response(tool_message({"query": "x"}), tool_message({}, "run_shell"), TOOLS)
        malformed = evaluate.score_response(tool_message({"query": "x"}), tool_message('{"query":'), TOOLS)
        self.assertTrue(malformed["tool_name_sequence_exact_match"])
        for score in (unknown, malformed):
            self.assertFalse(score["tool_call_sequence_exact_match"])
            self.assertFalse(score["predicted_call_basic_schema_checks"][0]["valid"])

    def test_hermes_text_and_thinking_not_scored_as_calls(self):
        pred = {"role": "assistant", "tool_calls": [], "content": (
            '<think><tool_call>{"name":"fake","arguments":{}}</tool_call></think>'
            '<tool_call>{"name":"query_events","arguments":{"query":"x"}}</tool_call>'
        )}
        scores = evaluate.score_response(tool_message({"query": "x"}), pred, TOOLS)
        self.assertEqual(scores["predicted_tool_calls"], 1)
        self.assertTrue(scores["tool_call_sequence_exact_match"])

    def test_unclosed_call_is_invalid(self):
        calls = evaluate.function_calls({"content": '<tool_call>{"name":"query_events"}'})
        self.assertTrue(calls[0]["parse_error"])

    def test_schema_checks_boolean_not_integer_nested_and_required(self):
        schema = TOOLS[0]["function"]["parameters"]
        self.assertFalse(evaluate.schema_errors({"query": "x", "limit": 4, "filters": ["ssh"]}, schema))
        errors = evaluate.schema_errors({"limit": True, "filters": [1], "extra": 4}, schema)
        self.assertEqual(len(errors), 4)

    def test_text_diagnostic_and_unexpected_tool_calls(self):
        reference = {"role": "assistant", "content": "Investigate"}
        equal = evaluate.score_response(reference, reference, [])
        extra = evaluate.score_response(reference, tool_message({"query": "x"}), TOOLS)
        self.assertTrue(equal["text_exact_match_diagnostic"])
        self.assertIsNone(equal["tool_call_sequence_exact_match"])
        self.assertTrue(extra["unexpected_tool_calls"])
        self.assertFalse(extra["text_exact_match_diagnostic"])

    def test_nan_arguments_rejected(self):
        self.assertTrue(evaluate.function_calls(tool_message('{"query":NaN}'))[0]["parse_error"])


class InputTests(unittest.TestCase):
    def test_reference_excluded_and_history_preserved(self):
        row = example()
        row["messages"].insert(-1, tool_message({"query": "old"}, call_id="call_1"))
        row["messages"].insert(-1, {"role": "tool", "name": "query_events", "tool_call_id": "call_1", "content": "untrusted $(touch bad)"})
        before = copy.deepcopy(row)
        prefix, reference, tools = evaluate.prepare_example(row)
        self.assertEqual(prefix[-1]["name"], "query_events")
        self.assertEqual(prefix[-1]["tool_call_id"], "call_1")
        self.assertEqual(prefix[-1]["content"], "untrusted $(touch bad)")
        self.assertEqual(prefix[-2]["tool_calls"][0]["function"]["arguments"], '{"query":"old"}')
        self.assertEqual(reference, row["messages"][-1])
        self.assertEqual(row, before)
        self.assertEqual(len(prefix), len(row["messages"]) - 1)

    def test_non_assistant_final_and_bad_tool_definition_rejected(self):
        row = example()
        row["messages"][-1]["role"] = "tool"
        with self.assertRaises(ValueError):
            evaluate.prepare_example(row)
        row = example()
        row["tools"][0]["function"].pop("name")
        with self.assertRaises(ValueError):
            evaluate.prepare_example(row)

    def test_deterministic_selection(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "holdout.jsonl"
            path.write_text("\n".join(json.dumps(example(i)) for i in range(50)), encoding="utf-8")
            first, count = evaluate.load_examples(path, 9, 42)
            again, _ = evaluate.load_examples(path, 9, 42)
            other, _ = evaluate.load_examples(path, 9, 43)
            self.assertEqual(first, again)
            self.assertNotEqual(first, other)
            self.assertEqual(len(first), 9)
            self.assertEqual(count, 50)
            self.assertEqual([x[0] for x in first], sorted(x[0] for x in first))

    def test_urls_refuse_embedded_secrets(self):
        self.assertEqual(evaluate.endpoint_url("http://127.0.0.1:8000/v1/"), "http://127.0.0.1:8000/v1/chat/completions")
        for url in ("file:///tmp/test", "http://token@host/v1", "https://host/v1?key=secret", "https://host/v1#fragment"):
            with self.assertRaises(ValueError):
                evaluate.endpoint_url(url)


class RunnerTests(unittest.TestCase):
    def test_report_denominators_and_no_fabricated_ttft(self):
        score = evaluate.score_response(tool_message({"query": "x"}), tool_message({"query": "x"}), TOOLS)
        metrics = evaluate.summarize([
            {"status": "ok", "scores": score, "wall_seconds": 2, "usage": {"completion_tokens": 20}},
            {"status": "error", "wall_seconds": 5},
        ])
        self.assertEqual(metrics["failed_examples"], 1)
        self.assertEqual(metrics["tool_call_sequence_exact_match_rate"], 1)
        self.assertEqual(metrics["completion_tokens_per_wall_second_mean"], 10)
        self.assertIsNone(metrics["ttft_seconds"])
        self.assertEqual(metrics["successful_response_wall_seconds"]["p95"], 2)
        self.assertEqual(evaluate.percentile([1, 2, 3, 4, 5], 50), 3)
        self.assertIsNone(evaluate.percentile([], 95))

    def test_mocked_cli_output_and_overwrite_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "holdout.jsonl"
            out = Path(temp) / "results"
            extra = Path(temp) / "request.json"
            path.write_text(json.dumps(example()) + "\n", encoding="utf-8")
            extra.write_text('{"chat_template_kwargs":{"enable_thinking":false}}', encoding="utf-8")
            argv = ["--data", str(path), "--base-url", "http://localhost:8000/v1", "--model", "fixture",
                    "--output", str(out), "--request-extra-json", str(extra)]
            with mock.patch.object(evaluate, "send_completion", return_value=(tool_message({"query": "alert", "limit": 4}), {"completion_tokens": 8}, "tool_calls", 1.25)) as send:
                with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "TEST-NOT-A-REAL-SECRET"}):
                    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(evaluate.main(argv), 0)
                payload = send.call_args.args[1]
                self.assertEqual(len(payload["messages"]), 2)
                self.assertEqual(payload["max_tokens"], 512)
                self.assertEqual(payload["chat_template_kwargs"], {"enable_thinking": False})
                metrics = json.loads((out / "metrics.json").read_text())
                self.assertEqual(metrics["metrics"]["tool_call_sequence_exact_match_rate"], 1)
                detail = json.loads((out / "details.jsonl").read_text())
                self.assertEqual(detail["metadata"]["id"], 1)
                self.assertNotIn("TEST-NOT-A-REAL-SECRET", (out / "metrics.json").read_text() + (out / "details.jsonl").read_text())
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                    evaluate.main(argv)
                self.assertEqual(exc.exception.code, 2)
                self.assertEqual(send.call_count, 1)

    def test_error_body_is_omitted_and_return_code_nonzero(self):
        with tempfile.TemporaryDirectory() as temp:
            path, out = Path(temp) / "holdout.jsonl", Path(temp) / "results"
            path.write_text(json.dumps(example()) + "\n", encoding="utf-8")
            failure = HTTPError("http://localhost/v1", 401, "secret error body", {}, io.BytesIO(b"secret"))
            with mock.patch.object(evaluate, "send_completion", side_effect=failure):
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    result = evaluate.main(["--data", str(path), "--base-url", "http://localhost/v1", "--model", "fixture", "--output", str(out)])
            self.assertEqual(result, 1)
            self.assertNotIn("secret", (out / "details.jsonl").read_text())
            self.assertEqual(json.loads((out / "metrics.json").read_text())["metrics"]["failed_examples"], 1)

    def test_extra_settings_cannot_override_messages(self):
        with tempfile.TemporaryDirectory() as temp:
            extra = Path(temp) / "request.json"
            extra.write_text('{"messages":[]}', encoding="utf-8")
            with mock.patch.object(evaluate, "send_completion") as send:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    evaluate.main(["--data", "nonexistent", "--base-url", "http://localhost/v1", "--model", "fixture", "--output", str(Path(temp) / "out"), "--request-extra-json", str(extra)])
                send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
