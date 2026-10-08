"""Content-free fixtures for data-integrity risks, no ML packages or network."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("prepare_data", Path(__file__).resolve().parents[1] / "prepare_data.py")
prep = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prep)


def tool_record(arguments=None):
    return {
        "tools": [{"type": "function", "function": {"name": "lookup", "parameters": {
            "type": "object", "properties": {"address": {"type": "string"}},
            "required": ["address"], "additionalProperties": False,
        }}}],
        "messages": [
            {"role": "user", "content": "Check this fixture address"},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "upstream-id", "type": "function", "function": {
                "name": "lookup", "arguments": arguments if arguments is not None else {"address": "192.0.2.10"},
            }}]},
            {"role": "tool", "tool_call_id": "upstream-id", "content": "fixture result"},
            {"role": "assistant", "content": "Fixture conclusion"},
        ],
    }


class NormalizationTests(unittest.TestCase):
    def test_string_arguments_and_response_ids_normalize(self):
        result = prep.normalize_record(tool_record('{"address":"192.0.2.10"}'), "fixture")
        call = result["messages"][1]["tool_calls"][0]
        self.assertIsInstance(call["function"]["arguments"], dict)
        self.assertEqual(call["id"], result["messages"][2]["tool_call_id"])

    def test_unknown_tool_without_declaration_rejected(self):
        record = tool_record()
        record["tools"] = []
        with self.assertRaisesRegex(prep.Reject, "undefined_tool"):
            prep.normalize_record(record, "fixture")

    def test_array_and_wrong_type_arguments_rejected(self):
        for arguments, reason in [([], "arguments_not_object"), ({}, "arguments_schema_mismatch"), ({"address": 5}, "arguments_schema_mismatch")]:
            with self.subTest(arguments=arguments), self.assertRaisesRegex(prep.Reject, reason):
                prep.normalize_record(tool_record(arguments), "fixture")

    def test_damaged_schema_rejected(self):
        record = tool_record()
        record["tools"][0]["function"]["parameters"]["properties"]["address"] = "string"
        with self.assertRaisesRegex(prep.Reject, "invalid_tool_schema"):
            prep.normalize_record(record, "fixture")

    def test_unhandled_schema_constraint_rejected(self):
        record = tool_record()
        record["tools"][0]["function"]["parameters"]["$ref"] = "#/definitions/example"
        with self.assertRaisesRegex(prep.Reject, "unsupported_schema_constraint"):
            prep.normalize_record(record, "fixture")

    def test_orphan_wrong_id_and_terminal_tool_rejected(self):
        orphan = tool_record()
        del orphan["messages"][1]
        with self.assertRaisesRegex(prep.Reject, "orphan_tool_response"):
            prep.normalize_record(orphan, "fixture")
        wrong_id = tool_record()
        wrong_id["messages"][2]["tool_call_id"] = "other-id"
        with self.assertRaisesRegex(prep.Reject, "ambiguous_tool_response"):
            prep.normalize_record(wrong_id, "fixture")
        terminal_tool = tool_record()
        terminal_tool["messages"].pop()
        with self.assertRaisesRegex(prep.Reject, "no_terminal_assistant"):
            prep.normalize_record(terminal_tool, "fixture")

    def test_missing_tool_response_rejected(self):
        record = tool_record()
        del record["messages"][2]
        with self.assertRaisesRegex(prep.Reject, "missing_tool_response"):
            prep.normalize_record(record, "fixture")

    def test_parallel_calls_with_explicit_ids_supported(self):
        record = tool_record()
        other = copy.deepcopy(record["messages"][1]["tool_calls"][0])
        other["id"] = "second-id"
        record["messages"][1]["tool_calls"].append(other)
        record["messages"].insert(2, {"role": "tool", "tool_call_id": "second-id", "content": "result 2"})
        result = prep.normalize_record(record, "fixture")
        self.assertEqual(result["messages"][2]["tool_call_id"], "call_1_1")
        self.assertEqual(result["messages"][3]["tool_call_id"], "call_1_0")

    def test_sharegpt_tags_and_think_cleanup(self):
        record = tool_record()
        record["conversations"] = [
            {"from": "system", "value": "<tools>" + json.dumps(record["tools"]) + "</tools>"},
            {"from": "human", "value": "Fixture query"},
            {"from": "gpt", "value": "<think>fixture scratchpad</think><tool_call>{'name':'lookup','arguments':{'address':'192.0.2.10'}}</tool_call>"},
            {"from": "tool", "value": "<tool_response>fixture answer</tool_response>"},
            {"from": "gpt", "value": "Done"},
        ]
        del record["messages"]
        result = prep.normalize_record(record, "fixture")
        self.assertEqual(result["messages"][1]["content"], "")
        self.assertEqual(result["messages"][2]["content"], "fixture answer")

    def test_hermes_empty_tag_example_does_not_hide_actual_schema(self):
        record = tool_record()
        preamble = "You are a function calling AI model. You are provided with function signatures within <tools> </tools> XML tags.\n"
        record["messages"].insert(0, {"role": "system", "content": preamble + "<tools>\n" + json.dumps(record["tools"]) + "\n</tools>"})
        normalized = prep.normalize_record(record, "fixture")
        self.assertEqual(normalized["tools"][0]["function"]["name"], "lookup")
        self.assertNotIn("<tools>", prep.canonical(normalized["messages"]))
        del record["tools"]
        from_system = prep.normalize_record(record, "fixture")
        self.assertEqual(from_system["tools"], normalized["tools"])

    def test_two_actual_tool_schema_blocks_remain_ambiguous(self):
        record = tool_record()
        block = "<tools>" + json.dumps(record["tools"]) + "</tools>"
        record["messages"].insert(0, {"role": "system", "content": block + block})
        with self.assertRaisesRegex(prep.Reject, "ambiguous_system_tools"):
            prep.normalize_record(record, "fixture")

    def test_attacklm_attribution_and_mitre_metadata_preserved(self):
        record = {"messages": [{"role": "user", "content": "Fixture question"}, {"role": "assistant", "content": "Fixture answer"}],
                  "source": "fixture original source", "license": "MIT", "source_uri": "https://example.invalid/source", "mitre_ids": ["T1190"]}
        result = prep.normalize_record(record, "attacklm.permissive.jsonl")
        self.assertEqual(result["source"], "attacklm.permissive.jsonl")
        for key in ("source", "license", "source_uri", "mitre_ids"):
            self.assertEqual(result["provenance"][key], record[key])

    def test_sevenllm_objects_and_thought_policy(self):
        result = prep.normalize_record({"instruction": "Review", "input": {"fixture": 1}, "thought": "omit", "output": {"result": "ok"}}, "fixture")
        self.assertNotIn("omit", prep.canonical(result))
        self.assertEqual(json.loads(result["messages"][-1]["content"]), {"result": "ok"})

    def test_argument_changes_are_not_conversation_duplicates(self):
        first = prep.normalize_record(tool_record({"address": "192.0.2.10"}), "fixture")
        second = prep.normalize_record(tool_record({"address": "192.0.2.11"}), "fixture")
        self.assertNotEqual(prep.digest(first["messages"]), prep.digest(second["messages"]))
        self.assertEqual(prep.group_key(first), prep.group_key(second))

    def test_license_and_invalid_record_rejected(self):
        with self.assertRaisesRegex(prep.Reject, "record_not_object"):
            prep.normalize_record([], "fixture")
        record = tool_record()
        record["license"] = "unknown"
        with self.assertRaisesRegex(prep.Reject, "unapproved_record_license"):
            prep.normalize_record(record, "attacklm.permissive.jsonl")


class PreparationTests(unittest.TestCase):
    def make_corpus(self, root):
        datasets = root / "datasets"
        processed = datasets / "processed"
        (processed / "eval").mkdir(parents=True)
        (datasets / "raw" / "sevenllm").mkdir(parents=True)
        (processed / "eval" / "reserved.jsonl").write_text(json.dumps({"question": "reserved prompt"}) + "\n")
        (datasets / "raw" / "sevenllm" / "test.jsonl").write_text(json.dumps({"instruction": "seven held out", "input": "", "output": "answer"}) + "\n")
        for source in prep.DEFAULT_INPUTS:
            rows = [{"messages": [{"role": "user", "content": f"prompt {i}"}, {"role": "assistant", "content": f"answer from {source} {i}"}], "license": "MIT"} for i in range(120)]
            for question in ("reserved prompt", "seven held out"):
                rows.append({"messages": [{"role": "user", "content": question}, {"role": "assistant", "content": "should be excluded"}], "license": "MIT"})
            rows.append(rows[0])
            (processed / source).write_text("\n".join(json.dumps(row) for row in rows) + "\nnot json\n")
        # Deliberately train-shaped but categorically excluded knowledge rows.
        (processed / "knowledge").mkdir()
        (processed / "knowledge" / "do_not_train.jsonl").write_text(json.dumps({"messages": [{"role": "user", "content": "knowledge excluded"}, {"role": "assistant", "content": "excluded"}]}) + "\n")
        return datasets

    def test_reproducible_leakage_safe_splits_manifest_and_source_immutability(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            datasets = self.make_corpus(root)
            before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in datasets.rglob("*.jsonl")}
            first = prep.prepare(datasets, root / "out", max_per_source=80, validation_ratio=0.2, test_ratio=0.2)
            second = prep.prepare(datasets, root / "out2", max_per_source=80, validation_ratio=0.2, test_ratio=0.2)
            self.assertEqual(first, second)
            groups = {}
            for split in ("train", "validation", "test"):
                raw = (root / "out" / f"{split}.jsonl").read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), first["outputs"][split]["sha256"])
                rows = [json.loads(line) for line in raw.splitlines()]
                self.assertEqual(len(rows), first["outputs"][split]["records"])
                groups[split] = {prep.group_key(record) for record in rows}
                self.assertTrue(all(record["source"] in prep.DEFAULT_INPUTS for record in rows))
                self.assertNotIn(prep.prompt_hash("reserved prompt"), groups[split])
                self.assertNotIn(prep.prompt_hash("seven held out"), groups[split])
            self.assertFalse(groups["train"] & groups["validation"])
            self.assertFalse(groups["train"] & groups["test"])
            self.assertFalse(groups["test"] & groups["validation"])
            self.assertEqual(first["totals"]["selected_rows"], 400)
            for stats in first["inputs"].values():
                self.assertEqual(stats["rejected"]["evaluation_prompt_overlap"], 2)
                self.assertEqual(stats["rejected"]["duplicate_conversation"], 1)
                self.assertEqual(stats["rejected"]["invalid_json"], 1)
                self.assertEqual(stats["rejected"]["source_cap"], 40)
            after = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in datasets.rglob("*.jsonl")}
            self.assertEqual(before, after)
            self.assertFalse(list(root.glob(".prepare-*")))

    def test_missing_input_and_mutating_source_destination_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            datasets = self.make_corpus(root)
            with self.assertRaisesRegex(ValueError, "outside"):
                prep.prepare(datasets, datasets / "processed" / "output")
            (datasets / "processed" / prep.DEFAULT_INPUTS[0]).unlink()
            with self.assertRaisesRegex(FileNotFoundError, "Required source missing"):
                prep.prepare(datasets, root / "out")
            self.assertFalse((root / "out").exists())

    def test_corrupt_exclusion_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            datasets = self.make_corpus(root)
            (datasets / "processed" / "eval" / "reserved.jsonl").write_text("bad json\n")
            with self.assertRaisesRegex(ValueError, "Invalid exclusion JSON"):
                prep.prepare(datasets, root / "out")
            self.assertFalse((root / "out").exists())


if __name__ == "__main__":
    unittest.main()
