"""Verify loss masking and integrity checks without ML dependencies or downloads."""
from array import array
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("finetuning_train", Path(__file__).resolve().parents[1] / "train.py")
train = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(train)


class FakeTokenizer:
    """One Unicode codepoint per token makes target boundaries inspectable."""

    def __init__(self):
        self.template_options = []

    def apply_chat_template(self, messages, **kwargs):
        self.template_options.append(kwargs)
        return "".join("<" + m["role"] + ">" + m.get("content", "") +
                       (json.dumps(m["tool_calls"], sort_keys=True) if m.get("tool_calls") else "") +
                       "</" + m["role"] + ">" for m in messages)

    def encode(self, text, add_special_tokens=False):
        if add_special_tokens:
            raise AssertionError("Template must own special-token insertion")
        return [ord(char) for char in text]


def conversation(final="Final fixture conclusion"):
    return {"id": "fixture", "source": "fixture", "tools": [{"type": "function", "function": {
        "name": "lookup", "parameters": {"type": "object", "properties": {}}}}], "messages": [
        {"role": "system", "content": "Fixture system"},
        {"role": "user", "content": "Fixture question"},
        {"role": "assistant", "content": "Earlier assistant", "tool_calls": [{"type": "function", "function": {"name": "lookup", "arguments": {}}}]},
        {"role": "tool", "content": "Fixture observation"},
        {"role": "assistant", "content": final},
    ]}


class EncodingTests(unittest.TestCase):
    def test_required_curriculum_cannot_silently_drop_overlength_tool_turns(self):
        train.check_token_coverage({'kept':4,'candidate_turns':4},True)
        with self.assertRaisesRegex(ValueError,'excluded'):
            train.check_token_coverage({'kept':3,'candidate_turns':4,'over_max_length':1},True)
        train.check_token_coverage({'kept':3,'candidate_turns':4},False)
    def test_only_final_assistant_is_supervised_and_all_input_roles_are_masked(self):
        row = conversation()
        tokenizer = FakeTokenizer()
        encoded, reason = train.encode_completion(row, tokenizer, 4096)
        self.assertIsNone(reason)
        batch = train.collate_lists([encoded], 0)
        boundary = encoded["prompt_length"]
        labels = batch["labels"][0]
        self.assertTrue(all(label == -100 for label in labels[:boundary]))
        self.assertEqual(labels[boundary:], list(encoded["input_ids"])[boundary:])
        target = "".join(chr(token) for token in labels if token != -100)
        self.assertEqual(target, "<assistant>Final fixture conclusion</assistant>")
        self.assertNotIn("Earlier assistant", target)
        self.assertNotIn("Fixture observation", target)
        self.assertEqual(len(tokenizer.template_options), 2)
        self.assertTrue(all(options["tools"] == row["tools"] for options in tokenizer.template_options))
        self.assertTrue(all(options["enable_thinking"] is False for options in tokenizer.template_options))

    def test_final_tool_call_target_is_preserved(self):
        row = conversation("")
        row["messages"][-1]["tool_calls"] = [{"type": "function", "function": {"name": "lookup", "arguments": {}}}]
        encoded, reason = train.encode_completion(row, FakeTokenizer(), 4096)
        self.assertIsNone(reason)
        target = "".join(chr(token) for token in list(encoded["input_ids"])[encoded["prompt_length"]:])
        self.assertIn('"name": "lookup"', target)
        self.assertIn('"arguments": {}', target)

    def test_padding_attention_and_loss_masks_are_independent(self):
        features = [
            {"input_ids": array("i", [10, 11, 12, 13]), "prompt_length": 2},
            {"input_ids": array("i", [20, 21]), "prompt_length": 1},
        ]
        batch = train.collate_lists(features, pad_token_id=99)
        self.assertEqual(batch["input_ids"], [[10, 11, 12, 13], [20, 21, 99, 99]])
        self.assertEqual(batch["attention_mask"], [[1, 1, 1, 1], [1, 1, 0, 0]])
        self.assertEqual(batch["labels"], [[-100, -100, 12, 13], [-100, 21, -100, -100]])

    def test_overlength_example_is_rejected_whole(self):
        encoded, reason = train.encode_completion(conversation(), FakeTokenizer(), 20)
        self.assertIsNone(encoded)
        self.assertEqual(reason, "over_max_length")

    def test_missing_target_is_rejected(self):
        for row in ({"messages": []}, {"messages": [{"role": "assistant", "content": "alone"}]},
                    {"messages": [{"role": "user", "content": "question"}, {"role": "tool", "content": "unfinished"}]}):
            with self.subTest(row=row):
                encoded, reason = train.encode_completion(row, FakeTokenizer(), 4096)
                self.assertIsNone(encoded)
                self.assertEqual(reason, "missing_assistant_target")

    def test_template_prefix_mismatch_fails_closed(self):
        class BrokenTemplate(FakeTokenizer):
            def apply_chat_template(self, messages, **kwargs):
                text = super().apply_chat_template(messages, **kwargs)
                return "prefix changed" + text if messages[-1]["role"] == "assistant" else text

        encoded, reason = train.encode_completion(conversation(), BrokenTemplate(), 4096)
        self.assertIsNone(encoded)
        self.assertEqual(reason, "template_prefix_mismatch")

    def test_token_prefix_mismatch_fails_closed(self):
        class BrokenTokenization(FakeTokenizer):
            def encode(self, text, **kwargs):
                ids = super().encode(text, **kwargs)
                if text.endswith("</assistant>"):
                    ids[0] += 1  # Simulate token merging across the text boundary.
                return ids

        encoded, reason = train.encode_completion(conversation(), BrokenTokenization(), 4096)
        self.assertIsNone(encoded)
        self.assertEqual(reason, "token_prefix_mismatch")

    def test_template_with_no_target_tokens_is_rejected(self):
        class DropsFinalAssistant(FakeTokenizer):
            def apply_chat_template(self, messages, **kwargs):
                if messages[-1]["role"] == "assistant":
                    messages = messages[:-1]
                return super().apply_chat_template(messages, **kwargs)

        encoded, reason = train.encode_completion(conversation(), DropsFinalAssistant(), 4096)
        self.assertIsNone(encoded)
        self.assertEqual(reason, "empty_target")

    def test_any_alignment_failure_aborts_a_mixed_split(self):
        class SometimesBroken(FakeTokenizer):
            def apply_chat_template(self, messages, **kwargs):
                result = super().apply_chat_template(messages, **kwargs)
                return "changed" + result if messages[-1].get("content") == "break prefix" else result

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "train.jsonl"
            path.write_text(json.dumps(conversation()) + "\n" + json.dumps(conversation("break prefix")) + "\n")
            with self.assertRaisesRegex(ValueError, "Chat template prefix mismatch"):
                train.tokenize_split(path, SometimesBroken(), 4096, limit=0)

    def test_overlength_statistics_and_limit_count_kept_examples(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "train.jsonl"
            rows = [conversation("x" * 5000), conversation("short"), conversation("unused")]
            for row in rows:
                # One assistant turn per row isolates rejected-vs-accepted counting.
                row["messages"] = row["messages"][:2] + row["messages"][-1:]
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            encoded, stats = train.tokenize_split(path, FakeTokenizer(), 4096, limit=1)
            self.assertEqual(len(encoded), 1)
            self.assertEqual(stats["read"], 2)
            self.assertEqual(stats["candidate_turns"], 2)
            self.assertEqual(stats["over_max_length"], 1)
            self.assertEqual(stats["kept"], 1)

    def test_each_assistant_turn_including_intermediate_tool_call_is_supervised(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "train.jsonl"
            row = conversation()
            path.write_text(json.dumps(row) + "\n")
            features, stats = train.tokenize_split(path, FakeTokenizer(), 4096, limit=0)
            self.assertEqual(stats["read"], 1)
            self.assertEqual(stats["candidate_turns"], 2)
            self.assertEqual(stats["kept"], 2)
            batch = train.collate_lists(features, 0)
            targets = ["".join(chr(token) for token in labels if token != -100) for labels in batch["labels"]]
            self.assertIn("Earlier assistant", targets[0])
            self.assertIn('"name": "lookup"', targets[0])
            self.assertNotIn("Final fixture conclusion", targets[0])
            self.assertEqual(targets[1], "<assistant>Final fixture conclusion</assistant>")
            self.assertNotIn("Earlier assistant", targets[1])
            self.assertNotIn("Fixture observation", targets[1])
            for feature, labels in zip(features, batch["labels"]):
                self.assertTrue(all(label == -100 for label in labels[:feature["prompt_length"]]))
            self.assertEqual(json.loads(path.read_text()), row)

    def test_early_short_assistant_turn_survives_overlength_final_turn(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "train.jsonl"
            path.write_text(json.dumps(conversation("x" * 5000)) + "\n")
            features, stats = train.tokenize_split(path, FakeTokenizer(), 4096, limit=0)
            self.assertEqual(len(features), 1)
            self.assertEqual(stats["read"], 1)
            self.assertEqual(stats["candidate_turns"], 2)
            self.assertEqual(stats["over_max_length"], 1)
            self.assertEqual(stats["kept"], 1)
            target = "".join(chr(token) for token in list(features[0]["input_ids"])[features[0]["prompt_length"]:])
            self.assertIn('"name": "lookup"', target)

    def test_limit_stops_inside_dialogue_after_accepted_prefix_count(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "train.jsonl"
            path.write_text((json.dumps(conversation()) + "\n") * 3)
            features, stats = train.tokenize_split(path, FakeTokenizer(), 4096, limit=3)
            self.assertEqual(len(features), 3)
            self.assertEqual(stats["read"], 2)
            self.assertEqual(stats["candidate_turns"], 3)
            self.assertEqual(stats["kept"], 3)


class IntegrityTests(unittest.TestCase):
    def fixture_data(self, root):
        manifest = {"outputs": {}}
        for split in ("train", "validation", "test"):
            row = conversation()
            row["messages"][1]["content"] = "Unique " + split + " question"
            payload = (json.dumps(row) + "\n").encode("utf-8")
            (root / (split + ".jsonl")).write_bytes(payload)
            manifest["outputs"][split] = {"path": split + ".jsonl", "records": 1, "sha256": hashlib.sha256(payload).hexdigest()}
        (root / "manifest.json").write_text(json.dumps(manifest))
        return {"data_dir": str(root), "model_name_or_path": "fixture/model"}, manifest

    def test_valid_manifest_counts_and_checksums(self):
        with tempfile.TemporaryDirectory() as temp:
            config, manifest = self.fixture_data(Path(temp))
            checked = train.check_data(config)
            self.assertEqual(checked["records"], {"train": 1, "validation": 1, "test": 1})
            self.assertEqual(checked["sha256"]["train"], manifest["outputs"]["train"]["sha256"])

    def test_payload_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config, _ = self.fixture_data(root)
            with (root / "train.jsonl").open("a") as handle:
                handle.write(json.dumps(conversation()) + "\n")
            with self.assertRaisesRegex(ValueError, "checksum does not match"):
                train.check_data(config)

    def test_manifest_count_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config, manifest = self.fixture_data(root)
            manifest["outputs"]["validation"]["records"] = 999
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "count does not match"):
                train.check_data(config)

    def test_hash_valid_row_without_assistant_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config, manifest = self.fixture_data(root)
            row = conversation()
            row["messages"].pop()
            payload = (json.dumps(row) + "\n").encode()
            (root / "test.jsonl").write_bytes(payload)
            manifest["outputs"]["test"]["sha256"] = hashlib.sha256(payload).hexdigest()
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "final assistant target missing"):
                train.check_data(config)


class ConfigTests(unittest.TestCase):
    def test_paths_are_relative_to_config_and_absolute_paths_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / "recipe"
            folder.mkdir()
            config = {
                "data_dir": "../data", "output_dir": str(root / "absolute-output"),
                "max_length": 4096, "per_device_train_batch_size": 1,
                "gradient_accumulation_steps": 8, "lora_r": 8,
                "model_name_or_path": "fixture/model", "target_modules": ["q_proj"],
                "enable_thinking": False,
            }
            path = folder / "config.json"
            path.write_text(json.dumps(config))
            parsed = train.read_config(path)
            self.assertEqual(Path(parsed["data_dir"]).resolve(), (root / "data").resolve())
            self.assertEqual(Path(parsed["output_dir"]), root / "absolute-output")

    def test_thinking_policy_and_missing_lora_targets_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            config = {"data_dir": "data", "output_dir": "outputs", "max_length": 4096,
                      "per_device_train_batch_size": 1, "gradient_accumulation_steps": 8, "lora_r": 8,
                      "model_name_or_path": "fixture/model", "target_modules": ["q_proj"], "enable_thinking": True}
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, "enable_thinking must be false"):
                train.read_config(path)
            config["enable_thinking"] = False
            config["target_modules"] = []
            path.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, "target_modules"):
                train.read_config(path)


if __name__ == "__main__":
    unittest.main()
