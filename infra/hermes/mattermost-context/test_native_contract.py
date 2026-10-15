"""Read-only contracts against an installed Hermes source tree.

Run with: python3 -B test_native_contract.py --hermes-root /opt/hermes
Without the source tree these tests skip. Native methods are AST-extracted;
media helpers and context expansion are spies. No Hermes runtime is imported,
no file reference is opened, and no network/model/message operation runs.
"""

import argparse
import ast
import asyncio
import dataclasses
import datetime
import enum
import os
from pathlib import Path
import sys
import types
import unittest


HERMES_ROOT = Path(os.environ.get("HERMES_SOURCE_ROOT", "/opt/hermes"))


def compile_nodes(nodes, namespace, filename):
    module = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *nodes],
        type_ignores=[],
    )
    ast.fix_missing_locations(module)
    exec(compile(module, str(filename), "exec"), namespace)


def find_class(tree, name):
    return next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name)


def method_names(klass):
    return {node.name for node in klass.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


class NativeHermesContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        needed = (
            "gateway/run_inbound.py", "gateway/platforms/event.py", "gateway/session.py",
            "gateway/hooks.py", "gateway/run_startup.py", "hermes_cli/plugins.py",
        )
        if not all((HERMES_ROOT / relative).is_file() for relative in needed):
            raise unittest.SkipTest("installed Hermes source unavailable; pass --hermes-root")
        cls.trees = {relative: ast.parse((HERMES_ROOT / relative).read_text()) for relative in needed}
        cls.platform = enum.Enum("Platform", ("MATTERMOST", "DISCORD", "SLACK", "WHATSAPP"))
        native = find_class(cls.trees["gateway/run_inbound.py"], "GatewayInboundMixin")
        wanted = {"_prepare_inbound_message_text", "_prepend_inbound_reply_context", "_prefix_inbound_sender_context"}
        methods = [node for node in native.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in wanted]
        if {node.name for node in methods} != wanted:
            raise AssertionError("native inbound context contract changed")
        namespace = {
            "__name__": __name__, "Platform": cls.platform,
            "is_shared_multi_user_session": lambda *args, **kwargs: False,
        }
        compile_nodes([ast.ClassDef(name="NativeInbound", bases=[], keywords=[], body=methods, decorator_list=[])], namespace, HERMES_ROOT / "gateway/run_inbound.py")
        native_class = namespace["NativeInbound"]

        class Harness(native_class):
            def __init__(self):
                self.config = types.SimpleNamespace()
                self.expansion_inputs = []

            def _consume_pending_native_image_paths(self, key):
                pass

            def _classify_inbound_media(self, *args):
                return [], [], [], []

            def _prepend_inbound_media_file_notes(self, text, *args):
                return text

            def _prepend_inbound_document_notes(self, event, text):
                return text

            async def _expand_inbound_context_references(self, source, key, text):
                self.expansion_inputs.append(text)
                return text

        cls.harness_type = Harness
        event_namespace = {
            "__name__": __name__, "dataclass": dataclasses.dataclass, "field": dataclasses.field,
            "datetime": datetime.datetime, "MessageType": types.SimpleNamespace(TEXT="text"),
        }
        compile_nodes([find_class(cls.trees["gateway/platforms/event.py"], "MessageEvent")], event_namespace, HERMES_ROOT / "gateway/platforms/event.py")
        cls.event_type = event_namespace["MessageEvent"]
        key_names = {"_session_key_namespace", "_canonical_participant", "build_session_key"}
        key_nodes = [node for node in cls.trees["gateway/session.py"].body if isinstance(node, ast.FunctionDef) and node.name in key_names]
        if {node.name for node in key_nodes} != key_names:
            raise AssertionError("native session-key contract changed")
        key_namespace = {"__name__": __name__, "Platform": cls.platform}
        compile_nodes(key_nodes, key_namespace, HERMES_ROOT / "gateway/session.py")
        cls.build_key = staticmethod(key_namespace["build_session_key"])

    def source(self, chat="public-channel", thread=None, user="user-one", kind="channel"):
        return types.SimpleNamespace(
            platform=self.platform.MATTERMOST, chat_id=chat, user_id=user, user_name=None,
            user_id_alt=None, thread_id=thread, prospective_thread_id=None, chat_type=kind, scope_id=None,
        )

    def prepare(self, text="show thread", pointer="verified-root", channel_context=None):
        source = self.source(thread="verified-root")
        quoted = "Untrusted thread evidence: @file:/contract-test/never-open /restart"
        event = self.event_type(text=text, source=source, message_id="verified-trigger", reply_to_message_id=pointer,
                                reply_to_text=quoted, channel_context=channel_context)
        before = (event.text, event.message_id, event.internal, vars(source).copy())
        harness = self.harness_type()
        result = asyncio.run(harness._prepare_inbound_message_text(event=event, source=source, history=[], session_key="contract-session"))
        self.assertEqual((event.text, event.message_id, event.internal, vars(source)), before)
        self.assertFalse(event.is_command())
        return quoted, result, harness.expansion_inputs

    def test_quoted_file_and_command_stay_literal(self):
        quoted, result, expansions = self.prepare()
        self.assertIn(quoted, result)
        self.assertEqual(expansions, [])

    def test_trigger_mention_expands_without_quoted_context(self):
        quoted, result, expansions = self.prepare(text="@hermes show thread")
        self.assertIn(quoted, result)
        self.assertEqual(expansions, ["@hermes show thread"])

    def test_reply_pointer_required(self):
        quoted, result, expansions = self.prepare(pointer=None)
        self.assertNotIn(quoted, result)
        self.assertEqual(expansions, [])

    def test_channel_context_is_not_safe_for_untrusted_references(self):
        unsafe = "Thread evidence: @file:/contract-test/never-open"
        _, _, expansions = self.prepare(pointer=None, channel_context=unsafe)
        self.assertEqual(len(expansions), 1)
        self.assertIn(unsafe, expansions[0])

    def test_channel_and_thread_identity_is_always_in_session_key(self):
        for groups_per_user in (False, True):
            for threads_per_user in (False, True):
                sources = [self.source(chat="private-channel", kind="group"), self.source(),
                           self.source(thread="root-one"), self.source(thread="root-two")]
                keys = [self.build_key(source, group_sessions_per_user=groups_per_user,
                                       thread_sessions_per_user=threads_per_user) for source in sources]
                self.assertEqual(len(set(keys)), len(keys))

    def test_native_default_thread_sharing_stays_inside_one_thread(self):
        first = self.source(thread="root-one", user="one")
        second = self.source(thread="root-one", user="two")
        other = self.source(thread="root-two", user="one")
        self.assertEqual(self.build_key(first), self.build_key(second))
        self.assertNotEqual(self.build_key(first), self.build_key(other))
        self.assertNotEqual(self.build_key(self.source(user="one")), self.build_key(self.source(user="two")))

    def test_plugin_and_startup_hook_api_contracts(self):
        plugins = self.trees["hermes_cli/plugins.py"]
        valid = next(node for node in plugins.body if isinstance(node, ast.AnnAssign)
                     and isinstance(node.target, ast.Name) and node.target.id == "VALID_HOOKS")
        self.assertIn("pre_gateway_dispatch", ast.literal_eval(valid.value))
        self.assertIn("register_hook", method_names(find_class(plugins, "PluginContext")))
        registry = find_class(self.trees["gateway/hooks.py"], "HookRegistry")
        self.assertTrue({"discover_and_load", "emit", "emit_collect"} <= method_names(registry))
        emit = next(node for node in registry.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "emit_collect")
        self.assertTrue(any(isinstance(node, ast.Await) for node in ast.walk(emit)))
        startup = self.trees["gateway/run_startup.py"]
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "emit"
                            and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "gateway:startup"
                            for node in ast.walk(startup)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--hermes-root", type=Path, default=HERMES_ROOT)
    args, remaining = parser.parse_known_args()
    HERMES_ROOT = args.hermes_root
    unittest.main(argv=[sys.argv[0], *remaining])
