"""Pure, hash-pinned patch builder for the inspected Hermes installation.

No file writes, imports of vendor code, network calls, or deployment occur here.
The caller supplies both UTF-8 source texts and writes the returned candidates
only after its own backup/deployment checks. The companion runtime module must
provide GuardedText(str), async guard_text(str) returning GuardedText, synchronous
turn_context(str), begin_turn(str), and set_turn_evidence(messages). The marker
is preserved only across local formatting of already checked text. Unknown or
partially patched sources fail closed.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any


ADAPTER_PATH = "plugins/platforms/mattermost/adapter.py"
TURN_PATH = "gateway/run_turn.py"
UPSTREAM_SHA256 = {
    ADAPTER_PATH: "4f05be68777068d7b454187c7323f2c471aac6412b830f11761b4013eed702c8",
    TURN_PATH: "5bdee5c82c00e02f664516f9da0af99674e23493ec2a30eff06cb03afc6718a0",
}
# Filled from the complete generated candidates, not merely a marker check.
PATCHED_SHA256 = {
    ADAPTER_PATH: "1bbe71e24cf7fd212f38b13cb421bb5b05c841ea4d70a061d6dcb57253e6c47b",
    TURN_PATH: "d4dae0f3194f7b7d435aac2eb37d4697822612cd6955911d86bb61400ad2871a",
}


class GuardPatchError(ValueError):
    """The supplied source/configuration is outside the reviewed contract."""


def _sha256(text: str) -> str:
    try:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
    except UnicodeError:
        raise GuardPatchError("invalid_utf8_source") from None


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    if source.count(old) != 1:
        raise GuardPatchError("anchor_not_unique:" + label)
    return source.replace(old, new, 1)


def _patch_adapter(source: str) -> str:
    replacements = (
        (
            "from gateway.config import Platform, PlatformConfig\n",
            "from capstone_korean_output_guard import GuardedText, guard_text, turn_context\n"
            "from gateway.config import Platform, PlatformConfig\n",
            "adapter_import",
        ),
        (
            "    # --- HTTP helpers ---\n",
            "    async def _process_message_background(self, event: MessageEvent, session_key: str) -> None:\n"
            "        # Every queued drain enters a fresh request scope; restore on cancellation too.\n"
            "        with turn_context(event.text or \"\"):\n"
            "            await super()._process_message_background(event, session_key)\n\n"
            "    # --- HTTP helpers ---\n",
            "adapter_turn_scope",
        ),
        (
            "        url = f\"{self._base_url}/api/v4/{path.lstrip('/')}\"\n",
            "        # Last transport check also covers captions, edits and thread fallback text.\n"
            "        _guard_path = path.lstrip(\"/\")\n"
            "        _guard_message_route = (\n"
            "            (method == \"POST\" and _guard_path == \"posts\")\n"
            "            or (method == \"PUT\" and re.fullmatch(r\"posts/[^/]+/patch\", _guard_path) is not None)\n"
            "        )\n"
            "        if _guard_message_route and isinstance(payload, dict) and isinstance(payload.get(\"message\"), str):\n"
            "            payload = {**payload, \"message\": await guard_text(payload[\"message\"])}\n"
            "        url = f\"{self._base_url}/api/v4/{path.lstrip('/')}\"\n",
            "adapter_api_guard",
        ),
        (
            "        \"\"\"Post once, optionally falling back flat for final notify content.\"\"\"\n"
            "        data = await self._api_post(\"posts\", payload)\n",
            "        \"\"\"Post once, optionally falling back flat for final notify content.\"\"\"\n"
            "        # Revalidate before retaining a body for retry: a GuardedText from another\n"
            "        # turn must not acquire this turn's marker merely through prefixing.\n"
            "        if isinstance(payload.get(\"message\"), str):\n"
            "            payload = {**payload, \"message\": await guard_text(payload[\"message\"])}\n"
            "        data = await self._api_post(\"posts\", payload)\n",
            "adapter_thread_entry_guard",
        ),
        (
            "        body = str(flat_payload.get(\"message\") or \"\")\n"
            "        flat_payload[\"message\"] = self.warning_text(\n"
            "            (\"⚠️ Mattermost thread delivery failed; posting final reply in channel.\\n\\n\" + body).strip(), body)\n",
            "        _guard_original_body = flat_payload.get(\"message\") or \"\"\n"
            "        body = str(_guard_original_body)\n"
            "        flat_payload[\"message\"] = self.warning_text(\n"
            "            (\"⚠️ Mattermost thread delivery failed; posting final reply in channel.\\n\\n\" + body).strip(), body)\n"
            "        # Only a checked body plus this fixed local notice inherits the marker.\n"
            "        if isinstance(_guard_original_body, GuardedText) and isinstance(flat_payload[\"message\"], str):\n"
            "            flat_payload[\"message\"] = GuardedText(flat_payload[\"message\"])\n",
            "adapter_retry_marker",
        ),
        (
            "        if not content:\n"
            "            return SendResult(success=True)\n"
            "        result = SendResult(success=True)\n"
            "        for chunk in self.truncate_message(self.format_message(content), MAX_POST_LENGTH):\n",
            "        if not content:\n"
            "            return SendResult(success=True)\n"
            "        content = await guard_text(content)\n"
            "        result = SendResult(success=True)\n"
            "        for chunk in self.truncate_message(self.format_message(content), MAX_POST_LENGTH):\n"
            "            # A fragment can lack its original quote/fence context; it was checked\n"
            "            # as part of the complete response before formatting and splitting.\n"
            "            chunk = GuardedText(chunk)\n",
            "adapter_send_guard",
        ),
        (
            "    async def edit_message(self, chat_id: str, message_id: str, content: str, *, finalize: bool = False) -> SendResult:\n"
            "        payload = _with_mentions_disabled({\"message\": self.format_message(content)})\n",
            "    async def edit_message(self, chat_id: str, message_id: str, content: str, *, finalize: bool = False) -> SendResult:\n"
            "        content = await guard_text(content)\n"
            "        payload = _with_mentions_disabled({\"message\": GuardedText(self.format_message(content))})\n",
            "adapter_edit_guard",
        ),
        (
            "    file_id; ``thread_id`` becomes ``root_id``. ``force_document`` is signature parity only (unused).\n"
            "    \"\"\"\n"
            "    try:\n",
            "    file_id; ``thread_id`` becomes ``root_id``. ``force_document`` is signature parity only (unused).\n"
            "    \"\"\"\n"
            "    # Standalone delivery has no verified user/tool context: use the safe fallback\n"
            "    # when original-language quotations cannot be verified, never blanket-exempt them.\n"
            "    with turn_context(\"\"):\n"
            "        message = await guard_text(message)\n"
            "    try:\n",
            "standalone_guard",
        ),
    )
    for old, new, label in replacements:
        source = _replace_once(source, old, new, label)
    return source


def _patch_turn(source: str) -> str:
    replacements = (
        (
            "from gateway.config import Platform\n",
            "from capstone_korean_output_guard import begin_turn, set_turn_evidence, guard_text\n"
            "from gateway.config import Platform\n",
            "turn_import",
        ),
        (
            "        Keys: \"final_response\", \"messages\", \"api_calls\", \"completed\".\"\"\"\n"
            "        if self._get_proxy_url():\n",
            "        Keys: \"final_response\", \"messages\", \"api_calls\", \"completed\".\"\"\"\n"
            "        if source.platform == Platform.MATTERMOST:\n"
            "            # In-band /queue recursion runs in this same task. Keep the terminal\n"
            "            # request's context until outer final delivery; the adapter restores it.\n"
            "            begin_turn(message)\n"
            "        if self._get_proxy_url():\n",
            "turn_begin",
        ),
        (
            "            self._run_agent_evict_on_fallback(turn_ctx)\n\n"
            "            # Interrupted OR queued message (/queue)?\n",
            "            if source.platform == Platform.MATTERMOST:\n"
            "                # Guard before an in-band queued first response can be delivered.\n"
            "                # The finalized response and raw result can be distinct dictionaries;\n"
            "                # preserve each one's metadata and guard its own text independently.\n"
            "                _guard_seen = set()\n"
            "                for _guard_result in (response, turn_ctx.result_holder[0]):\n"
            "                    if not isinstance(_guard_result, dict) or id(_guard_result) in _guard_seen:\n"
            "                        continue\n"
            "                    _guard_seen.add(id(_guard_result))\n"
            "                    set_turn_evidence(_guard_result.get(\"messages\", []))\n"
            "                    _guard_final = _guard_result.get(\"final_response\")\n"
            "                    if isinstance(_guard_final, str):\n"
            "                        _guard_result[\"final_response\"] = await guard_text(_guard_final)\n"
            "            self._run_agent_evict_on_fallback(turn_ctx)\n\n"
            "            # Interrupted OR queued message (/queue)?\n",
            "turn_worker_result_guard",
        ),
        (
            "            response = _sanitize_gateway_final_response(source.platform, response)\n\n",
            "            response = _sanitize_gateway_final_response(source.platform, response)\n"
            "            if source.platform == Platform.MATTERMOST:\n"
            "                # Proxy/fallback results also reach here; guard before delivery-ledger\n"
            "                # recording so persisted delivery text equals the corrected response.\n"
            "                set_turn_evidence(agent_messages)\n"
            "                response = await guard_text(response)\n\n",
            "turn_shape_guard",
        ),
    )
    for old, new, label in replacements:
        source = _replace_once(source, old, new, label)
    return source


def patch_sources(sources: dict[str, str]) -> dict[str, str]:
    """Return both reviewed candidates; require exact original or exact patched SHA.

    An already patched file is accepted only by its full known hash, not by an
    import/comment substring. Mixed original/patched pairs are safe to complete.
    The caller's mapping is never modified. All checks finish before return.
    """
    if not isinstance(sources, dict) or set(sources) != set(UPSTREAM_SHA256):
        raise GuardPatchError("expected_exact_source_paths")
    patched = {}
    for path, original in sources.items():
        if not isinstance(original, str):
            raise GuardPatchError("source_must_be_text:" + path)
        digest = _sha256(original)
        if digest == PATCHED_SHA256[path]:
            candidate = original
        elif digest == UPSTREAM_SHA256[path]:
            candidate = (_patch_adapter if path == ADAPTER_PATH else _patch_turn)(original)
            if _sha256(candidate) != PATCHED_SHA256[path]:
                raise GuardPatchError("generated_hash_mismatch:" + path)
        else:
            raise GuardPatchError("unknown_upstream_sha256:" + path)
        try:
            compile(candidate, path, "exec", dont_inherit=True)
        except (SyntaxError, ValueError):
            raise GuardPatchError("candidate_does_not_compile:" + path) from None
        patched[path] = candidate
    return patched


def patch_config(config: dict[str, Any]) -> dict[str, Any]:
    """Copy configuration and quiet only unverified Mattermost draft surfaces.

    Hermes display_config resolves real booleans at display.platforms.mattermost
    before global defaults. In particular display.streaming alone is CLI-only.
    Model/provider/TTS/tools/cron settings and other platforms are preserved.
    """
    if not isinstance(config, dict):
        raise GuardPatchError("config_must_be_mapping")
    result = copy.deepcopy(config)
    branch = result
    for key in ("display", "platforms", "mattermost"):
        if key not in branch or branch[key] is None:
            branch[key] = {}
        if not isinstance(branch[key], dict):
            raise GuardPatchError("config_branch_must_be_mapping:" + key)
        branch = branch[key]
    for key in ("streaming", "interim_assistant_messages", "show_reasoning", "thinking_progress"):
        branch[key] = False
    return result


def build_candidate(source_root, output_root):
    """Build only the two reviewed integration files; never deploy or restart.

    Ansible owns the private staging directories and the deployment transaction.
    Existing destinations are rejected so a stale candidate cannot be reused.
    """
    import os
    from pathlib import Path
    import stat

    source_root, output_root = Path(source_root), Path(output_root)
    for directory in (source_root, output_root):
        if not stat.S_ISDIR(directory.lstat().st_mode):
            raise GuardPatchError("candidate_directory_not_regular")
    sources = {}
    for name in UPSTREAM_SHA256:
        path = source_root / name
        if not stat.S_ISREG(path.lstat().st_mode):
            raise GuardPatchError("candidate_source_not_regular")
        sources[name] = path.read_text(encoding="utf-8")
    candidates = patch_sources(sources)
    for name, text in candidates.items():
        path = output_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8", newline="") as out:
            os.chmod(path, 0o644)
            out.write(text)
    return {name: _sha256(value) for name, value in candidates.items()}


if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser(description="Build reviewed Hermes integration candidates only")
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps({"candidate_sha256": build_candidate(args.source_root, args.output_root)}))
    except (GuardPatchError, OSError, UnicodeError):
        parser.exit(1, "guard_candidate_rejected\n")
