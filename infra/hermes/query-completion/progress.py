"""Mattermost progress on the native turn lifecycle; never model scratch text."""
import asyncio
import functools
import hashlib
import logging
from pathlib import Path
import re
import time

SOURCE_SHA256='d4dae0f3194f7b7d435aac2eb37d4697822612cd6955911d86bb61400ad2871a'
INTERVAL=1
LOG=logging.getLogger('capstone.chat_progress')


def phase(activity, evidence):
    tool=activity.get('current_tool') if isinstance(activity,dict) else None
    if isinstance(tool,str) and tool.startswith('mcp__'):
        return 'MCP 조회 중' if evidence.allowed(tool,'verify') else '승인·작업 절차 진행 중'
    return '요청·조회 결과 분석 중'


def wrapper(original, evidence, interim_metadata, nonconversational):
    @functools.wraps(original)
    async def notify(runner, disp, turn_ctx, _executor_task_holder):
        display,turn,executor=disp,turn_ctx,_executor_task_holder
        source=turn.source
        if str(getattr(source.platform,'value',source.platform)).lower()!='mattermost':
            return await original(runner,display,turn,executor)
        adapter=runner._delivery_adapter_for(source)
        if adapter is None:return
        started=time.monotonic();message_id=None;attempted=False
        metadata=interim_metadata(nonconversational(turn._status_thread_metadata,platform=source.platform))
        try:
            while True:
                await asyncio.sleep(INTERVAL)
                if not runner._should_emit_long_running_notification(turn.session_key,turn.agent_holder[0],executor[0]):break
                activity=runner._agent_activity_summary(turn.agent_holder[0])
                text='⏳ 작업 중 · '+phase(activity,evidence)+' · '+str(int(time.monotonic()-started))+'초 경과'
                try:
                    if message_id:
                        await asyncio.wait_for(adapter.edit_message(source.chat_id,message_id,text),4)
                    elif not attempted:
                        attempted=True  # Ambiguous POST is never blindly replayed.
                        result=await asyncio.wait_for(adapter.send(source.chat_id,text,metadata=metadata),4)
                        if getattr(result,'success',False) and getattr(result,'message_id',None):
                            message_id=str(result.message_id)
                            adapter._capstone_progress_ids.add((source.chat_id,message_id))
                            if turn._cleanup_progress:turn._cleanup_msg_ids.append(message_id)
                except Exception as exc:LOG.warning('progress_update_failed type=%s',type(exc).__name__)
        finally:
            if message_id:
                task=executor[0]
                done=task is not None and task.done() and not task.cancelled()
                text=('조회·분석 처리가 끝나 결과를 전송하고 있습니다.' if done else
                      '⚠️ 진행 표시가 중단되었습니다. 최종 응답이 없으면 작업 결과는 미확인입니다.')
                try:await asyncio.wait_for(adapter.edit_message(source.chat_id,message_id,text),4)
                except Exception:pass
    notify.__capstone_progress__=1
    return notify


def delete_wrapper(original):
    async def delete(adapter,chat_id,message_id):
        owned=getattr(adapter,'_capstone_progress_ids',set())
        if (chat_id,message_id) not in owned:
            return await original(adapter,chat_id,message_id)
        if not all(re.fullmatch('[a-z0-9]{26}',str(x)) for x in (chat_id,message_id)):return False
        try:
            post=await asyncio.wait_for(adapter._api_get('posts/'+message_id),4)
            if not isinstance(post,dict) or post.get('channel_id')!=chat_id or post.get('user_id')!=adapter._bot_user_id:return False
            async with adapter._session.delete(adapter._base_url.rstrip('/')+'/api/v4/posts/'+message_id,
                    headers=adapter._auth_header(),timeout=4,allow_redirects=False) as response:
                if response.status!=200:return False
            owned.discard((chat_id,message_id));return True
        except Exception:return False
    delete.__capstone_progress__=1
    return delete


def install(ctx,evidence,source_root):
    from gateway.run import GatewayRunner, _interim_metadata, _non_conversational_metadata
    path=Path(source_root)/'gateway/run_turn.py'
    if hashlib.sha256(path.read_bytes()).hexdigest()!=SOURCE_SHA256:raise ValueError('progress_source_drift')
    old=GatewayRunner._run_agent_notify_long_running
    if getattr(old,'__capstone_progress__',None)==1:return
    new=wrapper(old,evidence,_interim_metadata,_non_conversational_metadata)
    display_old=GatewayRunner._run_agent_display_settings
    adapters={}
    @functools.wraps(display_old)
    def display(runner,source):
        result=display_old(runner,source)
        if str(getattr(source.platform,'value',source.platform)).lower()=='mattermost':
            adapter=runner._delivery_adapter_for(source)
            if adapter is not None:
                if not hasattr(adapter,'_capstone_progress_ids'):adapter._capstone_progress_ids=set()
                kind=type(adapter)
                if not getattr(kind.delete_message,'__capstone_progress__',None):
                    prior=kind.delete_message;patched=delete_wrapper(prior)
                    adapters[kind]=(prior,patched);kind.delete_message=patched
        return result
    def restore():
        if GatewayRunner._run_agent_notify_long_running is new:GatewayRunner._run_agent_notify_long_running=old
        if GatewayRunner._run_agent_display_settings is display:GatewayRunner._run_agent_display_settings=display_old
        for kind,(prior,patched) in adapters.items():
            if kind.delete_message is patched:kind.delete_message=prior
    ctx.on_unload(restore)
    GatewayRunner._run_agent_notify_long_running=new
    GatewayRunner._run_agent_display_settings=display
    LOG.info('progress_installed interval_seconds=%s fixed_labels_only=true',INTERVAL)
