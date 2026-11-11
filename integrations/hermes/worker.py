"""Credential-free Hermes worker. Launched only in Nexus's networkless container.

The upstream agent owns its conversation loop. Nexus owns all model I/O and
workspace operations; no upstream tool implementation is called.
"""
import contextlib
import json
import os
import sys

WIRE = sys.stdout
LIMIT = 1024 * 1024


def send(value):
    encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if len(encoded.encode()) > LIMIT:
        raise ValueError('worker frame too large')
    WIRE.write(encoded + '\n')
    WIRE.flush()


def receive():
    line = sys.stdin.buffer.readline(LIMIT + 2)
    if not line.endswith(b'\n') or len(line) > LIMIT:
        raise ValueError('invalid worker frame')
    return json.loads(line)


def rpc(kind, **payload):
    send({'kind': kind, **payload})
    reply = receive()
    if reply.get('ok') is not True:
        raise InterruptedError('Nexus refused the operation')
    return reply['result']


def clean_history(messages):
    fields = {'role', 'content', 'tool_calls', 'tool_call_id', 'name'}
    return [{key: value for key, value in message.items() if key in fields} for message in messages]


def main():
    request = receive()
    # Imports and upstream status prints never enter the framed protocol.
    with contextlib.redirect_stdout(sys.stderr):
        from run_agent import AIAgent
        from openai.types.chat import ChatCompletion

        os.makedirs(os.environ['HERMES_HOME'], mode=0o700, exist_ok=True)
        with open(os.path.join(os.environ['HERMES_HOME'], 'config.yaml'), 'w') as stream:
            json.dump({'model': {'default': request['model'], 'provider': 'custom',
                'base_url': 'http://127.0.0.1:1/v1', 'context_length': request['context_window']},
                'compression': {'enabled': False}, 'plugins': {},
                'memory': {'enabled': False}}, stream)

        class NexusAgent(AIAgent):
            def _interruptible_api_call(self, kwargs):
                result = rpc('inference', messages=clean_history(kwargs['messages']))
                return ChatCompletion.model_validate(result)

            def _interruptible_streaming_api_call(self, kwargs, **_):
                return self._interruptible_api_call(kwargs)

            def _try_activate_fallback(self, *_args, **_kwargs):
                return False

            def _invoke_tool(self, *_args, **_kwargs):
                raise PermissionError('upstream tool dispatch is disabled')

            def _execute_tool_calls(self, assistant_message, messages, *_args, **_kwargs):
                calls = assistant_message.tool_calls
                if len(calls) != 1:
                    raise ValueError('Nexus requires sequential tool calls')
                call = calls[0]
                result = rpc('tool', name=call.function.name,
                    arguments=json.loads(call.function.arguments), history=clean_history(messages))
                messages.append({'role': 'tool', 'tool_call_id': call.id,
                                 'name': call.function.name, 'content': result})

        agent = NexusAgent(model=request['model'], provider='custom', api_mode='chat_completions',
            base_url='http://127.0.0.1:1/v1', api_key='nexus-worker-no-network',
            enabled_toolsets=[], max_iterations=8, max_tokens=request['output_budget'],
            quiet_mode=True, skip_context_files=True, skip_memory=True,
            skip_background_review=True, fallback_model=None, save_trajectories=False,
            checkpoints_enabled=False, cwd='/tmp', run_budget_seconds=1800)
        # Replace the complete tool surface, including any upstream defaults.
        agent.tools = request['tools']
        agent.valid_tool_names = {tool['function']['name'] for tool in agent.tools}
        history = request['history']
        if request.get('resume'):
            history = request['resume']['history']
            history.append(request['resume']['tool_result'])
            prompt = 'Continue from the verified Nexus tool result above.'
        else:
            prompt = history.pop()['content']
        result = agent.run_conversation(prompt, system_message=request['system'],
                                        conversation_history=history)
        if result.get('error') or result.get('interrupted'):
            raise RuntimeError('Hermes did not finish successfully')
        answer = result.get('final_response')
        if not isinstance(answer, str) or not answer.strip():
            raise RuntimeError('Hermes returned no final response')
        send({'kind': 'done', 'response': answer})


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        # No prompts, model output, source text or upstream exception text in logs.
        send({'kind': 'failed'})
        sys.exit(1)
