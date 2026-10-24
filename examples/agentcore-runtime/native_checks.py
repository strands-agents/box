"""Verify actual native tool attempts from Claude Code's structured transcript."""
import json
import posixpath
import re


def verify(state, transcript):
    root = state['directory']
    expected_paths = {
        'native-input.txt': root + '/project/.agent-tmp/native-input.txt',
        'native-note.txt': root + '/project/.agent-tmp/native-note.txt',
        'operator-private.txt': root + '/operator-private.txt',
        'native-readonly.txt': root + '/project/native-readonly.txt',
    }
    uses, results = {}, {}
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', transcript)
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        content = row.get('message', {}).get('content', [])
        for item in content if isinstance(content, list) else []:
            if item.get('type') == 'tool_use':
                uses[item['id']] = item
            if item.get('type') == 'tool_result':
                results[item['tool_use_id']] = item
    checks = {}
    for name, suffix, expected_error, marker in [
        ('native_read', 'native-input.txt', False, 'NATIVE_READ_OK'),
        ('native_write', 'native-note.txt', False, ''),
        ('native_readback', 'native-note.txt', False, 'NATIVE_WRITE_OK'),
        ('native_private_refused', 'operator-private.txt', True, ''),
        ('native_readonly_refused', 'native-readonly.txt', True, 'EROFS'),
    ]:
        tools = ('Write', 'Edit') if name in ('native_write', 'native_readonly_refused') else ('Read',)
        checks[name] = any(
            use.get('name') in tools
            and posixpath.normpath(posixpath.join(
                root + '/project', use.get('input', {}).get('file_path', '')
            )) == expected_paths[suffix]
            and identity in results
            and results[identity].get('is_error', False) == expected_error
            and marker in str(results[identity].get('content', ''))
            for identity, use in uses.items()
        )
    return checks

