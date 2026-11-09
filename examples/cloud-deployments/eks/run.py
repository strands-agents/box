"""Render or run one Box Job in the caller's Kubernetes context."""
import argparse
import datetime
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

COMMAND_TIMEOUT_SECONDS = 30
DIAGNOSTIC_TIMEOUT_SECONDS = 10
JOB_WAIT_SECONDS = {"scripted": 360, "claude": 960}
POLL_INTERVAL_SECONDS = 3


def manifest(args):
    if not re.fullmatch(r'[a-z0-9](?:[-a-z0-9]*[a-z0-9])?', args.namespace):
        raise ValueError('Use a Kubernetes namespace name containing lowercase letters, digits, and hyphens.')
    if not args.image or any(x.isspace() for x in args.image):
        raise ValueError('Provide the image you built and pushed to your registry.')
    if args.mode == 'claude' and (not args.service_account or not args.region):
        raise ValueError('Claude requires --service-account and --region.')
    container = {
        'name': 'workload', 'image': args.image,
        'securityContext': {
            'runAsNonRoot': True, 'runAsUser': 991, 'runAsGroup': 991,
            'allowPrivilegeEscalation': False, 'privileged': False,
            'capabilities': {'drop': ['ALL']},
            'seccompProfile': {'type': 'Unconfined'}, 'procMount': 'Unmasked',
        },
        'resources': {'requests': {'cpu': '250m', 'memory': '512Mi' if args.mode == 'claude' else '256Mi'},
                      'limits': {'cpu': '1', 'memory': '2Gi' if args.mode == 'claude' else '1Gi'}},
    }
    pod = {'restartPolicy': 'Never', 'hostUsers': False, 'automountServiceAccountToken': False,
           'securityContext': {'fsGroup': 991}, 'nodeSelector': {'kubernetes.io/arch': 'arm64'},
           'containers': [container]}
    if args.image_pull_secret:
        pod['imagePullSecrets'] = [{'name': args.image_pull_secret}]
    if args.mode == 'claude':
        pod['serviceAccountName'] = args.service_account
        container['command'] = ['/usr/bin/python3.12']
        container['args'] = ['/demo/main.py', '--exercise', args.exercise]
        container['env'] = [{'name': 'AWS_REGION', 'value': args.region},
                            {'name': 'AWS_DEFAULT_REGION', 'value': args.region},
                            {'name': 'BEDROCK_MODEL_ID', 'value': args.model},
                            {'name': 'AWS_EC2_METADATA_DISABLED', 'value': 'true'}]
    return {'apiVersion': 'batch/v1', 'kind': 'Job',
            'metadata': {'generateName': 'box-' + args.mode + '-', 'namespace': args.namespace},
            'spec': {'backoffLimit': 0, 'activeDeadlineSeconds': 900 if args.mode == 'claude' else 300,
                     'template': {'spec': pod}}}


def require_sandbox_settings(pod, source):
    """Reject API responses that lost the workload's required sandbox settings."""
    differences = []
    if pod.get('hostUsers') is not False:
        differences.append(f"hostUsers: expected false; received {json.dumps(pod.get('hostUsers'))}")
    workload = next((c for c in pod.get('containers', []) if c.get('name') == 'workload'), None)
    if workload is None:
        differences.append('containers: required workload container is absent')
    else:
        security = workload.get('securityContext', {})
        if security.get('procMount') != 'Unmasked':
            differences.append(f"procMount: expected Unmasked; received {json.dumps(security.get('procMount'))}")
        seccomp = security.get('seccompProfile', pod.get('securityContext', {}).get('seccompProfile', {}))
        if seccomp.get('type') != 'Unconfined':
            differences.append(f"seccompProfile.type: expected Unconfined; received {json.dumps(seccomp.get('type'))}")
    if differences:
        raise RuntimeError(
            f'The cluster did not preserve required Box settings in {source}:\n  '
            + '\n  '.join(differences)
            + '\nBox cannot start its sandbox with this configuration. '
            'See docs/user/tutorials/eks.md#cluster-baseline for cluster, worker, and admission requirements. '
            'This check does not identify which feature gate or admission rule changed the settings.'
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--mode', choices=['scripted', 'claude'], default='scripted')
    parser.add_argument('--exercise', choices=['deployment-cooldown', 'boundaries'],
                        default='deployment-cooldown', help='Exercise for --mode claude.')
    parser.add_argument('--namespace', default='box-demo')
    parser.add_argument('--context', help='Kubernetes context; otherwise use your current context.')
    parser.add_argument('--image-pull-secret')
    parser.add_argument('--service-account')
    parser.add_argument('--region')
    parser.add_argument('--model', default='us.anthropic.claude-sonnet-4-6')
    parser.add_argument('--render', action='store_true', help='Print the Job without connecting to Kubernetes.')
    args = parser.parse_args()
    try:
        job = manifest(args)
    except ValueError as error:
        parser.error(str(error))
    if args.render:
        print(json.dumps(job, indent=2))
        return 0
    kubectl = ['kubectl'] + (['--context', args.context] if args.context else [])
    kubectl += ['--namespace', args.namespace]
    def call(*parts, data=None, required=True, timeout=None):
        command = kubectl + list(parts)
        try:
            result = subprocess.run(command, input=data, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            output = error.stdout.decode(errors='replace') if isinstance(error.stdout, bytes) else error.stdout or ''
            result = subprocess.CompletedProcess(command, 124, output,
                                                 shlex.join(command) + f' timed out after {timeout:g} seconds')
        except OSError as error:
            result = subprocess.CompletedProcess(command, 1, '', str(error))
        if required and result.returncode:
            raise RuntimeError(result.stderr.strip() or shlex.join(command) + f' exited {result.returncode}')
        return result
    preview_result = call('create', '--dry-run=server', '-f', '-', '-o', 'json',
                          data=json.dumps(job), timeout=COMMAND_TIMEOUT_SECONDS)
    if preview_result.stderr.strip():
        print(preview_result.stderr.strip(), file=sys.stderr, flush=True)
    preview = json.loads(preview_result.stdout)
    require_sandbox_settings(preview.get('spec', {}).get('template', {}).get('spec', {}),
                             'the server dry-run Job; no Job was created')
    created = json.loads(call('create', '-f', '-', '-o', 'json', data=json.dumps(job)).stdout)
    name = created['metadata']['name']
    dest = Path('evidence') / name
    dest.mkdir(parents=True, exist_ok=False)
    (dest / 'submitted-job.json').write_text(json.dumps(created, indent=2))
    print('Created ' + name, file=sys.stderr, flush=True)
    deadline = time.monotonic() + JOB_WAIT_SECONDS[args.mode]
    current = created
    polling_error = None
    event_warning_printed = False
    last_creation_error = None
    try:
        require_sandbox_settings(created.get('spec', {}).get('template', {}).get('spec', {}),
                                 'the created Job')
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('The deadline expired before Job completion was confirmed')
            current = json.loads(call('get', 'job', name, '-o', 'json',
                                      timeout=min(COMMAND_TIMEOUT_SECONDS, remaining)).stdout)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('The deadline expired before Pod configuration was confirmed')
            observed = json.loads(call('get', 'pods', '-l', 'job-name=' + name, '-o', 'json',
                                       timeout=min(COMMAND_TIMEOUT_SECONDS, remaining)).stdout)
            (dest / 'pod-configuration.json').write_text(json.dumps(observed, indent=2))
            if observed.get('items'):
                last_creation_error = None
            for pod in observed.get('items', []):
                require_sandbox_settings(pod.get('spec', {}),
                                         'Pod ' + pod.get('metadata', {}).get('name', '<unknown>'))
            if not observed.get('items'):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError('The deadline expired before Pod creation events could be inspected')
                events = call('get', 'events', '--field-selector',
                              'involvedObject.uid=' + created['metadata']['uid'] + ',reason=FailedCreate',
                              '-o', 'json', required=False, timeout=min(COMMAND_TIMEOUT_SECONDS, remaining))
                (dest / 'pod-creation-events.json').write_text(events.stdout)
                if events.returncode:
                    (dest / 'pod-creation-events.stderr.txt').write_text(events.stderr)
                    if not event_warning_printed:
                        print('Could not inspect Pod creation events: ' + events.stderr.strip(),
                              file=sys.stderr, flush=True)
                        event_warning_printed = True
                else:
                    failures = json.loads(events.stdout).get('items', [])
                    if failures:
                        messages = '; '.join(event.get('message') or 'No event message' for event in failures)
                        if messages != last_creation_error:
                            print('The Job controller could not create a Pod: ' + messages,
                                  file=sys.stderr, flush=True)
                        last_creation_error = messages
            status = current.get('status', {})
            if status.get('succeeded') and not observed.get('items'):
                raise RuntimeError('The Job completed but no Pod configuration could be verified')
            failed = status.get('failed') or any(
                x.get('type') == 'Failed' and x.get('status') == 'True' for x in status.get('conditions', [])
            )
            if failed and not observed.get('items') and last_creation_error:
                raise RuntimeError('The Job failed before a Pod was created')
            if status.get('succeeded') or failed:
                break
            time.sleep(min(POLL_INTERVAL_SECONDS, max(0, deadline - time.monotonic())))
    except (RuntimeError, json.JSONDecodeError) as error:
        polling_error = str(error)
        if last_creation_error:
            polling_error += '\nLast Pod creation error: ' + last_creation_error
    receipt = {'job': name, 'image': args.image, 'mode': args.mode,
               'passed': False, 'checks': {}, 'error': polling_error,
               'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    if args.mode == 'claude':
        receipt['exercise'] = args.exercise
    if polling_error is not None:
        receipt['incomplete'] = True
        (dest / 'receipt.json').write_text(json.dumps(receipt, indent=2))
        (dest / 'job.json').write_text(json.dumps(current, indent=2))
        (dest / 'stderr.txt').write_text(polling_error + '\n')
        print('Evidence: ' + str(dest), file=sys.stderr, flush=True)
        print('The Job may still be running. Inspect it with: ' + shlex.join(kubectl + ['get', 'job', name]),
              file=sys.stderr, flush=True)
    logs = call('logs', 'job/' + name, '-c', 'workload', required=False,
                timeout=DIAGNOSTIC_TIMEOUT_SECONDS)
    pods = call('get', 'pods', '-l', 'job-name=' + name, '-o', 'json', required=False,
                timeout=DIAGNOSTIC_TIMEOUT_SECONDS)
    (dest / 'job.json').write_text(json.dumps(current, indent=2))
    (dest / 'stdout.json').write_text(logs.stdout)
    (dest / 'stderr.txt').write_text('\n'.join(detail for detail in
                                               (polling_error, logs.stderr, pods.stderr) if detail))
    (dest / 'pods.json').write_text(pods.stdout)
    try:
        result = json.loads(logs.stdout)
        state = result.get('state', result)
    except json.JSONDecodeError:
        state = {'passed': False, 'error': 'The container did not emit a JSON result. Inspect pods.json and stderr.txt.'}
    receipt.update(passed=bool(polling_error is None and logs.returncode == 0
                              and current.get('status', {}).get('succeeded') and state.get('passed')),
                   checks=state.get('checks', {}),
                   error=polling_error or state.get('error') or (logs.stderr if logs.returncode else None),
                   recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    (dest / 'receipt.json').write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))
    print('Evidence: ' + str(dest), file=sys.stderr)
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, FileNotFoundError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
