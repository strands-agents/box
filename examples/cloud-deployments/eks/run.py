"""Render or run one Box Job in the caller's Kubernetes context."""
import argparse
import datetime
import json
from pathlib import Path
import re
import subprocess
import sys
import time


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
        container['env'] = [{'name': 'AWS_REGION', 'value': args.region},
                            {'name': 'AWS_DEFAULT_REGION', 'value': args.region},
                            {'name': 'BEDROCK_MODEL_ID', 'value': args.model},
                            {'name': 'AWS_EC2_METADATA_DISABLED', 'value': 'true'}]
    return {'apiVersion': 'batch/v1', 'kind': 'Job',
            'metadata': {'generateName': 'box-' + args.mode + '-', 'namespace': args.namespace},
            'spec': {'backoffLimit': 0, 'activeDeadlineSeconds': 900 if args.mode == 'claude' else 300,
                     'template': {'spec': pod}}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--mode', choices=['scripted', 'claude'], default='scripted')
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
    def call(*parts, data=None, required=True):
        result = subprocess.run(kubectl + list(parts), input=data, capture_output=True, text=True)
        if required and result.returncode:
            raise RuntimeError(result.stderr.strip())
        return result
    created = json.loads(call('create', '-f', '-', '-o', 'json', data=json.dumps(job)).stdout)
    name = created['metadata']['name']
    dest = Path('evidence') / name
    dest.mkdir(parents=True, exist_ok=False)
    (dest / 'submitted-job.json').write_text(json.dumps(created, indent=2))
    print('Created ' + name, file=sys.stderr, flush=True)
    deadline = time.monotonic() + (960 if args.mode == 'claude' else 360)
    current = created
    while time.monotonic() < deadline:
        current = json.loads(call('get', 'job', name, '-o', 'json').stdout)
        status = current.get('status', {})
        if status.get('succeeded') or status.get('failed') or any(
            x.get('type') == 'Failed' and x.get('status') == 'True' for x in status.get('conditions', [])
        ):
            break
        time.sleep(3)
    logs = call('logs', 'job/' + name, '-c', 'workload', required=False)
    pods = call('get', 'pods', '-l', 'job-name=' + name, '-o', 'json', required=False)
    (dest / 'job.json').write_text(json.dumps(current, indent=2))
    (dest / 'stdout.json').write_text(logs.stdout)
    (dest / 'stderr.txt').write_text(logs.stderr)
    (dest / 'pods.json').write_text(pods.stdout)
    try:
        result = json.loads(logs.stdout)
        state = result.get('state', result)
    except json.JSONDecodeError:
        state = {'passed': False, 'error': 'The container did not emit a JSON result. Inspect pods.json and stderr.txt.'}
    receipt = {'job': name, 'image': args.image, 'mode': args.mode,
               'passed': bool(current.get('status', {}).get('succeeded') and state.get('passed')),
               'checks': state.get('checks', {}), 'error': state.get('error'),
               'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
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
