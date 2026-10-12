"""Read-only, exact-source release preflight. Never dispatch, publish, or select latest."""
import argparse
import http.client
import json
import os
import re

REPOSITORY = 'storminator89/Tracebolt'
REPO_ID = 1403204207
WORKFLOW = '.github/workflows/validate.yml'
PREFIX = '/repos/' + REPOSITORY
MAX_RESPONSE = 2 << 20
BASE_JOBS = {
    'Official Debian security feed compatibility',
    'Positive native Ubuntu package and operational observations',
    'Positive v3 Ubuntu inventory, endpoint consent and native restart',
    'Go build and runtime checks', 'Go tests and build-only platform checks',
    'Real two-process Linux transport and expiry', 'UI types, tests and production build',
    'Same-origin browser acceptance and screenshots', 'Required Linux service-action IPC (no skips)',
}
JOBS = BASE_JOBS | {
    f'Native agent runtime ({platform}/{arch})' for platform, arch in
    [('linux', 'amd64'), ('linux', 'arm64'), ('windows', 'amd64'), ('macos', 'arm64')]
} | {f'Unsigned Windows action source ({arch})' for arch in ['amd64', 'arm64']} | {
    f'Dense package race ({topology}/{profile})' for topology in ['same-handle', 'cross-handle'] for profile in ['tls', 'http-test']
} | {f'Go race shard ({shard})' for shard in range(3)} | {
    f'Linux manager container lifecycle ({arch}, TLS and HTTP test)' for arch in ['amd64', 'arm64']
}
AGGREGATE_STEPS = {
    'Require successful runtime and race prerequisites',
    "Download this attempt's normalized race evidence",
    'Prepare independent package discovery',
    'Require exact complete race coverage and successful runtime checks',
}


def require(ok):
    if not ok:
        raise ValueError('full validation rejected')


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def verify_run(value, source, run_id, workflow_id, attempt=None):
    require(type(value) is dict and type(value.get('id')) is int and value['id'] == int(run_id)
            and value.get('head_sha') == source and value.get('head_branch') == 'main'
            and value.get('path') == WORKFLOW and value.get('name') == 'Validate'
            and value.get('workflow_id') == workflow_id
            and value.get('event') in {'push', 'workflow_dispatch', 'schedule'}
            and value.get('status') == 'completed' and value.get('conclusion') == 'success'
            and type(value.get('run_attempt')) is int and 1 <= value['run_attempt'] <= 1000
            and value.get('repository', {}).get('id') == REPO_ID
            and value.get('head_repository', {}).get('id') == REPO_ID
            and value.get('html_url') == f'https://github.com/{REPOSITORY}/actions/runs/{run_id}')
    require(attempt is None or value['run_attempt'] == attempt)
    return value['run_attempt']


def verify_jobs(value, source, run_id, attempt):
    require(type(value) is dict and value.get('total_count') == len(JOBS)
            and type(value.get('jobs')) is list and len(value['jobs']) == len(JOBS))
    names, ids = set(), set()
    for job in value['jobs']:
        require(type(job) is dict and job.get('name') in JOBS and job['name'] not in names
                and type(job.get('id')) is int and job['id'] > 0 and job['id'] not in ids
                and job.get('run_id') == int(run_id) and job.get('run_attempt') == attempt
                and job.get('head_sha') == source and job.get('workflow_name') == 'Validate'
                and job.get('status') == 'completed' and job.get('conclusion') == 'success')
        names.add(job['name']); ids.add(job['id'])
        if job['name'] == 'Go tests and build-only platform checks':
            steps = job.get('steps')
            require(type(steps) is list)
            for expected in AGGREGATE_STEPS:
                matching = [step for step in steps if step.get('name') == expected]
                require(len(matching) == 1 and matching[0].get('status') == 'completed'
                        and matching[0].get('conclusion') == 'success')
    require(names == JOBS)


def check(source, run_id, get):
    require(type(source) is str and re.fullmatch('[0-9a-f]{40}', source)
            and type(run_id) is str and re.fullmatch('[1-9][0-9]{0,19}', run_id))
    workflow = get(PREFIX + '/actions/workflows/validate.yml')
    require(type(workflow) is dict and type(workflow.get('id')) is int and workflow['id'] > 0
            and workflow.get('path') == WORKFLOW and workflow.get('name') == 'Validate')
    path = PREFIX + '/actions/runs/' + run_id
    attempt = verify_run(get(path), source, run_id, workflow['id'])
    verify_run(get(path + f'/attempts/{attempt}'), source, run_id, workflow['id'], attempt)
    verify_jobs(get(path + f'/attempts/{attempt}/jobs?per_page=100'), source, run_id, attempt)
    # A concurrent rerun cannot replace the checked attempt before this gate ends.
    verify_run(get(path), source, run_id, workflow['id'], attempt)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    token = os.environ.get('GH_TOKEN', '')
    require(0 < len(token) <= 10000 and not any(c.isspace() for c in token))
    def get(path):
        require(path.startswith(PREFIX + '/actions/'))
        conn = http.client.HTTPSConnection('api.github.com', timeout=30)
        try:
            conn.request('GET', path, headers={'Authorization': 'Bearer ' + token,
                'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
                'User-Agent': 'Tracebolt-exact-full-validation/1', 'Accept-Encoding': 'identity'})
            response = conn.getresponse()
            require(response.status == 200 and response.getheader('Content-Encoding') in (None, 'identity'))
            raw = response.read(MAX_RESPONSE + 1)
            require(0 < len(raw) <= MAX_RESPONSE)
            return json.loads(raw, object_pairs_hook=unique,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid JSON')))
        finally:
            conn.close()
    check(args.source_sha, args.run_id, get)
    print('PASS: explicit full Validate run and all exact-source jobs succeeded; separate native acceptance remains required.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('FAIL: exact-source full Validate release gate; raw API data withheld. Run full Validate on the released main source and supply its successful run ID.')
