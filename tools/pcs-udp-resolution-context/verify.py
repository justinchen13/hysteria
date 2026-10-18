#!/usr/bin/env python3
"""Reviewed remote-only verification. No application or network fixture is run."""
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import shutil
import statistics
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
OUT = ROOT/'dist/pcs-udp-resolution-context'
LOCK = json.loads((HERE/'inputs.json').read_text())


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(name, value):
    (OUT/name).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def command(argv, cwd, name, env, timeout=360):
    started, tick = utc(), time.monotonic()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    record = dict(argv=argv, cwd=str(cwd), started_utc=started)
    try:
        with (OUT/(name+'.log')).open('wb') as log:
            result = subprocess.run(argv, cwd=cwd, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=timeout)
        record['exit_code'] = result.returncode
        if result.returncode:
            raise RuntimeError('command failed: '+name)
    finally:
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        record.update(ended_utc=utc(), wall_seconds=time.monotonic()-tick,
                      child_user_seconds=after.ru_utime-before.ru_utime,
                      child_system_seconds=after.ru_stime-before.ru_stime,
                      children_maxrss_cumulative_kib=after.ru_maxrss)
        save(name+'.json', record)
    return OUT/(name+'.log')


def module_guard(source):
    for path, expected in LOCK['module_sha256'].items():
        if sha(source/path) != expected:
            raise RuntimeError('module lock changed: '+path)


def source_archive(commit, destination):
    data = subprocess.check_output(['git', 'archive', '--format=tar', commit,
                                    'core', 'extras', 'app'], cwd=ROOT, timeout=20)
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for item in archive.getmembers():
            target = (destination/item.name).resolve()
            if not (item.isfile() or item.isdir()) or not target.is_relative_to(destination.resolve()):
                raise RuntimeError('invalid source archive entry')
        archive.extractall(destination, filter='data')
    module_guard(destination)
    return {'commit': commit, 'archive_sha256': hashlib.sha256(data).hexdigest(),
            'files_sha256': {str(p.relative_to(destination)): sha(p)
                             for p in sorted(destination.rglob('*')) if p.is_file()}}


def verify_tests(log, expected):
    ran, passed = set(), set()
    for line in log.read_text().splitlines():
        if not line.startswith('{'):
            continue
        event = json.loads(line)
        name = event.get('Test', '')
        if name and '/' not in name:
            if event.get('Action') == 'run':
                ran.add(name)
            if event.get('Action') == 'pass':
                passed.add(name)
        if event.get('Action') in ('fail', 'skip'):
            raise RuntimeError('test failed/skipped')
    if ran != set(expected) or passed != set(expected):
        raise RuntimeError('test enumeration mismatch')
    return sorted(passed)


def benchmark_rows(log):
    rows = {}
    for line in log.read_text().splitlines():
        match = re.match(r'^BenchmarkUDPResolutionContextCost/(\w+)(?:-\d+)?\s+\d+\s+([0-9.]+) ns/op\s+([0-9.]+) B/op\s+([0-9.]+) allocs/op$', line.strip())
        if match:
            rows[match[1]] = dict(ns_per_op=float(match[2]), bytes_per_op=float(match[3]),
                                  allocations_per_op=float(match[4]))
    if set(rows) != set(LOCK['benchmark_cases']):
        raise RuntimeError('benchmark cases missing')
    return rows


def main():
    # Hard refusal on a local host; this script is not a substitute local build.
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('GITHUB_REPOSITORY') != LOCK['repository'] or
            os.environ.get('GITHUB_REF') != LOCK['ref']):
        raise RuntimeError('only the reviewed dedicated remote workflow is allowed')
    OUT.mkdir(parents=True, exist_ok=False)
    result = dict(status='RUNNING', execution_origin='REMOTE_CI', started_utc=utc(),
                  repository=LOCK['repository'], ref=LOCK['ref'],
                  workflow_commit=os.environ['GITHUB_SHA'], run_id=os.environ['GITHUB_RUN_ID'],
                  run_attempt=os.environ['GITHUB_RUN_ATTEMPT'], inputs_sha256=sha(HERE/'inputs.json'),
                  script_sha256=sha(Path(__file__)), tests=[], benchmark_runs=[], binaries={})
    save('result.json', result)
    try:
        env = dict(os.environ, GOOS='linux', GOARCH='amd64', GOAMD64='v1',
                   CGO_ENABLED='0', GOTOOLCHAIN='local', GOWORK='off', GOMAXPROCS='1',
                   GOFLAGS='-mod=readonly -buildvcs=false', GOMEMLIMIT='768MiB',
                   GOPROXY='https://proxy.golang.org', GOSUMDB='sum.golang.org',
                   GOPRIVATE='', GONOPROXY='', GONOSUMDB='', HYSTERIA_DISABLE_UPDATE_CHECK='1')
        version = command(['go', 'version'], ROOT, 'go-version', env).read_text().strip()
        if version != 'go version go1.25.6 linux/amd64':
            raise RuntimeError('toolchain mismatch')
        result['go_binary_sha256'] = sha(Path(shutil.which('go')))
        command(['gcc', '--version'], ROOT, 'race-cc-version', env)
        command(['go', 'env', '-json', 'GOOS', 'GOARCH', 'GOAMD64', 'GOTOOLCHAIN',
                 'GOWORK', 'CGO_ENABLED', 'GOFLAGS', 'GOPROXY', 'GOSUMDB'], ROOT, 'go-env', env)
        if sha(HERE/'benchmark_test.go') != LOCK['benchmark_sha256']:
            raise RuntimeError('benchmark fixture changed')
        if subprocess.check_output(['git', 'diff', '--name-only', LOCK['candidate_commit'],
                                    'HEAD', '--', 'core', 'extras', 'app'], cwd=ROOT).strip():
            raise RuntimeError('runtime source differs from frozen candidate')
        shutil.copyfile(HERE/'inputs.json', OUT/'inputs.json')
        shutil.copyfile(HERE/'actions-lock.json', OUT/'actions-lock.json')
        shutil.copyfile(ROOT/'.github/workflows/pcs-udp-resolution-context.yml', OUT/'workflow.yml')
        with tempfile.TemporaryDirectory(prefix='hy-udp-context-') as temporary:
            area = Path(temporary)
            roots = {arm: area/arm for arm in ('baseline', 'candidate')}
            result['sources'] = {arm: source_archive(LOCK[arm+'_commit'], root) for arm, root in roots.items()}
            save('source-manifests.json', result['sources'])
            # Fetch only actual compilation dependencies, never download all.
            # go list does not execute tests or application code.
            for arm, root in roots.items():
                for module, package in (('core', './server'), ('extras', './outbounds'), ('app', '.')):
                    args = ['go', 'list', '-mod=readonly', '-deps', '-json']
                    if module != 'app':
                        args.append('-test')
                    command(args+[package], root/module, arm+'-deps-'+module, env)
                    module_guard(root)
                    command(['go', 'mod', 'verify'], root/module, arm+'-verify-'+module, env)
            offline = dict(env, GOPROXY='off', GOSUMDB='off')
            for arm, root in roots.items():
                for kind in ('normal', 'race'):
                    for module, package in (('core', './server'), ('extras', './outbounds')):
                        selected = LOCK['tests'][module]['existing'][:]
                        if arm == 'candidate':
                            selected += LOCK['tests'][module]['new']
                        pattern = '^('+'|'.join(selected)+')$'
                        args = ['go', 'test', '-p', '1', '-mod=readonly', '-count=1',
                                '-timeout=60s', '-json', '-run', pattern]
                        if kind == 'race':
                            args.append('-race')
                        log = command(args+[package], root/module, arm+'-'+kind+'-'+module,
                                      dict(offline, CGO_ENABLED='1' if kind == 'race' else '0'))
                        result['tests'].append(dict(arm=arm, kind=kind, module=module,
                                                    passed=verify_tests(log, selected)))
                        module_guard(root)
            # Same tiny fixture in both archives, and a fixed ABBA order.
            for root in roots.values():
                shutil.copyfile(HERE/'benchmark_test.go', root/'extras/outbounds/pcs_context_cost_test.go')
            for index, arm in enumerate(LOCK['benchmark_order']):
                log = command(['go', 'test', '-p', '1', '-mod=readonly', '-run', '^$',
                               '-bench', '^BenchmarkUDPResolutionContextCost$', '-benchmem',
                               '-benchtime=200ms', '-count=1', '-timeout=30s', './outbounds'],
                              roots[arm]/'extras', 'benchmark-'+str(index)+'-'+arm, offline)
                result['benchmark_runs'].append(dict(index=index, arm=arm, cases=benchmark_rows(log)))
            result['benchmark_summary'] = {}
            for case in LOCK['benchmark_cases']:
                result['benchmark_summary'][case] = {
                    arm: {metric: statistics.median(r['cases'][case][metric] for r in result['benchmark_runs'] if r['arm'] == arm)
                          for metric in ('ns_per_op', 'bytes_per_op', 'allocations_per_op')}
                    for arm in roots}
            result['cost_status'] = 'MEASURED_MICROBENCHMARK_ONLY_NOT_DEPLOYMENT_ACCEPTANCE'
            # Runtime artifacts use original archives: no benchmark file included.
            for root in roots.values():
                (root/'extras/outbounds/pcs_context_cost_test.go').unlink()
            for arm, root in roots.items():
                commit = LOCK[arm+'_commit']
                version_tag = LOCK['version_prefix']+'-'+arm
                prefix = 'github.com/apernet/hysteria/app/v2/cmd.'
                values = dict(appVersion=version_tag, appCommit=commit, appDate=LOCK['build_date'],
                              appType='pcs-ci', appToolchain='go1.25.6', appPlatform='linux',
                              appArch='amd64', libVersion=LOCK['quic_go'])
                flags = '-s -w '+' '.join('-X '+prefix+k+'='+v for k, v in values.items())
                binary = OUT/('hysteria-'+arm)
                args = ['go', 'build', '-p', '1', '-mod=readonly', '-trimpath', '-buildvcs=false',
                        '-ldflags='+flags, '-o', str(binary), '.']
                command(args, root/'app', 'build-'+arm, offline)
                module_guard(root)
                command(['go', 'version', '-m', str(binary)], root/'app', 'buildinfo-'+arm, offline)
                result['binaries'][arm] = dict(sha256=sha(binary), bytes=binary.stat().st_size,
                                               source_commit=commit, ldflags=flags, cgo_enabled=False)
                if arm == 'candidate':
                    rebuilt = area/'candidate-rebuilt'
                    args[args.index('-o')+1] = str(rebuilt)
                    command(args, root/'app', 'build-candidate-reproducibility', offline)
                    module_guard(root)
                    if sha(rebuilt) != sha(binary):
                        raise RuntimeError('candidate binary rebuild differed')
                    result['candidate_rebuild_sha256'] = sha(rebuilt)
            result['status'] = 'PASS_SCOPED_TESTS_BUILD_ONLY'
            result['runtime_security_and_cost_acceptance'] = 'NOT_RUN_NOT_DEPLOYMENT_APPROVAL'
    except Exception as error:
        result.update(status='FAIL', failure_type=type(error).__name__, failure_reason=str(error))
        raise
    finally:
        result['ended_utc'] = utc()
        save('result.json', result)
        (OUT/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in sorted(OUT.iterdir()) if p.is_file() and p.name != 'SHA256SUMS'))


if __name__ == '__main__':
    main()
