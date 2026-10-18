#!/usr/bin/env python3
"""Test-only serial workers inside one delegated, aggregate-capped CI unit."""
import datetime
import json
import math
import os
from pathlib import Path
import re
import time
import traceback

MEMORY_MAX = 768 * 1024 * 1024
FILES = ('cpu.max', 'cpu.stat', 'memory.max', 'memory.swap.max',
         'memory.current', 'memory.peak', 'memory.events', 'memory.events.local',
         'memory.stat', 'cgroup.events')


def expected_phases():
    return ([('prepare', 'prepare')] +
            [('build-' + arm + '-' + mode, 'build') for arm in ('baseline', 'candidate') for mode in ('normal', 'race')] +
            [('functional-' + arm + '-' + mode, 'functional') for arm in ('baseline', 'candidate') for mode in ('normal', 'race')] +
            [('cost', 'cost')])


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def counters(value):
    return {key: int(number) for key, number in (line.split() for line in value.splitlines())}


def validate_limits(values):
    quota, period = values['cpu.max'].split()
    if (quota == 'max' or int(period) <= 0 or int(quota) != int(period) or
            int(values['memory.max']) != MEMORY_MAX or values['memory.swap.max'] != '0'):
        raise ValueError('phase resource limits differ')


def validate_parent_location(group, run_id, attempt):
    if not re.fullmatch(r'[0-9]+', run_id) or not re.fullmatch(r'[0-9]+', attempt):
        raise ValueError('invalid workflow identity')
    expected = '/system.slice/pcs-hy-context-chain-' + run_id + '-' + attempt + '.service'
    if group != expected:
        raise ValueError('not the owned aggregate unit')
    return Path('/sys/fs/cgroup' + group)


def owned_child(parent, name):
    if not re.fullmatch(r'phase-[0-9]{2}-[a-z0-9-]+', name):
        raise ValueError('invalid owned phase name')
    child = parent / name
    if child.parent != parent:
        raise ValueError('phase escaped aggregate parent')
    return child


def snapshot(root):
    generation = root.stat()
    values = {name: (root / name).read_text().strip() for name in FILES}
    validate_limits(values)
    final = root.stat()
    if (generation.st_dev, generation.st_ino) != (final.st_dev, final.st_ino):
        raise ValueError('cgroup generation changed during snapshot')
    values.update(cgroup=str(root), device=generation.st_dev, inode=generation.st_ino,
                  captured_utc=utc(), captured_monotonic=time.monotonic(),
                  memory_peak_scope='cumulative_for_this_cgroup_generation')
    return values


def same_generation(before, after):
    return (before['cgroup'] == after['cgroup'] and
            before['device'] == after['device'] and before['inode'] == after['inode'] and
            after['captured_monotonic'] >= before['captured_monotonic'])


def validate_snapshot(value):
    validate_limits(value)
    if (any(not isinstance(value[name],str) or not value[name] for name in FILES) or
            not isinstance(value['device'],int) or value['device']<0 or
            not isinstance(value['inode'],int) or value['inode']<=0 or
            not math.isfinite(value['captured_monotonic']) or
            not Path(value['cgroup']).is_absolute() or not value['captured_utc'] or
            value['memory_peak_scope']!='cumulative_for_this_cgroup_generation'):
        raise ValueError('missing or invalid snapshot identity/counters')
    for name in ('memory.current','memory.peak'):
        if int(value[name])<0:
            raise ValueError('invalid memory gauge')


def event_delta(before, after):
    validate_snapshot(before)
    validate_snapshot(after)
    if not same_generation(before, after):
        raise ValueError('cgroup identity or clock changed')
    old, new = counters(before['memory.events']), counters(after['memory.events'])
    result = {key: new[key] - old[key] for key in ('high', 'max', 'oom', 'oom_kill')}
    if any(value < 0 for value in result.values()):
        raise ValueError('memory events regressed')
    return result


def phase_gate(report):
    try:
        return _phase_gate(report)
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def _phase_gate(report):
    if (report.get('status') != 'COMPLETED' or report.get('exit_code') != 0 or
            report.get('cleanup') != 'owned_empty_cgroup_removed' or
            report.get('errors') or report['kind'] not in ('prepare', 'build', 'functional', 'cost')):
        return False
    if (Path(report['worker_before']['cgroup']) !=
            owned_child(Path(report['parent_before']['cgroup']), report['name'])):
        return False
    if not (report['parent_before']['captured_monotonic'] <= report['worker_before']['captured_monotonic'] <=
            report['worker_after']['captured_monotonic'] <= report['parent_after']['captured_monotonic']):
        return False
    for scope in ('parent', 'worker'):
        before, after = report[scope + '_before'], report[scope + '_after']
        validate_limits(before)
        validate_limits(after)
        delta = event_delta(before, after)
        if any(delta[key] for key in ('high', 'oom', 'oom_kill')):
            return False
        if report['kind'] != 'build' and delta['max']:
            return False
    return True


def write_payload(payload, value, exit_code):
    try:
        with payload.open('x') as target:
            target.write(json.dumps(value, allow_nan=False) + '\n')
        return exit_code
    except BaseException:
        traceback.print_exc()
        return 2


def aggregate_gate(before, after, reports):
    """Only explicitly attributed build max events may be accepted in run6."""
    try:
        validate_limits(before)
        validate_limits(after)
        total = event_delta(before, after)
        previous = before
        for report in reports:
            if not phase_gate(report):
                return False
            # Reports must be serial and refer to this exact aggregate parent.
            event_delta(previous, report['parent_before'])
            previous = report['parent_after']
        event_delta(previous, after)
        allowed_max = sum(event_delta(r['parent_before'], r['parent_after'])['max']
                          for r in reports if r['kind'] == 'build')
        return (bool(reports) and not any(total[k] for k in ('high', 'oom', 'oom_kill')) and
                total['max'] == allowed_max)
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


class PhaseManager:
    def __init__(self, output, parent):
        group = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
        self.parent = validate_parent_location(group, os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT'])
        if self.parent != parent:
            raise ValueError('aggregate identity changed before delegation')
        self.output = output
        self.reports = []
        self.before = snapshot(self.parent)
        if {int(x) for x in (self.parent / 'cgroup.procs').read_text().split()} != {os.getpid()}:
            raise ValueError('aggregate unit has unrelated processes')
        if len(list(Path('/proc/self/task').iterdir())) != 1:
            raise ValueError('phase controller must be single-threaded')
        if not {'cpu', 'memory'} <= set((self.parent / 'cgroup.controllers').read_text().split()):
            raise ValueError('required controllers not delegated')
        control = self.parent / 'control'
        control.mkdir()
        (control / 'cgroup.procs').write_text(str(os.getpid()))
        if (self.parent / 'cgroup.procs').read_text().strip():
            raise ValueError('aggregate parent not empty before delegation')
        (self.parent / 'cgroup.subtree_control').write_text('+cpu +memory')
        (control / 'cpu.max').write_text('100000 100000')
        (control / 'memory.max').write_text(str(96 * 1024 * 1024))
        (control / 'memory.swap.max').write_text('0')
        self.control = control

    def run(self, name, kind, callback, timeout):
        if kind not in ('prepare', 'build', 'functional', 'cost'):
            raise ValueError('unknown phase kind')
        tag = 'phase-%02d-%s' % (len(self.reports), name)
        child = owned_child(self.parent, tag)
        payload = self.output / (tag + '-return.json')
        report = dict(name=tag, kind=kind, status='RUNNING', started_utc=utc(), errors=[])
        created = False
        try:
            report['parent_before'] = snapshot(self.parent)
            child.mkdir()
            created = True
            for filename, value in (('cpu.max', '100000 100000'), ('memory.max', str(MEMORY_MAX)), ('memory.swap.max', '0')):
                (child / filename).write_text(value)
            if not (child / 'cgroup.kill').is_file():
                raise ValueError('owned cgroup kill unavailable')
            report['worker_before'] = snapshot(child)
            pid = os.fork()
            if pid == 0:
                exit_code = 1
                try:
                    (child / 'cgroup.procs').write_text(str(os.getpid()))
                    actual = next(x.split(':', 2)[2] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
                    if Path('/sys/fs/cgroup' + actual) != child:
                        raise ValueError('worker did not enter owned cgroup')
                    value = {'status': 'PASS', 'value': callback()}
                    exit_code = 0
                except BaseException as error:
                    value = {'status': 'FAIL', 'error_type': type(error).__name__, 'error': str(error), 'traceback': traceback.format_exc()}
                os._exit(write_payload(payload,value,exit_code))
            deadline = time.monotonic() + timeout
            timed_out = False
            while True:
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited:
                    report['exit_code'] = os.waitstatus_to_exitcode(status)
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    (child / 'cgroup.kill').write_text('1')
                    _, status = os.waitpid(pid, 0)
                    report['exit_code'] = os.waitstatus_to_exitcode(status)
                    break
                time.sleep(.02)
            report['status'] = 'TIMED_OUT' if timed_out else 'COMPLETED'
        except BaseException as error:
            report['status'] = 'CONTROLLER_ERROR'
            report['errors'].append(dict(stage='run', type=type(error).__name__, message=str(error)))
            raise
        finally:
            # The unit-level hard timeout also covers this controller and every
            # delegated descendant. Never kill a path outside this owned child.
            for scope, root in (('worker', child), ('parent', self.parent)):
                if scope == 'worker' and not created:
                    continue
                try:
                    report[scope + '_after'] = snapshot(root)
                except BaseException as error:
                    report['errors'].append(dict(stage=scope + '_after', type=type(error).__name__, message=str(error)))
                if scope == 'worker':
                    try:
                        if counters((child / 'cgroup.events').read_text())['populated']:
                            (child / 'cgroup.kill').write_text('1')
                            report['cleanup'] = 'unexpected_remaining_owned_processes'
                            # Explicit failure even if cleanup succeeds afterward.
                            deadline = time.monotonic() + 2
                            while counters((child / 'cgroup.events').read_text())['populated'] and time.monotonic() < deadline:
                                time.sleep(.02)
                            if not counters((child / 'cgroup.events').read_text())['populated']:
                                child.rmdir()
                        else:
                            child.rmdir()
                            report['cleanup'] = 'owned_empty_cgroup_removed'
                    except BaseException as error:
                        report['errors'].append(dict(stage='cleanup', type=type(error).__name__, message=str(error)))
            report['ended_utc'] = utc()
            self.reports.append(report)
            with (self.output / (tag + '.json')).open('x') as target:
                target.write(json.dumps(report, indent=2) + '\n')
        if not phase_gate(report):
            raise RuntimeError('phase functional/resource failure: ' + tag)
        if payload.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('phase return exceeds bound')
        value = json.loads(payload.read_text())
        if value['status'] != 'PASS':
            raise RuntimeError('phase body failed: ' + tag)
        return value['value']
