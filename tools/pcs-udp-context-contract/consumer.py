#!/usr/bin/env python3
"""Test-only actual producer-record -> real consumer persistence/cost driver."""
import argparse
import collections
import importlib.util
import json
import os
from pathlib import Path
import resource
import tempfile
import time

EPOCH = dict(container_id='a'*12, image='sha256:'+'b'*64,
             started_at='2026-10-18T00:00:00Z', issues=[])
CASES = {'success_cache': None, 'supplied_no_ipv4_error': 'no_ipv4',
         'cache_fill_then_failed_write': 'no_ipv4', 'dns_timeout': 'dns_timeout',
         # WriteTo wraps supplied resolution failures in resolveError; its
         # top-level class is dns_other. Candidate resolution detail remains
         # no_address and is asserted separately below.
         'no_address': 'dns_other'}


def load_module(path):
    spec = importlib.util.spec_from_file_location('actual_evidence', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def corpus(path):
    if path.stat().st_size > 8*1024*1024:
        raise ValueError('corpus too large')
    grouped = collections.defaultdict(lambda: {0: {}, 1: {}})
    with path.open() as source:
        for line in source:
            if len(line) > 20000:
                raise ValueError('record too large')
            row = json.loads(line)
            case, population, member, phase = (row[k] for k in ('case','population','member','phase'))
            if case not in CASES or population not in (1,128) or type(member) is not int or not 0 <= member < population or phase not in (0,1):
                raise ValueError('corpus identity')
            if row['raw']['msg'] != 'quic_evidence' or member in grouped[(case,population)][phase]:
                raise ValueError('duplicate or wrong envelope')
            grouped[(case,population)][phase][member] = row['raw']['evidence']
    expected = {(case,1) for case in CASES} | {('success_cache',128),('cache_fill_then_failed_write',128)}
    if set(grouped) != expected:
        raise ValueError('case enumeration')
    for (_, population), phases in grouped.items():
        for rows in phases.values():
            if set(rows) != set(range(population)):
                raise ValueError('missing member')
    return grouped


def batch(module, rows):
    return [module.sanitize(rows[index]) for index in sorted(rows)]


def record(module, state, records, *, collector_now=None):
    now = max(row['capture_unix'] for row in records) + .005 if collector_now is None else collector_now
    result = state.record(EPOCH, records, {}, now)
    if state.error or result.get('availability') != 'h1_observed':
        raise ValueError('actual persistence failure')
    if state.path.stat().st_size > module.MAX_STATE or (state.path.stat().st_mode & 0o777) != 0o600:
        raise ValueError('state bound/permissions')
    return result


def functional(module, groups, arm):
    outcomes = []
    for (case, population), phases in groups.items():
        with tempfile.TemporaryDirectory(prefix='pcs-context-contract-') as directory:
            state = module.EvidenceState(Path(directory))
            initial = record(module, state, batch(module, phases[0]))
            initial_summary = dict(retained_sessions=initial['retained_sessions'],
                                   state_bytes=state.path.stat().st_size,
                                   quality=dict(initial['batch']['quality']))
            state = module.EvidenceState(Path(directory))
            if not state.restarted:
                raise ValueError('restart did not load state')
            advancing = batch(module, phases[1])
            incoming_ids = {row['session'] for row in advancing}
            retained_ids = set(state.state['sessions'])
            if len(incoming_ids) != population or not retained_ids <= incoming_ids:
                raise ValueError('unexpected retained counter identity')
            known = len(retained_ids)
            missing = population - known
            if population == 1 and (known != 1 or initial['batch']['quality'].get('state_byte_limit_evictions', 0)):
                raise ValueError('single-session complete baseline missing')
            if initial['batch']['quality'].get('state_byte_limit_evictions', 0) != missing:
                raise ValueError('initial omitted sessions not explicitly reported')
            for entry in state.state['sessions'].values():
                if (entry['counters'].get('udp.target_write_calls') != 0 or
                        entry['counters'].get('udp.target_write_errors') != 0 or
                        entry['counters'].get('udp.target_written_bytes') != 0 or
                        'udp_error_cursor' not in entry):
                    raise ValueError('retained counter chain lacks known zero baseline')
            result = record(module, state, advancing)
            deltas = result['batch']['observed_counter_deltas']
            # 128 is an input/capacity stress population, not a promise that128
            # complete counter chains fit the independent256KiB state bound.
            # Only identities proven present before this update may yield deltas.
            expected_calls = 8*known
            if deltas.get('sessions.udp.target_write_calls') != expected_calls:
                detail=dict(case=case,population=population,phase='after_phase1',
                            expected_calls=expected_calls,input_calls=8*population,
                            previous_retained_sessions=known,unobserved_calls=8*missing,
                            actual_calls=deltas.get('sessions.udp.target_write_calls'),
                            initial=initial_summary,retained_sessions=result['retained_sessions'],
                            state_bytes=state.path.stat().st_size,
                            quality=dict(result['batch']['quality']),
                            baseline_fields=dict(result['batch']['baseline_fields']),
                            udp_deltas={k:v for k,v in deltas.items() if k.startswith('sessions.udp.')})
                raise ValueError('actual Feed calls lost: '+json.dumps(detail,sort_keys=True))
            for field in ('sessions.udp.target_write_calls', 'sessions.udp.target_write_errors',
                          'sessions.udp.target_written_bytes', 'sessions.udp.error_detail.complete_snapshot'):
                if result['batch']['baseline_fields'].get(field, 0) != missing:
                    raise ValueError('missing chains not reported as fresh baselines')
            expected_errors = expected_calls if CASES[case] else 0
            if deltas.get('sessions.udp.target_write_errors',0) != expected_errors:
                raise ValueError('actual error counts lost')
            if deltas.get('sessions.udp.target_written_bytes',0) != (0 if CASES[case] else 512*known):
                raise ValueError('actual successful payload count changed')
            if expected_errors and deltas.get('sessions.udp.error_detail.target_write.'+CASES[case]) != expected_errors:
                raise ValueError('actual classified error delta lost')
            state = module.EvidenceState(Path(directory))
            retained_after = len(state.state['sessions'])
            if not state.restarted or not 0 < retained_after <= population:
                raise ValueError('counter chain/restart invalid')
            if result['batch']['quality'].get('state_byte_limit_evictions', 0) != population-retained_after:
                raise ValueError('post-update omitted sessions not explicitly reported')
            if population == 1 and retained_after != 1:
                raise ValueError('single-session complete counter chain lost')
            contexts = []
            for entry in state.state['sessions'].values():
                detail = entry['snapshot'].get('udp',{}).get('error_detail',{})
                contexts += [last.get('outbound') for last in detail.get('latest',[]) if 'outbound' in last]
            if arm == 'baseline' and contexts:
                raise ValueError('legacy emitted new context')
            if not expected_errors and contexts:
                raise ValueError('success invented an error context')
            if arm == 'candidate' and CASES[case]:
                if not contexts and population == 1:
                    raise ValueError('all outbound contexts missing')
                if not contexts and result['batch']['quality'].get('udp_error_detail_context_evictions', 0) == 0:
                    raise ValueError('missing optional contexts not explicitly reported')
                for context in contexts:
                    if set(context) != {'availability','target_kind','resolution_path','resolved_ipv4_present','resolved_ipv6_present','cache_hit','cache_age_at_error_ms','resolution_error_class','selected_family'}:
                        raise ValueError('optional context fields differ')
                    if context.get('availability') != 'supported' or context['target_kind'] != 'hostname' or context['selected_family'] != 'unknown':
                        raise ValueError('new context incorrect')
                    wanted = 'cache_hit' if case == 'cache_fill_then_failed_write' else 'supplied'
                    if context['resolution_path'] != wanted:
                        raise ValueError('actual resolution path lost')
                    wanted_error = 'dns_timeout' if case=='dns_timeout' else 'no_address' if case=='no_address' else 'none'
                    if context['resolution_error_class'] != wanted_error:
                        raise ValueError('resolver error class changed')
                    if context['resolved_ipv4_present'] is not False or context['resolved_ipv6_present'] is not (case in ('supplied_no_ipv4_error','cache_fill_then_failed_write')):
                        raise ValueError('actual family presence lost')
                    if wanted == 'cache_hit' and (context['cache_hit'] is not True or type(context['cache_age_at_error_ms']) is not int or context['cache_age_at_error_ms'] < 0):
                        raise ValueError('cache hit/age lost')
                    if wanted == 'supplied' and (context['cache_hit'] is not None or context['cache_age_at_error_ms'] is not None):
                        raise ValueError('unknown cache values became false/zero')
            encoded = state.path.read_bytes()
            if any(value in encoded for value in (b'PRIVATE-CANARY', b'synthetic.invalid', b'2001:db8')):
                raise ValueError('privacy violation')
            # The producer record is replayed unchanged at a later collector
            # poll, not at the prior poll's identical clock value. Retain that
            # invalid same-clock invocation as an explicit negative control.
            replay_records = batch(module, phases[1])
            last_poll = state.state['last_poll_unix']
            previous_state = json.dumps(state.state, sort_keys=True)
            try:
                state.update(EPOCH, replay_records, {}, last_poll)
            except ValueError as error:
                if str(error) != 'non-increasing collector clock':
                    raise
            else:
                raise ValueError('same-clock negative control unexpectedly accepted')
            if json.dumps(state.state, sort_keys=True) != previous_state or state.path.read_bytes() != encoded:
                raise ValueError('same-clock rejection changed persistent state')
            repeated = record(module, state, replay_records, collector_now=last_poll+.005)
            if state.state['last_poll_unix'] <= last_poll:
                raise ValueError('replay collector clock did not advance')
            if any(value for key,value in repeated['batch']['observed_counter_deltas'].items() if key.startswith('sessions.udp.')):
                raise ValueError('restart replay double counted')
            if repeated['batch']['quality'].get('duplicate_evidence_records', 0) != population:
                raise ValueError('replay not accounted as unchanged source records')
            outcomes.append(dict(case=case,population=population,
                                 coverage='complete_single_session' if population==1 else 'bounded_overload',
                                 input_calls=8*population,calls=expected_calls,
                                 unobserved_calls=8*missing,
                                 errors=expected_errors,retained_contexts=len(contexts),
                                 previous_retained_sessions=known,retained_sessions=retained_after,
                                 fresh_counter_baselines=missing,initial=initial_summary,
                                 update_quality=dict(result['batch']['quality']),
                                 same_clock_rejected=True,later_poll_replay_deduplicated=True,
                                 state_bytes=len(encoded),quality=dict(state.state['quality'])))
    return outcomes


def cost(module, groups, case, repeats):
    phases = groups[(case,128)]
    encoded_final = [json.dumps(phases[1][index]) for index in sorted(phases[1])]
    cpu = wall = 0.0
    maximum_state = 0
    # Every measured iteration is a genuine advancing update with128 input
    # records and existing bounded retention. Initial baseline/fsync is setup
    # outside the timer; no fake
    # clocks, edited producer counters or replay-only cheap path are timed.
    for _ in range(repeats):
        with tempfile.TemporaryDirectory(prefix='pcs-context-cost-') as directory:
            state = module.EvidenceState(Path(directory))
            record(module, state, batch(module, phases[0]))
            began_cpu, began_wall = time.process_time(), time.monotonic()
            records = [module.sanitize(json.loads(row)) for row in encoded_final]
            record(module, state, records)
            wall += time.monotonic()-began_wall
            cpu += time.process_time()-began_cpu
            maximum_state = max(maximum_state,state.path.stat().st_size)
    return dict(case=case,population=128,repeats=repeats,process_cpu_seconds=cpu,
                measured_wall_seconds=wall,cpu_seconds_per_update=cpu/repeats,
                wall_seconds_per_update=wall/repeats,max_state_bytes=maximum_state,
                process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                scope='producer JSON -> parse -> sanitize -> real advancing EvidenceState.record with flush/fsync/replace; excludes corpus file IO, initial baseline and full monitor API/ss/TLS')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--module',type=Path,required=True)
    parser.add_argument('--corpus',type=Path,required=True)
    parser.add_argument('--arm',choices=['baseline','candidate'],required=True)
    parser.add_argument('--mode',choices=['functional','cost'],required=True)
    parser.add_argument('--case',choices=['success_cache','cache_fill_then_failed_write'])
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        raise ValueError('output already exists')
    resource.setrlimit(resource.RLIMIT_AS,(96*1024*1024,96*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU,(30,30))
    module=load_module(args.module);groups=corpus(args.corpus)
    value={'arm':args.arm,'mode':args.mode,'status':'RUNNING'}
    try:
        value['results']=functional(module,groups,args.arm) if args.mode=='functional' else cost(module,groups,args.case,1)
        value['status']='PASS'
    except Exception as error:
        value.update(status='FAIL',error_type=type(error).__name__,error=str(error))
        raise
    finally:
        args.output.write_text(json.dumps(value,indent=2)+'\n')


if __name__=='__main__':
    main()
