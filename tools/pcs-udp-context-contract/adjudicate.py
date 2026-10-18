#!/usr/bin/env python3
"""Pure result adjudication; no test, program, network or production execution."""
import argparse
import json
from pathlib import Path
import statistics
import re
import phase_cgroup


def staged_resource_contract(data):
    reports=data.get('phase_resources',[])
    expected=[('phase-%02d-%s'%(i,name),kind) for i,(name,kind) in enumerate(phase_cgroup.expected_phases())]
    return (data.get('resource_contract')=='staged_v6_build_only_max_exception' and
            [(r.get('name'),r.get('kind')) for r in reports]==expected and
            phase_cgroup.aggregate_gate(data.get('resources_before'),data.get('resources_after'),reports))


def binary_contract(data,plan,artifact):
    try:
        records=data['test_binaries']
        if artifact!=records or set(records)!={'baseline','candidate'}:
            return False
        for arm in ('baseline','candidate'):
            if set(records[arm])!={'normal','race'}:
                return False
            for mode in ('normal','race'):
                row=records[arm][mode]
                if (row['source_commit']!=plan['sources'][arm] or row['mode']!=mode or
                        row['toolchain']!='go1.25.6' or not re.fullmatch('[0-9a-f]{64}',row['sha256'])):
                    return False
                functional=[f for f in data['functional'] if f['arm']==arm and f['mode']==mode]
                if len(functional)!=1 or functional[0]['binary_sha256']!=row['sha256']:
                    return False
        return all(r['binary_sha256']==records[r['arm']]['normal']['sha256'] for r in data['benchmark_runs'])
    except (KeyError,TypeError,ValueError):
        return False


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('directory',type=Path)
    parser.add_argument('--plan',type=Path,default=Path(__file__).with_name('plan.json'))
    args=parser.parse_args()
    data=json.loads((args.directory/'result.json').read_text())
    plan=json.loads(args.plan.read_text());gates={};report={'status':'HOLD','gates':gates}
    functions=data['functional'];normal=[x for x in functions if x['mode']=='normal']
    gates['producer_consumer_functional']=data['status']=='PASS_PURE_CONTRACT_MEASURED_COST_PENDING_ADJUDICATION' and {(x['arm'],x['mode']) for x in functions}=={(a,m) for a in ('baseline','candidate') for m in ('normal','race')} and len(functions)==4 and all(x['passed']==['TestPCSUDPContextContract'] for x in functions) and len(normal)==2 and all(x['consumer']['status']=='PASS' and len(x['consumer']['results'])==7 for x in normal)
    expected_complete={'success_cache','supplied_no_ipv4_error','cache_fill_then_failed_write','dns_timeout','no_address'}
    expected_overload={'success_cache','cache_fill_then_failed_write'}
    def coverage_valid(results):
        complete=[r for r in results if r.get('coverage')=='complete_single_session']
        overload=[r for r in results if r.get('coverage')=='bounded_overload']
        return (len(complete)==5 and {r['case'] for r in complete}==expected_complete and
                len(overload)==2 and {r['case'] for r in overload}==expected_overload and
                all(r['population']==1 and r['calls']==8 and r['unobserved_calls']==0 and r['retained_sessions']==1 for r in complete) and
                all(r['population']==128 and 0<r['previous_retained_sessions']<=128 and
                    r['calls']==8*r['previous_retained_sessions'] and
                    r['unobserved_calls']==8*(128-r['previous_retained_sessions']) and
                    r['fresh_counter_baselines']==128-r['previous_retained_sessions'] and
                    r['initial']['quality'].get('state_byte_limit_evictions',0)==r['fresh_counter_baselines'] and
                    r['update_quality'].get('state_byte_limit_evictions',0)==128-r['retained_sessions'] for r in overload) and
                all(r['input_calls']==8*r['population'] and r['calls']+r['unobserved_calls']==r['input_calls'] and
                    r['same_clock_rejected'] and r['later_poll_replay_deduplicated'] and r['state_bytes']<=262144 for r in results))
    gates['functional_coverage_contract']=len(normal)==2 and all(coverage_valid(x['consumer']['results']) for x in normal)
    runs=data['benchmark_runs']
    gates['frozen_order']= [x['arm'] for x in runs]==plan['producer_order']
    cases={name for run in runs for name in run['cases']};summary={}
    for case in sorted(cases):
        summary[case]={arm:{metric:statistics.median(run['cases'][case][metric] for run in runs if run['arm']==arm) for metric in ('cpu-ns/op','ns/op','B/op','allocs/op')} for arm in ('baseline','candidate')}
    report['producer_medians']=summary
    gates['measured_cpu_floor']=all(run['cases'][case]['cpu-ns/op']*run['cases'][case]['iterations']>=plan['budgets']['producer_min_cpu_seconds_per_case']*1e9 for run in runs for case in cases)
    success=summary['feed_success_cache'];a=success['baseline'];b=success['candidate']
    gates['success_hot_path_cpu']= b['cpu-ns/op']<=a['cpu-ns/op']*1.20 or b['cpu-ns/op']-a['cpu-ns/op']<=100
    gates['success_no_extra_allocations']=b['allocs/op']<=a['allocs/op'] and b['B/op']<=a['B/op']
    errors=[summary[name] for name in ('feed_supplied_no_ipv4_error','feed_cache_fill_then_failed_write')]
    gates['error_cpu_budget']=all(x['candidate']['cpu-ns/op']-x['baseline']['cpu-ns/op']<=5000 for x in errors)
    gates['error_allocation_budget']=all(x['candidate']['allocs/op']-x['baseline']['allocs/op']<=16 and x['candidate']['B/op']-x['baseline']['B/op']<=1024 for x in errors)
    snapshots=[summary[name] for name in cases if name.startswith('snapshot_')]
    gates['snapshot_cpu_budget']=all(x['candidate']['cpu-ns/op']-x['baseline']['cpu-ns/op']<=20000 for x in snapshots)
    consumer={}
    for case in ('success_cache','cache_fill_then_failed_write'):
        selected=[r for r in data['consumer_runs'] if r['case']==case]
        gates['consumer_order_'+case]=[x['arm'] for x in selected]==plan['consumer_order']
        consumer[case]={arm:{key:statistics.median(x['measurement']['results'][key] for x in selected if x['arm']==arm) for key in ('cpu_seconds_per_update','wall_seconds_per_update','process_peak_rss_kib','max_state_bytes')} for arm in ('baseline','candidate')}
        gates['consumer_fixed_budget_'+case]=all(x['measurement']['status']=='PASS' and x['measurement']['results']['cpu_seconds_per_update']<=.05 and x['measurement']['results']['wall_seconds_per_update']<=.5 and x['measurement']['results']['process_peak_rss_kib']<=96*1024 and x['measurement']['results']['max_state_bytes']<=262144 for x in selected)
        gates['consumer_extra_cpu_'+case]=consumer[case]['candidate']['cpu_seconds_per_update']-consumer[case]['baseline']['cpu_seconds_per_update']<=.01
    report['consumer_medians']=consumer
    # Compare actual serialized producer envelopes. All content is synthetic;
    # aliases/times differ but lengths are retained as measured, not normalized.
    sizes={}
    for arm in ('baseline','candidate'):
        sizes[arm]={}
        for line in (args.directory/(arm+'-normal-producer.jsonl')).read_text().splitlines():
            row=json.loads(line)
            if row['population']==1 and row['phase']==1:
                sizes[arm][row['case']]=len(json.dumps(row['raw'],separators=(',',':')).encode())
    report['serialized_json_bytes']=sizes
    gates['extra_json_bytes']=all(sizes['candidate'][case]-sizes['baseline'][case]<=512 for case in sizes['baseline'])
    success_extra=max(0,b['cpu-ns/op']-a['cpu-ns/op'])/1e9
    error_extra=max(max(0,x['candidate']['cpu-ns/op']-x['baseline']['cpu-ns/op']) for x in errors)/1e9
    snapshot_extra=max(max(0,x['candidate']['cpu-ns/op']-x['baseline']['cpu-ns/op']) for x in snapshots)/1e9
    consumer_extra=max(max(0,x['candidate']['cpu_seconds_per_update']-x['baseline']['cpu_seconds_per_update']) for x in consumer.values())
    report['modeled_incremental_cpu_core']=10000*success_extra+1000*error_extra+64*snapshot_extra+consumer_extra/10
    report['model_scope']='Conservative stated-rate arithmetic only: 10k successful pure Feed/s, 1k errors/s, existing maximum64 emitted records/s, one128-member state update/10s. Not actual UDP/TLS/server throughput or a deployment safety proof.'
    gates['modeled_incremental_budget']=report['modeled_incremental_cpu_core']<=.01
    gates['staged_resource_budget']=staged_resource_contract(data)
    try:
        binary_artifact=json.loads((args.directory/'test-binaries.json').read_text())
    except (OSError,ValueError):
        binary_artifact=None
    gates['fixed_functionally_qualified_cost_binary']=binary_contract(data,plan,binary_artifact)
    report['resource_contract']='New run6 staged contract. Run5 whole-unit memory.max HOLD remains unchanged. Only build-phase max events may be attributed as compilation pressure; all other phases and the corresponding full parent windows require zero high/max/OOM/kill deltas. Missing counters/generation/limits fail closed.'
    report['resource_peak_semantics']='Every memory.peak is cumulative for its own cgroup generation. Parent peak includes prior build/cache and is not a cost-specific peak. Fresh worker peak covers only that worker, but cannot replace parent-window event checks.'
    report['phase_resource_summary']=[]
    for phase in data.get('phase_resources',[]):
        item={'name':phase.get('name'),'kind':phase.get('kind'),'pass':phase_cgroup.phase_gate(phase)}
        for scope in ('parent','worker'):
            try:
                item[scope+'_memory_events_delta']=phase_cgroup.event_delta(phase[scope+'_before'],phase[scope+'_after'])
                item[scope+'_memory_peak_cumulative_bytes']=int(phase[scope+'_after']['memory.peak'])
            except (KeyError,TypeError,ValueError):
                item[scope+'_memory_events_delta']=None
                item[scope+'_memory_peak_cumulative_bytes']=None
        report['phase_resource_summary'].append(item)
    if all(gates.values()):report['status']='PURE_DIAGNOSTIC_CONTRACT_AND_BUDGET_PASS'
    report['failed_gates']=[k for k,v in gates.items() if not v]
    report['release_scope']='No production changes or network/TLS/QUIC validation occurred. Root coordinates formal identity and monitored single-service deployment separately.'
    (args.directory/'adjudication.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
