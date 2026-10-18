#!/usr/bin/env python3
"""Pure result adjudication; no test, program, network or production execution."""
import argparse
import json
from pathlib import Path
import statistics


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('directory',type=Path)
    parser.add_argument('--plan',type=Path,default=Path(__file__).with_name('plan.json'))
    args=parser.parse_args()
    data=json.loads((args.directory/'result.json').read_text())
    plan=json.loads(args.plan.read_text());gates={};report={'status':'HOLD','gates':gates}
    functions=data['functional'];normal=[x for x in functions if x['mode']=='normal']
    gates['producer_consumer_functional']=data['status']=='PASS_PURE_CONTRACT_MEASURED_COST_PENDING_ADJUDICATION' and {(x['arm'],x['mode']) for x in functions}=={(a,m) for a in ('baseline','candidate') for m in ('normal','race')} and len(functions)==4 and all(x['passed']==['TestPCSUDPContextContract'] for x in functions) and len(normal)==2 and all(x['consumer']['status']=='PASS' and len(x['consumer']['results'])==7 for x in normal)
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
    before=data['resources_before'];after=data['resources_after']
    parse=lambda s:{key:int(value) for key,value in (line.split() for line in s.splitlines())}
    gates['memory_budget']=all(parse(after['memory.events']).get(k,0)-parse(before['memory.events']).get(k,0)==0 for k in ('high','max','oom','oom_kill'))
    if all(gates.values()):report['status']='PURE_DIAGNOSTIC_CONTRACT_AND_BUDGET_PASS'
    report['failed_gates']=[k for k,v in gates.items() if not v]
    report['release_scope']='No production changes or network/TLS/QUIC validation occurred. Root coordinates formal identity and monitored single-service deployment separately.'
    (args.directory/'adjudication.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
