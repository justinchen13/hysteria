#!/usr/bin/env python3
"""PREPARED remote-only pure contract/cost runner; no workflow or CLI launch."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def budgets():
    group=next(line.split(':',2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
    root=Path('/sys/fs/cgroup'+group)
    values={name:(root/name).read_text().strip() for name in ('cpu.max','cpu.stat','memory.max','memory.swap.max','memory.events')}
    quota,period=values['cpu.max'].split()
    if quota=='max' or int(quota)/int(period)>1 or values['memory.max']=='max' or int(values['memory.max'])>768*1024*1024 or values['memory.swap.max']!='0':
        raise RuntimeError('remote CPU/memory/swap budget not applied')
    return values


def parse_bench(path):
    rows={}
    for line in path.read_text().splitlines():
        fields=line.split()
        if not fields or not fields[0].startswith('BenchmarkPCSUDPContextPipeline/'):
            continue
        name=re.sub(r'-\d+$','',fields[0].split('/',1)[1])
        values={fields[index+1]:float(fields[index]) for index in range(2,len(fields)-1,2)}
        if set(values)!= {'ns/op','cpu-ns/op','B/op','allocs/op'} or name in rows:
            raise ValueError('benchmark metrics')
        rows[name]=dict(iterations=int(fields[1]),**values)
    wanted={prefix+case for prefix in ('feed_','snapshot_') for case in ('success_cache','supplied_no_ipv4_error','cache_fill_then_failed_write')}
    if set(rows)!=wanted:
        raise ValueError('benchmark enumeration')
    return rows


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser()
    parser.add_argument('--repository-dir',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();plan=json.loads((HERE/'plan.json').read_text())
    if plan['status']!='ROOT_REVIEWED_REMOTE_ONLY' or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('GITHUB_REPOSITORY')!=plan['repository'] or os.environ.get('GITHUB_REF')!=plan['ref']:
        raise RuntimeError('unreviewed or non-dedicated remote execution refused')
    for name,digest in plan['fixture_sha256'].items():
        if sha(HERE/name)!=digest:
            raise ValueError('fixture changed: '+name)
    helper=args.repository_dir/plan['helper_path']
    if sha(helper)!=plan['helper_sha256']:
        raise ValueError('existing remote helper changed')
    if shutil.disk_usage(HERE).free<1024**3:
        raise RuntimeError('less than 1GiB remote free space')
    before=budgets();args.output.mkdir(parents=True,exist_ok=False)
    spec=importlib.util.spec_from_file_location('reviewed_remote_helper',helper)
    base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    base.ROOT=args.repository_dir;base.OUT=args.output
    result={'status':'RUNNING','execution_origin':'REMOTE_CI_PURE_ONLY','started_utc':base.utc(),'resources_before':before,'sources':{},'functional':[],'benchmark_runs':[],'consumer_runs':[], 'plan_sha256':sha(HERE/'plan.json'),'fixture_sha256':plan['fixture_sha256'],'workflow_commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),'run_attempt':os.environ.get('GITHUB_RUN_ATTEMPT')}
    shutil.copyfile(HERE/'plan.json',args.output/'plan.json')
    base.save('result.json',result)
    try:
        env=dict(os.environ,GOOS='linux',GOARCH='amd64',GOAMD64='v1',CGO_ENABLED='0',GOTOOLCHAIN='local',GOWORK='off',GOMAXPROCS='1',GOMEMLIMIT='512MiB',GOFLAGS='-mod=readonly -buildvcs=false',GOPROXY='https://proxy.golang.org',GOSUMDB='sum.golang.org',GOPRIVATE='',GONOPROXY='',GONOSUMDB='')
        if base.command(['go','version'],args.repository_dir,'go-version',env).read_text().strip()!='go version go1.25.6 linux/amd64':
            raise ValueError('toolchain changed')
        with tempfile.TemporaryDirectory(prefix='pcs-context-chain-') as temp:
            roots={arm:Path(temp)/arm for arm in ('baseline','candidate')}
            for arm,root in roots.items():
                result['sources'][arm]=base.source_archive(plan['sources'][arm],root)
                shutil.copyfile(HERE/'core_bridge.go',root/'core/server/pcs_context_contract_bridge.go')
                shutil.copyfile(HERE/'contract_test.go',root/'extras/outbounds/pcs_context_contract_test.go')
                base.command(['go','list','-mod=readonly','-tags=pcs_udp_context_contract','-deps','-test','-json','./outbounds'],root/'extras',arm+'-deps',env)
                for module in ('core','extras'):
                    base.module_guard(root)
                    base.command(['go','mod','verify'],root/module,arm+'-verify-'+module,env)
            base.save('source-manifests.json',result['sources'])
            offline=dict(env,GOPROXY='off',GOSUMDB='off')
            for arm,root in roots.items():
                for mode in ('normal','race'):
                    corpus=args.output/(arm+'-'+mode+'-producer.jsonl')
                    command=['go','test','-p','1','-mod=readonly','-tags=pcs_udp_context_contract','-count=1','-timeout=30s','-json','-run','^TestPCSUDPContextContract$']
                    if mode=='race':command+=['-race']
                    log=base.command(command+['./outbounds'],root/'extras',arm+'-'+mode,dict(offline,PCS_CONTRACT_OUTPUT=str(corpus),CGO_ENABLED='1' if mode=='race' else '0'),timeout=240)
                    passed=base.verify_tests(log,['TestPCSUDPContextContract'])
                    base.module_guard(root)
                    consumer=None
                    if mode=='normal':
                        dest=args.output/(arm+'-'+mode+'-consumer.json')
                        base.command(['python3',str(HERE/'consumer.py'),'--module',str(HERE/('consumer-'+arm+'.py')),'--corpus',str(corpus),'--arm',arm,'--mode','functional','--output',str(dest)],HERE,arm+'-'+mode+'-consumer',offline,timeout=30)
                        consumer=json.loads(dest.read_text())
                    result['functional'].append(dict(arm=arm,mode=mode,passed=passed,consumer=consumer))
            for index,arm in enumerate(plan['producer_order']):
                log=base.command(['go','test','-p','1','-mod=readonly','-tags=pcs_udp_context_contract','-run','^$','-bench','^BenchmarkPCSUDPContextPipeline$','-benchmem','-benchtime=250ms','-count=1','-timeout=30s','./outbounds'],roots[arm]/'extras','producer-cost-'+str(index)+'-'+arm,offline,timeout=60)
                result['benchmark_runs'].append(dict(index=index,arm=arm,cases=parse_bench(log)))
            for case in ('success_cache','cache_fill_then_failed_write'):
                for index,arm in enumerate(plan['consumer_order']):
                    dest=args.output/('consumer-cost-'+case+'-'+str(index)+'-'+arm+'.json')
                    base.command(['python3',str(HERE/'consumer.py'),'--module',str(HERE/('consumer-'+arm+'.py')),'--corpus',str(args.output/(arm+'-normal-producer.jsonl')),'--arm',arm,'--mode','cost','--case',case,'--output',str(dest)],HERE,dest.stem,offline,timeout=30)
                    result['consumer_runs'].append(dict(index=index,arm=arm,case=case,measurement=json.loads(dest.read_text())))
            for arm,root in roots.items():
                base.module_guard(root)
                for name,digest in result['sources'][arm]['files_sha256'].items():
                    if sha(root/name)!=digest:raise ValueError('original source changed')
            result['status']='PASS_PURE_CONTRACT_MEASURED_COST_PENDING_ADJUDICATION'
            result['limits']=plan['limits']
    except Exception as error:
        result.update(status='FAIL',error_type=type(error).__name__,error=str(error))
        raise
    finally:
        result.update(ended_utc=base.utc(),resources_after=budgets())
        base.save('result.json',result)
        (args.output/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in sorted(args.output.iterdir()) if p.is_file() and p.name!='SHA256SUMS'))


if __name__=='__main__':main()
