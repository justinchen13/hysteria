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
import phase_cgroup

HERE=Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def consumer_command_name(destination):
    # Command metadata must never replace the consumer's measured JSON result.
    return destination.stem+'-command'


def output_layout(plan):
    names={}
    def reserve(name,role):
        if name in names:
            raise ValueError('output path collision: '+name)
        names[name]=role
    def command(name):
        reserve(name+'.json','command_metadata')
        reserve(name+'.log','command_log')
    for name in ('result.json','plan.json','source-manifests.json','output-layout.json','test-binaries.json',
                 'SHA256SUMS','adjudication.json','workflow-provenance.json',
                 'actions-lock.json','pcs-udp-context-contract.yml',
                 'workflow-execution.log','workflow-execution.exit'):
        reserve(name,'summary_or_provenance')
    command('go-version')
    for index,(name,kind) in enumerate(phase_cgroup.expected_phases()):
        reserve('phase-%02d-%s.json'%(index,name),'phase_resource_report')
        reserve('phase-%02d-%s-return.json'%(index,name),'phase_return')
    for arm in ('baseline','candidate'):
        command(arm+'-deps')
        for module in ('core','extras'):command(arm+'-verify-'+module)
        for mode in ('normal','race'):
            command(arm+'-'+mode+'-build')
            command(arm+'-'+mode)
            reserve(arm+'-'+mode+'-producer.jsonl','producer_corpus')
        dest=Path(arm+'-normal-consumer.json')
        reserve(dest.name,'consumer_result');command(consumer_command_name(dest))
    for index,arm in enumerate(plan['producer_order']):
        command('producer-cost-'+str(index)+'-'+arm)
    for case in ('success_cache','cache_fill_then_failed_write'):
        for index,arm in enumerate(plan['consumer_order']):
            dest=Path('consumer-cost-'+case+'-'+str(index)+'-'+arm+'.json')
            reserve(dest.name,'consumer_result');command(consumer_command_name(dest))
    return names


def aggregate_parent():
    group=next(line.split(':',2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
    return phase_cgroup.validate_parent_location(group,os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT'])


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



def verified_binary(record):
    path=Path(record['path'])
    if not path.is_file() or path.is_symlink() or sha(path)!=record['sha256']:
        raise ValueError('fixed test executable changed')
    return str(path)


def functional_command(record):
    return ['go','tool','test2json','-t','-p','github.com/apernet/hysteria/extras/v2/outbounds',
            verified_binary(record),'-test.v=test2json','-test.count=1','-test.timeout=30s',
            '-test.run=^TestPCSUDPContextContract$']


def benchmark_command(record):
    return [verified_binary(record),'-test.run=^$','-test.bench=^BenchmarkPCSUDPContextPipeline$',
            '-test.benchmem','-test.benchtime=250ms','-test.count=1','-test.timeout=30s']


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
    layout=output_layout(plan)
    parent=aggregate_parent();before=phase_cgroup.snapshot(parent)
    args.output.mkdir(parents=True,exist_ok=False)
    spec=importlib.util.spec_from_file_location('reviewed_remote_helper',helper)
    base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    base.ROOT=args.repository_dir;base.OUT=args.output
    result={'status':'RUNNING','execution_origin':'REMOTE_CI_PURE_ONLY','started_utc':base.utc(),'resources_before':before,'sources':{},'functional':[],'benchmark_runs':[],'consumer_runs':[], 'plan_sha256':sha(HERE/'plan.json'),'fixture_sha256':plan['fixture_sha256'],'workflow_commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),'run_attempt':os.environ.get('GITHUB_RUN_ATTEMPT')}
    shutil.copyfile(HERE/'plan.json',args.output/'plan.json')
    base.save('result.json',result)
    base.save('output-layout.json',layout)
    phases=None
    try:
        phases=phase_cgroup.PhaseManager(args.output,parent)
        env=dict(os.environ,GOOS='linux',GOARCH='amd64',GOAMD64='v1',CGO_ENABLED='0',GOTOOLCHAIN='local',GOWORK='off',GOMAXPROCS='1',GOMEMLIMIT='512MiB',GOFLAGS='-mod=readonly -buildvcs=false',GOPROXY='https://proxy.golang.org',GOSUMDB='sum.golang.org',GOPRIVATE='',GONOPROXY='',GONOSUMDB='')
        with tempfile.TemporaryDirectory(prefix='pcs-context-chain-') as temp:
            roots={arm:Path(temp)/arm for arm in ('baseline','candidate')}
            def prepare():
                if base.command(['go','version'],args.repository_dir,'go-version',env).read_text().strip()!='go version go1.25.6 linux/amd64':
                    raise ValueError('toolchain changed')
                sources={}
                for arm,root in roots.items():
                    sources[arm]=base.source_archive(plan['sources'][arm],root)
                    shutil.copyfile(HERE/'core_bridge.go',root/'core/server/pcs_context_contract_bridge.go')
                    shutil.copyfile(HERE/'contract_test.go',root/'extras/outbounds/pcs_context_contract_test.go')
                    base.command(['go','list','-mod=readonly','-tags=pcs_udp_context_contract','-deps','-test','-json','./outbounds'],root/'extras',arm+'-deps',env)
                    for module in ('core','extras'):
                        base.module_guard(root)
                        base.command(['go','mod','verify'],root/module,arm+'-verify-'+module,env)
                return sources
            result['sources']=phases.run('prepare','prepare',prepare,180)
            base.save('source-manifests.json',result['sources'])
            offline=dict(env,GOPROXY='off',GOSUMDB='off')
            binaries={}
            for arm,root in roots.items():
                binaries[arm]={}
                for mode in ('normal','race'):
                    def build(arm=arm,root=root,mode=mode):
                        binary=Path(temp)/(arm+'-'+mode+'.test')
                        command=['go','test','-c','-p','1','-mod=readonly','-tags=pcs_udp_context_contract','-o',str(binary)]
                        if mode=='race':command+=['-race']
                        base.command(command+['./outbounds'],root/'extras',arm+'-'+mode+'-build',
                                     dict(offline,CGO_ENABLED='1' if mode=='race' else '0'),timeout=240)
                        base.module_guard(root)
                        return dict(path=str(binary),sha256=sha(binary),source_commit=plan['sources'][arm],
                                    mode=mode,toolchain='go1.25.6',build_command=command+['./outbounds'])
                    binaries[arm][mode]=phases.run('build-'+arm+'-'+mode,'build',build,250)
            result['test_binaries']=binaries
            base.save('test-binaries.json',binaries)
            for arm,root in roots.items():
                for mode in ('normal','race'):
                    def functional(arm=arm,root=root,mode=mode):
                        corpus=args.output/(arm+'-'+mode+'-producer.jsonl')
                        log=base.command(functional_command(binaries[arm][mode]),root/'extras',arm+'-'+mode,
                                         dict(offline,PCS_CONTRACT_OUTPUT=str(corpus)),timeout=60)
                        passed=base.verify_tests(log,['TestPCSUDPContextContract'])
                        base.module_guard(root)
                        consumer=None
                        if mode=='normal':
                            dest=args.output/(arm+'-normal-consumer.json')
                            base.command(['python3',str(HERE/'consumer.py'),'--module',str(HERE/('consumer-'+arm+'.py')),'--corpus',str(corpus),'--arm',arm,'--mode','functional','--output',str(dest)],HERE,consumer_command_name(dest),offline,timeout=30)
                            consumer=json.loads(dest.read_text())
                        return dict(arm=arm,mode=mode,passed=passed,consumer=consumer,binary_sha256=binaries[arm][mode]['sha256'])
                    result['functional'].append(phases.run('functional-'+arm+'-'+mode,'functional',functional,100))
            def cost():
                benchmarks=[];consumers=[]
                for index,arm in enumerate(plan['producer_order']):
                    binary=binaries[arm]['normal']
                    if not any(x['arm']==arm and x['mode']=='normal' and x['binary_sha256']==binary['sha256'] for x in result['functional']):
                        raise ValueError('cost binary lacks functional qualification')
                    log=base.command(benchmark_command(binary),roots[arm]/'extras','producer-cost-'+str(index)+'-'+arm,offline,timeout=60)
                    benchmarks.append(dict(index=index,arm=arm,cases=parse_bench(log),binary_sha256=binary['sha256']))
                for case in ('success_cache','cache_fill_then_failed_write'):
                    for index,arm in enumerate(plan['consumer_order']):
                        dest=args.output/('consumer-cost-'+case+'-'+str(index)+'-'+arm+'.json')
                        base.command(['python3',str(HERE/'consumer.py'),'--module',str(HERE/('consumer-'+arm+'.py')),'--corpus',str(args.output/(arm+'-normal-producer.jsonl')),'--arm',arm,'--mode','cost','--case',case,'--output',str(dest)],HERE,consumer_command_name(dest),offline,timeout=30)
                        consumers.append(dict(index=index,arm=arm,case=case,measurement=json.loads(dest.read_text())))
                return dict(benchmark_runs=benchmarks,consumer_runs=consumers)
            result.update(phases.run('cost','cost',cost,180))
            for arm,root in roots.items():
                base.module_guard(root)
                for name,digest in result['sources'][arm]['files_sha256'].items():
                    if sha(root/name)!=digest:raise ValueError('original source changed')
                for binary in binaries[arm].values():verified_binary(binary)
            result['status']='PASS_PURE_CONTRACT_MEASURED_COST_PENDING_ADJUDICATION'
            result['limits']=plan['limits']
    except Exception as error:
        result.update(status='FAIL',error_type=type(error).__name__,error=str(error))
        raise
    finally:
        # Keep the original aggregate reference even if delegation failed after
        # moving the controller. A missing snapshot is explicit failure, never
        # a fallback read of the smaller controller cgroup.
        try:
            result['resources_after']=phase_cgroup.snapshot(parent)
        except Exception as error:
            result.update(status='FAIL',resources_after=None,
                          resource_snapshot_error={'type':type(error).__name__,'message':str(error)})
        result.update(ended_utc=base.utc(),phase_resources=phases.reports if phases else [],
                      resource_contract='staged_v6_build_only_max_exception')
        base.save('result.json',result)
        (args.output/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in sorted(args.output.iterdir()) if p.is_file() and p.name!='SHA256SUMS'))


if __name__=='__main__':main()
