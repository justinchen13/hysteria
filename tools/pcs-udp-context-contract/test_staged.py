#!/usr/bin/env python3
"""Pure mock contracts; no cgroup writes, fork, subprocess, Go or network."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import phase_cgroup as phases
import adjudicate
import run

PARENT='/sys/fs/cgroup/system.slice/pcs-hy-context-chain-123-1.service'


def snapshot(path,when,maximum=0,inode=100):
    values={name:'x' for name in phases.FILES}
    values.update({'cpu.max':'100000 100000','cpu.stat':'usage_usec 10',
                   'memory.max':str(phases.MEMORY_MAX),'memory.swap.max':'0',
                   'memory.current':'100','memory.peak':'1000',
                   'memory.events':f'high 0\nmax {maximum}\noom 0\noom_kill 0',
                   'cgroup':path,'device':26,'inode':inode,
                   'captured_monotonic':when,'captured_utc':'2026-10-18T00:00:00Z',
                   'memory_peak_scope':'cumulative_for_this_cgroup_generation'})
    return values


def reports():
    result=[];current=0
    for index,(name,kind) in enumerate(phases.expected_phases()):
        tag='phase-%02d-%s'%(index,name);start=10+index*10
        after=current+(3 if kind=='build' else 0)
        result.append(dict(name=tag,kind=kind,status='COMPLETED',exit_code=0,errors=[],
                           cleanup='owned_empty_cgroup_removed',
                           parent_before=snapshot(PARENT,start,current),
                           parent_after=snapshot(PARENT,start+3,after),
                           worker_before=snapshot(PARENT+'/'+tag,start+1,0,200+index),
                           worker_after=snapshot(PARENT+'/'+tag,start+2,after-current,200+index)))
        current=after
    return result


def data():
    return dict(resource_contract='staged_v6_build_only_max_exception',
                resources_before=snapshot(PARENT,0),resources_after=snapshot(PARENT,120,12),
                phase_resources=reports())


class StagedContractTests(unittest.TestCase):
    def test_all_phases_and_build_only_max_are_required(self):
        value=data()
        self.assertTrue(adjudicate.staged_resource_contract(value))
        value['phase_resources'].pop(0)
        self.assertFalse(adjudicate.staged_resource_contract(value))

    def test_prepare_functional_cost_parent_or_worker_max_hold(self):
        for index in (0,5,9):
            for scope in ('parent','worker'):
                value=data();row=value['phase_resources'][index][scope+'_after']
                row['memory.events']=row['memory.events'].replace('max 0','max 1').replace('max 12','max 13')
                self.assertFalse(adjudicate.staged_resource_contract(value),(index,scope))

    def test_build_high_oom_and_kill_hold(self):
        for field in ('high','oom','oom_kill'):
            for scope in ('parent','worker'):
                value=data();row=value['phase_resources'][1][scope+'_after']
                row['memory.events']=row['memory.events'].replace(field+' 0',field+' 1')
                self.assertFalse(adjudicate.staged_resource_contract(value),(field,scope))

    def test_gap_pressure_and_generation_reuse_hold(self):
        value=data();value['resources_after']['memory.events']='high 0\nmax 13\noom 0\noom_kill 0'
        self.assertFalse(adjudicate.staged_resource_contract(value))
        for scope in ('parent','worker'):
            value=data();value['phase_resources'][9][scope+'_after']['inode']+=1
            self.assertFalse(adjudicate.staged_resource_contract(value))

    def test_missing_or_wrong_parent_snapshot_is_unknown_hold(self):
        for field in ('cpu.stat','memory.events','memory.peak','device','inode'):
            value=data();del value['phase_resources'][9]['parent_after'][field]
            self.assertFalse(adjudicate.staged_resource_contract(value),field)
        value=data();value['resources_after']['cgroup']=PARENT+'/control'
        self.assertFalse(adjudicate.staged_resource_contract(value))

    def test_parent_window_must_enclose_worker(self):
        value=data();value['phase_resources'][9]['parent_after']['captured_monotonic']=101.5
        self.assertFalse(adjudicate.staged_resource_contract(value))

    def test_limits_timeout_cleanup_and_payload_failure_hold(self):
        for field,change in (('status','TIMED_OUT'),('exit_code',2),('cleanup','unexpected_remaining_owned_processes')):
            value=data();value['phase_resources'][1][field]=change
            self.assertFalse(adjudicate.staged_resource_contract(value),field)
        for key,change in (('cpu.max','200000 100000'),('memory.max',str(1024**3)),('memory.swap.max','max')):
            value=data();value['phase_resources'][1]['worker_after'][key]=change
            self.assertFalse(adjudicate.staged_resource_contract(value),key)
        target=mock.Mock();target.open.side_effect=OSError('synthetic write failure')
        with mock.patch('sys.stderr',io.StringIO()):
            self.assertEqual(phases.write_payload(target,{'status':'PASS'},0),2)

    def test_owned_paths_reject_other_units_and_traversal(self):
        self.assertEqual(phases.validate_parent_location('/system.slice/pcs-hy-context-chain-123-1.service','123','1'),Path(PARENT))
        for group in ('/system.slice/another.service','/system.slice/pcs-hy-context-chain-123-1.service/control'):
            with self.assertRaises(ValueError):phases.validate_parent_location(group,'123','1')
        for child in ('../foreign','control','phase-00-../../foreign'):
            with self.assertRaises(ValueError):phases.owned_child(Path(PARENT),child)

    def test_output_paths_unique_and_old_collision_rejected(self):
        plan=json.loads(Path(__file__).with_name('plan.json').read_text())
        layout=run.output_layout(plan)
        self.assertEqual(len(layout),112)
        self.assertEqual(sum(v=='phase_resource_report' for v in layout.values()),10)
        with mock.patch.object(run,'consumer_command_name',lambda p:p.stem):
            with self.assertRaises(ValueError):run.output_layout(plan)

    def test_cost_uses_exact_functionally_qualified_normal_binary(self):
        value={'test_binaries':{},'functional':[],'benchmark_runs':[]};plan={'sources':{}}
        for arm in ('baseline','candidate'):
            plan['sources'][arm]='source-'+arm;value['test_binaries'][arm]={}
            for mode in ('normal','race'):
                digest=('a' if arm=='baseline' else 'b')*63+('0' if mode=='normal' else '1')
                value['test_binaries'][arm][mode]=dict(source_commit=plan['sources'][arm],mode=mode,toolchain='go1.25.6',sha256=digest)
                value['functional'].append(dict(arm=arm,mode=mode,binary_sha256=digest))
            value['benchmark_runs'].append(dict(arm=arm,binary_sha256=value['test_binaries'][arm]['normal']['sha256']))
        artifact=copy.deepcopy(value['test_binaries'])
        self.assertTrue(adjudicate.binary_contract(value,plan,artifact))
        value['benchmark_runs'][0]['binary_sha256']='f'*64
        self.assertFalse(adjudicate.binary_contract(value,plan,artifact))

    def test_test2json_and_cost_commands_do_not_build_or_select_old_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'baseline-normal.test';binary.write_bytes(b'synthetic')
            record=dict(path=str(binary),sha256=run.sha(binary))
            function=run.functional_command(record);cost=run.benchmark_command(record)
            self.assertEqual(function[:3],['go','tool','test2json'])
            self.assertIn('-test.run=^TestPCSUDPContextContract$',function)
            self.assertIn('-test.v=test2json',function)
            self.assertEqual(cost[0],str(binary))
            self.assertIn('-test.benchtime=250ms',cost)
            self.assertIn('-test.run=^$',cost)
            binary.write_bytes(b'changed')
            with self.assertRaises(ValueError):run.benchmark_command(record)


if __name__=='__main__':unittest.main()
