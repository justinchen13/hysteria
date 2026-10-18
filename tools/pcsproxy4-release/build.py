#!/usr/bin/env python3
"""Remote release-identity build only; no tests or generated CLI execution."""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import tarfile
import tempfile
import time
import urllib.request

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]


def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as source:
        while chunk:=source.read(65536):digest.update(chunk)
    return digest.hexdigest()


def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()


def snapshot():
    group=next(x.split(':',2)[2] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
    expected='/system.slice/pcs-hy-release4-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']+'.service'
    if group!=expected:raise ValueError('not the owned remote build unit')
    root=Path('/sys/fs/cgroup'+group);identity=root.stat()
    values={name:(root/name).read_text().strip() for name in ('cpu.max','cpu.stat','memory.max','memory.swap.max','memory.current','memory.peak','memory.events')}
    quota,period=values['cpu.max'].split()
    if int(quota)!=int(period) or int(period)<=0 or values['memory.max']!=str(768*1024**2) or values['memory.swap.max']!='0':raise ValueError('build resource limits differ')
    return dict(cgroup=group,device=identity.st_dev,inode=identity.st_ino,captured_utc=utc(),**values)


def archive_check(destination,plan,expected_files):
    """Bind future PCS source-download metadata to exactly the built source tree."""
    url='https://codeload.github.com/justinchen13/hysteria/tar.gz/'+plan['source_commit']
    deadline=time.monotonic()+45;count=0
    with urllib.request.urlopen(url,timeout=20) as source,destination.open('xb') as target:
        if source.geturl()!=url:raise ValueError('unexpected source archive redirect')
        while chunk:=source.read(65536):
            count+=len(chunk)
            if count>16*1024**2 or time.monotonic()>deadline:raise ValueError('source archive bound exceeded')
            target.write(chunk)
    observed={};prefix='hysteria-'+plan['source_commit']
    with tarfile.open(destination,'r:gz') as archive:
        members=archive.getmembers()
        if len(members)>4096 or sum(x.size for x in members)>64*1024**2:raise ValueError('source archive expanded bound')
        for member in members:
            path=PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0]!=prefix:raise ValueError('unsafe source archive path')
            if len(path.parts)<2 or path.parts[1] not in ('core','extras','app'):continue
            if member.isdir():continue
            name=str(PurePosixPath(*path.parts[1:]))
            # This fixed source includes one 9,640,091-byte GeoIP database.
            fixed_geoip=name=='extras/outbounds/acl/v2geo/geoip.dat'
            if fixed_geoip and member.size!=9640091:raise ValueError('fixed GeoIP source size differs')
            limit=9640091 if fixed_geoip else 8*1024**2
            if not member.isfile() or member.size>limit or name in observed:raise ValueError('source archive member type/size/duplicate')
            observed[name]=hashlib.sha256(archive.extractfile(member).read()).hexdigest()
    if observed!=expected_files:raise ValueError('codeload runtime source differs from verified build tree')
    return dict(url=url,sha256=sha(destination),bytes=count,runtime_files_verified=len(observed))


def main():
    os.umask(0o077)
    plan=json.loads((HERE/'plan.json').read_text())
    if (plan['status']!='ROOT_REVIEWED_REMOTE_BUILD_ONLY' or os.environ.get('GITHUB_ACTIONS')!='true' or
            os.environ.get('GITHUB_REPOSITORY')!=plan['repository'] or os.environ.get('GITHUB_REF')!=plan['ref']):
        raise RuntimeError('unreviewed or non-dedicated build refused')
    for name,digest in plan['files_sha256'].items():
        if sha(REPO/name)!=digest:raise ValueError('fixed input changed: '+name)
    if shutil.disk_usage(HERE).free<1024**3:raise ValueError('remote disk below1GiB')
    output=REPO/'dist/pcsproxy4-release';output.mkdir(parents=True,exist_ok=False)
    helper=REPO/plan['helper_path']
    spec=importlib.util.spec_from_file_location('verified_cli_build_helper',helper)
    base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    base.ROOT=REPO;base.OUT=output
    result=dict(status='RUNNING',started_utc=utc(),origin='REMOTE_CI_RELEASE_BUILD_ONLY',
                workflow_commit=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'],attempt=os.environ['GITHUB_RUN_ATTEMPT'],
                plan_sha256=sha(HERE/'plan.json'),source_commit=plan['source_commit'],resources_before=None)
    shutil.copyfile(HERE/'plan.json',output/'plan.json')
    try:
        result['resources_before']=snapshot()
        env=dict(os.environ,CGO_ENABLED='0',GOOS='linux',GOARCH='amd64',GOAMD64='v1',GOTOOLCHAIN='local',GOWORK='off',
                 GOMAXPROCS='1',GOMEMLIMIT='512MiB',GOFLAGS='-mod=readonly -buildvcs=false',
                 GOPROXY='https://proxy.golang.org',GOSUMDB='sum.golang.org',GOPRIVATE='',GONOPROXY='',GONOSUMDB='')
        if base.command(['go','version'],REPO,'go-version',env).read_text().strip()!='go version go1.25.6 linux/amd64':raise ValueError('toolchain differs')
        result['go_binary_sha256']=sha(Path(shutil.which('go')))
        if subprocess.check_output(['git','diff','--name-only',plan['source_commit'],'HEAD','--','core','extras','app'],cwd=REPO).strip():raise ValueError('checkout runtime source differs')
        expected=json.loads((HERE/'source-manifest.json').read_text())
        with tempfile.TemporaryDirectory(prefix='pcs-release4-source-') as temp:
            area=Path(temp);root=area/'source'
            source=base.source_archive(plan['source_commit'],root)
            if source['files_sha256']!=expected['files_sha256'] or source['commit']!=expected['commit']:raise ValueError('source manifest differs from verified candidate')
            base.save('source-manifest.json',source)
            archive=archive_check(area/'source.tar.gz',plan,expected['files_sha256'])
            result['source_archive']=archive
            base.command(['go','list','-mod=readonly','-deps','-json','.'],root/'app','dependencies',env,timeout=180)
            for module in ('core','extras','app'):
                base.module_guard(root)
                base.command(['go','mod','verify'],root/module,'verify-'+module,env,timeout=60)
            offline=dict(env,GOPROXY='off',GOSUMDB='off')
            prefix='github.com/apernet/hysteria/app/v2/cmd.'
            flags='-s -w '+' '.join('-X '+prefix+key+'='+value for key,value in plan['ldflags_fields'].items())
            binary=output/'hysteria'
            command=['go','build','-p','1','-mod=readonly','-trimpath','-buildvcs=false','-ldflags='+flags,'-o',str(binary),'.']
            base.command(command,root/'app','build-final',offline,timeout=240)
            base.module_guard(root)
            with binary.open('rb') as handle:header=handle.read(64)
            if header[:6]!=b'\x7fELF\x02\x01' or struct.unpack('<H',header[18:20])[0]!=62:raise ValueError('not Linuxamd64 ELF')
            base.command(['go','version','-m',str(binary)],root/'app','buildinfo',offline,timeout=30)
            rebuilt=area/'hysteria-rebuilt';command[command.index('-o')+1]=str(rebuilt)
            base.command(command,root/'app','build-identical-repeat',offline,timeout=240)
            if sha(binary)!=sha(rebuilt):raise ValueError('identical formal build SHA differs')
            base.module_guard(root)
            if {str(p.relative_to(root)):sha(p) for p in root.rglob('*') if p.is_file()}!=expected['files_sha256']:raise ValueError('source or lock mutated during build')
            sources=json.loads((HERE/'sources.template.json').read_text())
            sources['source']['archive_sha256']=archive['sha256']
            sources['source']['archive_url']=archive['url']
            base.save('sources.json',sources)
            result.update(binary_sha256=sha(binary),binary_bytes=binary.stat().st_size,rebuild_sha256=sha(rebuilt),
                          sources_sha256=sha(output/'sources.json'),ldflags=flags,source_files_verified=len(expected['files_sha256']),
                          status='PASS_FIXED_RELEASE_BUILD_AND_IDENTICAL_REBUILD')
    except BaseException as error:
        result.update(status='FAIL',error_type=type(error).__name__,error=str(error))
        raise
    finally:
        result['ended_utc']=utc()
        try:
            result['resources_after']=snapshot()
            before=result['resources_before'];after=result['resources_after']
            if any(before[k]!=after[k] for k in ('cgroup','device','inode')):raise ValueError('resource generation changed')
            counters=lambda s:dict((k,int(v)) for k,v in (x.split() for x in s.splitlines()))
            result['memory_events_delta']={k:counters(after['memory.events'])[k]-counters(before['memory.events'])[k] for k in ('high','max','oom','oom_kill')}
            if any(result['memory_events_delta'][k] for k in ('high','oom','oom_kill')) or result['memory_events_delta']['max']<0:raise ValueError('release-build resource failure')
            result['memory_max_scope']='Whole build-only unit; any max increments are preserved compilation/dependency pressure, not functional/runtime cost evidence. No tests or CLI main ran.'
        except BaseException as error:
            result.update(status='FAIL',resource_error_type=type(error).__name__,resource_error=str(error))
        base.save('result.json',result)
        (output/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in sorted(output.iterdir()) if p.is_file() and p.name!='SHA256SUMS'))
    if result['status']!='PASS_FIXED_RELEASE_BUILD_AND_IDENTICAL_REBUILD':raise RuntimeError('formal build did not pass')


if __name__=='__main__':main()
