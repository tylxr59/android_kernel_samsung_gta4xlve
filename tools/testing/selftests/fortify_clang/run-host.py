#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
import os, subprocess, json, hashlib
fixture=Path(__file__).resolve().parent;k=fixture.parents[3]
b=Path(os.environ['TEST_OUTPUT']).resolve();b.mkdir(parents=True,exist_ok=True)
s=(k/'include/linux/string.h').read_text();a=s.index('#ifdef __clang__\n#define __FORTIFY_INLINE');e=s.index('#undef __FORTIFY_POS',a)+len('#undef __FORTIFY_POS')
(b/'actual-fortify.inc').write_text(s[a:e]+'\n')
results=[]
for compiler in [os.environ.get('TEST_CLANG','clang'),'gcc']:
 for mode in ['valid','NEGATIVE_WRITE','NEGATIVE_READ']:
  name=Path(compiler).name;exe=b/(name+'-'+mode)
  cmd=[compiler,'-O2','-std=gnu11','-I',str(b),str(fixture/'test.c'),'-o',str(exe)]
  if mode!='valid':cmd+=['-D'+mode]
  r=subprocess.run(cmd,text=True,capture_output=True);(b/(name+'-'+mode+'.log')).write_text(r.stdout+r.stderr)
  if mode=='valid':
   r.check_returncode();subprocess.run([str(exe)],check=True)
  else:assert r.returncode!=0 and 'detected' in r.stderr,(name,mode,r.stderr)
  results.append({'compiler':name,'mode':mode,'compile_returncode':r.returncode})
(b/'results.json').write_text(json.dumps({'actual_source_sha256':hashlib.sha256(s.encode()).hexdigest(),'results':results},indent=2)+'\n')
print('PASS: actual wrappers, Clang/GCC valid operations, dynamic traps and constant overflow rejection')
