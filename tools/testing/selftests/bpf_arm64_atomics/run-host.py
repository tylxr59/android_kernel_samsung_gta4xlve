#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
import os,subprocess,json,hashlib
fixture=Path(__file__).resolve().parent;k=fixture.parents[3]
b=Path(os.environ['TEST_OUTPUT']).resolve();b.mkdir(parents=True,exist_ok=True)
s=(k/'arch/arm64/net/bpf_jit_comp.c').read_text()
def function(signature):
 a=s.index(signature);e=s.index('{',a)+1;level=1
 while level:
  level+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[a:e]
a=s.index('#define TMP_REG_1');e=s.index('struct jit_ctx {',a)
(b/'actual-functions.inc').write_text(s[a:e]+function('static int emit_ll_sc_atomic(')+'\n')
subprocess.run(['gcc','-std=gnu11','-g','-fsanitize=address,undefined','-I',str(b),str(fixture/'test.c'),'-o',str(b/'test')],check=True)
r=subprocess.run([str(b/'test')],capture_output=True,text=True);(b/'result.txt').write_text(r.stdout+r.stderr);print(r.stdout+r.stderr);r.check_returncode()
(b/'source-proof.json').write_text(json.dumps({'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'actual_emitter_extracted':True,'asan_ubsan_passed':True,'instruction_semantics_model_only':True,'not_actual_arm64_or_live_verifier_execution':True},indent=2)+'\n')
