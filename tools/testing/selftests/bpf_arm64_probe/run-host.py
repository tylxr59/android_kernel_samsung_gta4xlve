#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
import subprocess,hashlib,json,os
fixture=Path(__file__).resolve().parent;k=fixture.parents[3];b=Path(os.environ['TEST_OUTPUT']).resolve();b.mkdir(parents=True,exist_ok=True)
s=(k/'arch/arm64/net/bpf_jit_comp.c').read_text();ext=(k/'arch/arm64/mm/extable.c').read_text()
def function(text,signature):
 start=text.index(signature);brace=text.index('{',start);level=1;end=brace+1
 while level:
  if text[end]=='{':level+=1
  if text[end]=='}':level-=1
  end+=1
 return text[start:end]
a=s.index('struct jit_ctx {');e=s.index('};',a)+2
source=s[a:e]+'\n#define BPF_FIXUP_OFFSET_MASK GENMASK(26,0)\n#define BPF_FIXUP_REG_MASK GENMASK(31,27)\n'
for name in ['int arm64_bpf_fixup_exception(', 'static int add_exception_handler(', 'static int validate_code(']:source+=function(s,name)+'\n'
source+=function(ext,'int fixup_exception(')+'\n'
verifier=(k/'kernel/bpf/verifier.c').read_text();start=verifier.index('static int fixup_bpf_calls(');start=verifier.index('*patch++ = BPF_MOV64_REG(BPF_REG_AX',start);end=verifier.index('\n\t\t\tcnt = patch - insn_buf;',start)
source+='static int generate_guard(struct bpf_insn *insn,struct bpf_insn *buf,uint64_t uaddress_limit) { struct bpf_insn *patch=buf;\n'+verifier[start:end]+'\nreturn patch-buf; }\n' 
(b/'actual-functions.inc').write_text(source)
subprocess.run(['gcc','-std=gnu11','-g','-fsanitize=address,undefined','-I',str(b),str(fixture/'test.c'),'-o',str(b/'test')],check=True)
r=subprocess.run([str(b/'test')],capture_output=True,text=True);(b/'result.txt').write_text(r.stdout+r.stderr);print(r.stdout+r.stderr);r.check_returncode()
(b/'source-proof.json').write_text(json.dumps({'jit_source_sha256':hashlib.sha256(s.encode()).hexdigest(),'extable_source_sha256':hashlib.sha256(ext.encode()).hexdigest(),'functions_extracted_from_actual_source':True,'asan_ubsan_passed':True,'verifier_source_sha256':hashlib.sha256(verifier.encode()).hexdigest(),'user_address_guard_generated_from_actual_source':True,'not_actual_kernel_fault_injection':True},indent=2)+'\n')
