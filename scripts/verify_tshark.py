#!/usr/bin/env python3
"""Independent dissector check for one key packet and total frame count."""
import json
from pathlib import Path
import subprocess
import sys

p=sys.argv[1]
capture=Path(p).read_bytes()
# Stream the already-readable capture through stdin for restricted file profiles.
version=subprocess.check_output(['tshark','--version'],input=capture).decode().splitlines()[0]
args=['tshark','-n','-r','-','-d','tcp.port==443,http','-Y','frame.number == 24675','-T','fields','-E','separator=,','-e','frame.number','-e','eth.src','-e','ip.src','-e','ip.dst','-e','tcp.dstport','-e','http.request.method','-e','http.user_agent']
row=subprocess.check_output(args,input=capture).decode().strip()
expected='24675,00:12:f0:e5:17:43,10.11.10.147,93.152.209.36,443,POST,NetSupport Manager/1.3'
assert row==expected,(row,expected)
count=subprocess.check_output(['tshark','-n','-r','-','-T','fields','-e','frame.number'],input=capture).decode().splitlines()
assert len(count)==30182
result={'tool':version,'key_frame_fields':row,'frame_count':len(count),'result':'passed','scope':'Independent key HTTP packet and total frame count. Does not validate every extractor output.'}
Path('tshark-validation.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
