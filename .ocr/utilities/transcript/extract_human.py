import json, sys
F="/home/tristan/.claude/projects/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440.jsonl"
turns=[]
with open(F) as fh:
    for i,line in enumerate(fh,1):
        line=line.strip()
        if not line: continue
        try: o=json.loads(line)
        except: continue
        t=o.get("type")
        # genuine typed human turns
        if t=="user":
            m=o.get("message",{})
            if not isinstance(m,dict): continue
            if m.get("role")!="user": continue
            if o.get("isMeta"): continue
            c=m.get("content")
            txt=None
            if isinstance(c,str):
                txt=c
            elif isinstance(c,list):
                parts=[]
                skip=False
                for b in c:
                    if isinstance(b,dict):
                        if b.get("type")=="tool_result": skip=True; break
                        if b.get("type")=="text": parts.append(b.get("text",""))
                    elif isinstance(b,str): parts.append(b)
                if skip: continue
                txt="\n".join(parts)
            if txt is None: continue
            txt=txt.strip()
            if not txt: continue
            # skip pure command-stdout / system noise
            if txt.startswith("<") and txt.count("<")>3 and "command-name" not in txt and "OPERATOR" not in txt:
                pass
            turns.append((i,txt))
print("TOTAL genuine human turns:", len(turns))
print("="*90)
N=int(sys.argv[1]) if len(sys.argv)>1 else 45
for i,txt in turns[-N:]:
    if len(txt)>1100: txt=txt[:1100]+" …[trunc]"
    print(f"\n----- line {i} -----\n{txt}")
