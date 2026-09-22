import json
F="/home/tristan/.claude/projects/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440.jsonl"
want={24123,24176,24685,24699,24709}
lines=open(F).read().splitlines()
def text_of(o):
    m=o.get("message",{})
    c=m.get("content")
    if isinstance(c,str): return c
    if isinstance(c,list):
        out=[]
        for b in c:
            if isinstance(b,dict) and b.get("type")=="text": out.append(b.get("text",""))
            elif isinstance(b,str): out.append(b)
        return "\n".join(out)
    # command args
    return ""
for ln in sorted(want):
    o=json.loads(lines[ln-1])
    t=o.get("type")
    txt=""
    if t=="user":
        txt=text_of(o)
        if not txt:
            # maybe command args stored differently
            txt=json.dumps(o.get("message",{}).get("content",""))[:0]
    print(f"\n########## line {ln} (type={t}) ##########")
    # For the /loop line, also dump raw if text empty
    if not txt:
        print("[raw]", lines[ln-1][:2500])
    else:
        print(txt[:3000])
