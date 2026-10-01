import os, socket, struct, random

from .base import Evidence

RECORD_TYPES={"A":1,"NS":2,"CNAME":5,"MX":15,"TXT":16,"AAAA":28,"SRV":33,"CAA":257}

def _encode_name(name):
    return b"".join(bytes([len(p)])+p.encode() for p in name.rstrip(".").split("."))+b"\x00"

def _read_name(data, offset):
    labels=[]; jumped=False; end=offset
    while True:
        length=data[offset]
        if length==0:
            offset+=1
            if not jumped:end=offset
            break
        if length & 0xC0==0xC0:
            ptr=((length&0x3F)<<8)|data[offset+1]
            label,_=_read_name(data,ptr)
            labels.append(label); offset+=2
            if not jumped:end=offset
            break
        offset+=1; labels.append(data[offset:offset+length].decode("utf-8","ignore")); offset+=length
    return ".".join(x for x in labels if x),end

def _query(name,qtype,server,timeout):
    tid=random.randrange(0,65536); packet=struct.pack("!HHHHHH",tid,0x0100,1,0,0,0)+_encode_name(name)+struct.pack("!HH",qtype,1)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(timeout); s.sendto(packet,(server,53)); data,_=s.recvfrom(8192)
    if len(data)<12 or struct.unpack("!H",data[:2])[0]!=tid:return []
    qd,an=struct.unpack("!HH",data[4:8]); off=12
    for _ in range(qd): _,off=_read_name(data,off); off+=4
    out=[]
    for _ in range(an):
        _,off=_read_name(data,off)
        if off+10>len(data):break
        typ,cls,ttl,rdlen=struct.unpack("!HHIH",data[off:off+10]); off+=10
        rstart=off
        if typ in (2,5): value,_=_read_name(data,off)
        elif typ==1 and rdlen==4: value=socket.inet_ntoa(data[off:off+4])
        elif typ==28 and rdlen==16: value=socket.inet_ntop(socket.AF_INET6,data[off:off+16])
        elif typ==15:
            pref=struct.unpack("!H",data[off:off+2])[0]; host,_=_read_name(data,off+2); value=f"{pref} {host}"
        elif typ==16:
            chunks=[]; p=off
            end=off+rdlen
            while p<end:
                n=data[p];p+=1;chunks.append(data[p:p+n].decode("utf-8","ignore"));p+=n
            value="".join(chunks)
        elif typ==257 and rdlen>=2:
            flags=data[off]
            tag_len=data[off+1]
            tag=data[off+2:off+2+tag_len].decode("utf-8","ignore")
            value=f"{flags} {tag} {data[off+2+tag_len:rstart+rdlen].decode("utf-8","ignore")}"
        elif typ==33 and rdlen>=7:
            pri,weight,port=struct.unpack("!HHH",data[off:off+6]); host,_=_read_name(data,off+6); value=f"{pri} {weight} {port} {host}"
        else:value=""
        off=rstart+rdlen
        if value:out.append((typ,value,ttl))
    return out

class DNSCollector:
    name="dns"
    def collect(self,target:str,timeout:float=1.5)->list[Evidence]:
        evidence=[]; server=os.getenv("BSA_DNS_SERVER","1.1.1.1")
        for label,qtype in RECORD_TYPES.items():
            try: answers=_query(target,qtype,server,timeout)
            except (OSError,TimeoutError,struct.error): answers=[]
            for typ,value,ttl in answers:
                evidence.append(Evidence(self.name,target,label.lower(),value,94 if label in {"A","AAAA","CNAME"} else 90,{"ttl":ttl,"resolver":server,"record_type":label}))
        try:
            _,aliases,addresses=socket.gethostbyname_ex(target)
            for ip in sorted(set(addresses)):
                evidence.append(Evidence(self.name,target,"a_record",ip,95,{"resolver":"system"}))
            for alias in sorted(set(aliases)):
                evidence.append(Evidence(self.name,target,"alias",alias,90,{"resolver":"system"}))
        except socket.gaierror: pass
        return evidence
