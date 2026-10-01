import json
from urllib.parse import quote
from urllib.request import Request,urlopen
from urllib.error import URLError,HTTPError
from .base import Evidence

class RDAPCollector:
    name="rdap"
    def collect(self,target:str,timeout:float=6.0)->list[Evidence]:
        target=target.strip().lower().lstrip("*."); out=[]
        url="https://rdap.org/domain/"+quote(target)
        req=Request(url,headers={"User-Agent":"BSA-ASM/0.3 defensive-rdap-discovery"})
        try:
            with urlopen(req,timeout=timeout) as resp: data=json.loads(resp.read().decode("utf-8","replace"))
        except (URLError,HTTPError,ValueError,TimeoutError): return out
        for item in data.get("nameservers",[]) or []:
            name=(item.get("ldhName") or item.get("unicodeName") or "").lower().rstrip(".")
            if name: out.append(Evidence(self.name,target,"rdap_nameserver",name,96,{"passive":True}))
        for item in data.get("entities",[]) or []:
            roles=item.get("roles") or []
            if roles: out.append(Evidence(self.name,target,"rdap_entity_role",",".join(sorted(set(roles))),90,{"passive":True}))
        events={x.get("eventAction"):x.get("eventDate") for x in data.get("events",[]) if x.get("eventAction")}
        for action,date in events.items():
            if date: out.append(Evidence(self.name,target,"rdap_event:"+action,str(date),96,{"passive":True}))
        status=data.get("status") or []
        if status: out.append(Evidence(self.name,target,"rdap_status",",".join(status),96,{"passive":True}))
        return out
