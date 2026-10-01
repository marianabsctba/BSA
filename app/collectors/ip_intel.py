import ipaddress, json
from urllib.parse import quote
from urllib.request import Request,urlopen
from urllib.error import URLError,HTTPError
from .base import Evidence

class IPIntelCollector:
    name="ip_intel"
    def collect(self,target:str,timeout:float=5.0)->list[Evidence]:
        out=[]
        try: ipaddress.ip_address(target)
        except ValueError: return out
        req=Request("https://rdap.org/ip/"+quote(target),headers={"User-Agent":"BSA-ASM/0.3 defensive-ip-intel"})
        try:
            with urlopen(req,timeout=timeout) as resp: data=json.loads(resp.read().decode("utf-8","replace"))
        except (URLError,HTTPError,ValueError,TimeoutError): return out
        for key in ("name","handle","startAddress","endAddress"):
            if data.get(key): out.append(Evidence(self.name,target,"rdap_"+key,str(data[key]),95,{"passive":True}))
        for item in data.get("entities",[]) or []:
            roles=item.get("roles") or []
            if roles: out.append(Evidence(self.name,target,"rdap_entity_role",",".join(sorted(set(roles))),88,{"passive":True}))
        return out
