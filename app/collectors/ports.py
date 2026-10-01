import socket
from .base import Evidence
from ..security import resolve_public

COMMON_PORTS=(21,22,25,53,80,110,143,443,445,465,587,993,995,1433,1521,2049,3306,3389,5432,6379,8080,8443)

class PortCollector:
    name="ports"
    def collect(self,target:str,timeout:float=0.45,ports=COMMON_PORTS)->list[Evidence]:
        ips=resolve_public(target)
        if not ips:
            return []
        evidence=[]
        for ip in ips:
            for port in ports:
                try:
                    with socket.create_connection((ip,port),timeout=timeout):
                        evidence.append(Evidence(self.name,target,"tcp_open",str(port),92,{"port":port,"ip":ip,"bounded":True,"validated_resolution":True}))
                except (OSError,TimeoutError):
                    continue
        return evidence
