#Generar paquete ICMP con scapy

from scapy.all import *

#Generar paquete ICMP
from scapy.all import IP, ICMP

allIp = []
ttl = 0
reached = False
while ttl < 100 and not reached:
    p = IP(dst="www.google.com", ttl=ttl)/ICMP()
    ttl += 1

    start = time.time()
    r = sr1(p, verbose=0, timeout=1)
    end = time.time()


    if r is None:
        print("Timeout")
    else:
        #print(r.src, "respondio con TTL: ", r.ttl)
        totalTimeMiliseconds = (end-start)*1000
        try:
            hostname = socket.gethostbyaddr(r.src)
        except:
            hostname = "No se pudo resolver"
        print("TTL: ", ttl, "--> ", r.src, "With hostname: ", hostname[0], "in ", totalTimeMiliseconds, "ms")
        if r.src not in allIp:
            allIp.append(r.src)
        if p.dst == r.src:
            print("Llego al destino: ", r.src)
            reached = True

print("Direcciones IP encontradas: ", allIp)




#p = sr1(IP(dst="www.google.com")/ICMP()/"")

#p.show()