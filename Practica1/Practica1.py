#Generar paquete ICMP con scapy

from scapy.all import *

#Generar paquete ICMP
from scapy.all import IP, ICMP

p = sr1(IP(dst="www.google.com")/ICMP()/"")

p.show()