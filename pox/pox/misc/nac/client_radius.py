#-*- coding: utf-8 -*-
import socket
import sys
from pox.lib.addresses import EthAddr,IPAddr
from pox.lib.packet.radius import radius


class radClient(object):
    """
    Simple client radius implémentant 
    le minimum de fonctionnalitée
    """
    
    User_Name           = 1
    NAS_IP_Address      = 2
    NAS_Port            = 5
    Reply_Message       = 18
    Called_Station_Id   = 30
    Calling_Station_Id  = 31
    
    def __init__(self, secret, srv_addr, srv_port):
        try:
            self.srv_addr = str(IPAddr(srv_addr))
            self.srv_port = int(srv_port)
            self.secret = str(secret)
        except Exception as e:
            raise ValueError("Bad format argument "+ str(e))
            
        self.sock= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        
            
    def send(self, radius_pckt):
        authenticator = radius_pckt.getAuthenticator()
        self.sock.sendto(radius_pckt.getRaw(), (self.srv_addr, self.srv_port))
        rep = self.sock.recv(4096)
        
        radius_pckt2 = radius( raw = rep)
        
        radius_pckt2.checkResponse(self.secret, radius_pckt.getAuthenticator(), radius_pckt.id)
            
        return radius_pckt2
        