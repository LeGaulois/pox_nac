from pox.core import core
import pox.openflow.libopenflow_01 as of

from observable import Observable
import ConfigParser, codecs

from pox.lib.addresses import EthAddr,IPAddr
from pox.lib.packet.dhcp import dhcp, DHCPRelay
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ethernet import ethernet
from tools import *
from hosts_infos import HostsInfos
import socket
import struct


class DhcpIntercept(Observable):
    """
    Create DHCP request interceptor
    """

    def __init__(self, connection, transparent, host_authenticated):
        Observable.__init__(self)
        self.connection = connection
        self.transparent = transparent
        self.hosts_authenticated = host_authenticated
        self.sock= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        

    def notify(self, type_notification,*args,**kwargs):
        """
        Gestion des paquets recus par le dispatcher
        """
        try:
            paquet = kwargs.pop('packet')
            port = kwargs.pop('port')
        except:
            log.debug('Erreur dans le format de notification recu')
            return
        
        dhcp_pckt = paquet.next.next.next
        host_params = self.hosts_authenticated.getInfos(paquet.src)
        
        if not host_params.has_key('user'):
            return
        
        ipsrc_initial = paquet.next.srcip
        macsrc_initial = paquet.src
        relay_agent_ip = dhcp_pckt.giaddr
        
        dhcp_pckt.packOptions()
        dhcp_pckt= self.addUsername (dhcp_pckt, host_params['user'])
        dhcp_pckt =  self.addRelay(dhcp_pckt, host_params['user'])
        
        if relay_agent_ip == '0.0.0.0':
            dhcp_pckt.giaddr = getIPRelay(host_params['ip'], host_params['netmask'])
            
        dhcp_reponse = self.sendToDHCPServer(dhcp_pckt)
        self.reponseToClient(dhcp_reponse, dhcp_pckt.giaddr, ipsrc_initial, macsrc_initial, port)
        
        
    def reponseToClient(self, dhcp_pckt, ip_relay, ip_dst, mac_dst, port_switch):
        ip_dst = '255.255.255.255' if ip_dst=='0.0.0.0' else ip_dst
        
        udp = udp(srcport = 67,
                  dstport = 68)
        udp.set_payload(dhcp_pckt)
        
        ip = ipv4(protocol=17,
                  srcip = ip_relay,
                  dstip = ip_dst)
        ip.set_payload(udp)
        
        e= ethernet(type= 0x0800,
                    src = 'aa:aa:aa:bb:bb:bb',
                    dst = mac_dst)
        e.set_payload(ip)
        
        msg= of.ofp_packet_out()
        msg.data = e.pack()
        action=of.ofp_action_output( port=of.OFPP_IN_PORT )
        msg.actions.append(action)
        msg.in_port= port_switch
        self.connection.send(msg)
        
    def addUsername(self, dhcp_pckt, username):
        size=len(username)
        dhcp_pckt.appendOption(225, struct.pack('!%is' %(size), username))
        return dhcp_pckt
    
    def addRelay(self, dhcp_pckt, username):
        size_username = len(username)
        size_attr_eap = size_username + 2
        eap_attr = struct.pack('!BB%is' %(size_username), 1, size_attr_eap, username)
        
        suboption_relay = struct.pack('!BB',7, size_attr_eap) + eap_attr
        dhcp_pckt.appendOption(82, suboption_relay)
        
        return dhcp_pckt
        
        
        
    def sendToDHCPServer(self, dhcp_pckt):
        self.sock.sendto(dhcp_pckt.hdr(None), ('10.0.5.2', 67))
        rep = self.sock.recv(4096)
        
        dhcp_reponse = dhcp(raw=rep)
        return dhcp_reponse