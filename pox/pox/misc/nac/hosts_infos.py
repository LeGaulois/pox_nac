from pox.lib.addresses import EthAddr,IPAddr
from pox.lib.packet.ethernet import ethernet
from tools import *

class HostsInfos(object):
    """
    Class for shared hosts infos between
    other class (NAS, DHCP)
    """

    def __init__(self):
        self.host_authenticated={}
        #Permet de stocker la liste des adresses MAC authentifies
        #{'aa:bb:cc:dd:ee:ff':
        #   {
        #       'user':'dupont', #internal-identity
        #       'switch': mac_addr,
        #       'port': 2,
        #       'ip': 10.0.0.1,
        #       'netmask': 255.255.255.0,
        #       'timestamp': <timestamp>, #Time before restart authentication
        #       'count': 0 
        #   }
        #}
        
    def isAuthenticated(self,addr_mac, switch, port):
        """
        Cette fonction permet de controler si une machine
        est identifiee sur le reseau
        """
        
        addr_mac = checkMac(addr_mac)
        switch = checkMac(switch)

        if self.host_authenticated.has_key(addr_mac):
            if int(self.host_authenticated[addr_mac]['port'])==int(port) \
            and self.host_authenticated[addr_mac]['switch']==switch:
                return True
            
        return False
    
    
    def addAuthenticated(self,mac,switch, port,user,ip=None, netmask=None):
        """
        Add user to authenticated array
        Remove user to progress_eap_session array
        """
        
        mac = checkMac(mac)
        switch = checkMac(switch)
        port = checkInt(port)
        ip = checkIP(ip)
        netmask = checkNetmask(netmask)
        
        self.host_authenticated[mac]= {'user':user, 'switch': switch,\
                    'port':port, 'ip': ip, 'netmask': netmask , 'count':0}
        
        
    def getInfos(self, mac):
        mac = checkMac(mac)
        
        if self.host_authenticated.has_key(mac):
            return self.host_authenticated[mac]
        
        
    def setInfos(self, mac, dict_infos):
        mac = checkMac(mac)
        checkDict(dict_infos)
        
        self.host_authenticated[mac] = dict_infos
        
    def deleteEntry(self, mac):
        mac = checkMac(mac)
        
        if self.host_authenticated.has_key(mac):
            del self.host_authenticated[mac]
        
    def getAll(self):
        return self.host_authenticated
        