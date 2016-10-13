from pox.lib.addresses import EthAddr,IPAddr
from gtk.keysyms import checkmark


def checkMac(mac):
    try:
        mac = EthAddr(mac)
        return mac
    except:
        raise ValueError("Bad Mac-Address format")

def checkIP(ip):
    try:
        ip = IPAddr(ip)
        return ip
    except:
        raise ValueError("Bad IPv4-Address format")
    
    
def checkInt(number):
    try:
        number = int(number)
        return number
    except:
        raise ValueError('Bad number format')
    
def checkDict(dictionnary):
    if not isinstance(dictionnary, dict):
        raise ValueError("Bad dictionnary format")
    
    
def checkNetmask(netmask):
    netmask=checkIP(netmask)
    tab = str(netmask).split('.')
    prec=False
    
    
    for nombre in tab:
        nombre=int(nombre)
        if not prec and nombre!=255:
            prec=True
            bits=bin(nombre).split('0b')[1]
            pre=False
            
            for bit in bits:
                if not pre and bit==0:
                    pre=True
                elif pre and bit==1:
                    raise Exception('Invalid netmask')
            
        elif prec and nombre!=0:
            raise Exception('Invalid netmask 3')
        
    return netmask
        

def getOctetNetwork(addr_octet, netmask_octet):
    if netmask_octet==0:
        return '0'
    elif netmask_octet==255:
        return str(addr_octet)
    else:
        netmask_bits = format(netmask_octet,'08b')
        addr_bits = format(addr_octet,'08b')

        res=""
        
        for j in range(0,8):
            if int(netmask_bits[j])==1:
                res+=addr_bits[j]
            else:
                res+='0'
                
                
        return str(int(res,2))
    
def getOctetBroadcast(addr_octet, netmask_octet):
    if netmask_octet==255:
        return str(addr_octet)
    if netmask_octet==0:
        return '255'    
    else:
        netmask_bits = format(netmask_octet,'08b')
        addr_bits = format(addr_octet,'08b')

        res=""
        
        for j in range(0,8):
            if int(netmask_bits[j])==1:
                res+=addr_bits[j]
            else:
                res+='1'
                
                
        return str(int(res,2))
        
                

def getIPNetwork(ip, netmask):
    netmask=checkNetmask(netmask)
    ip=checkIP(ip)
    addr_network = []
    tab_mask = str(netmask).split('.')
    tab_ip = str(ip).split('.')
    
    for i in range(0,4):
        addr_network.append(getOctetNetwork(int(tab_ip[i]), int(tab_mask[i])))
        
    return IPAddr(addr_network[0]+'.'+addr_network[1]+'.'+addr_network[2]+'.'+addr_network[3])


def getIPRelay(ip, netmask):
    """
    Get address from dhcp relay
     = netmask - 2
    """
    netmask=checkNetmask(netmask)
    ip=checkIP(ip)
    addr_relay = []
    tab_mask = str(netmask).split('.')
    tab_ip = str(ip).split('.')
    
    for i in range(0,4):
        addr_relay.append(getOctetBroadcast(int(tab_ip[i]), int(tab_mask[i])))
        
    return IPAddr(addr_relay[0]+'.'+addr_relay[1]+'.'+addr_relay[2]+'.'+str(int(addr_relay[3])-2))

    
    
     
    
