from pox.core import core
import pox.openflow.libopenflow_01 as of
import pyrad.packet
from client_radius import radClient
from observable import Observable
import ConfigParser, codecs
from pox.lib.addresses import EthAddr,IPAddr
from pox.lib.packet.eap import eap
from pox.lib.packet.eapol import eapol
from pox.lib.packet.radius import radius
from pox.lib.packet.ethernet import ethernet


log = core.getLogger()

User_Name           = 1
NAS_IP_Address      = 2
NAS_Port            = 5
Reply_Message       = 18
Called_Station_Id   = 30
Calling_Station_Id  = 31
EAP_Message         = 79
    
#Recuperation des informations serveur
Config = ConfigParser.ConfigParser()
Config.readfp(codecs.open("nac.cfg","r","utf-8"))
rad_addr=Config.get('RADIUS','address')
rad_authport=Config.get('RADIUS','authport')
rad_acctport=Config.get('RADIUS','acctport')
rad_secret=Config.get('RADIUS','secret')


class Nas(Observable):

    def __init__(self, connection, transparent, nas_address):
        Observable.__init__(self)
        self.radclient = radClient(rad_secret, rad_addr, rad_authport)


        self.ipaddr = "192.168.0.1"
        self.macaddr = "aa:bb:cc:dd:ee:ff"
        self.connection = connection
        self.transparent = transparent
        
        self.host_authenticated={}
        #Permet de stocker la liste des adresses MAC authentifies
        #{'aa:bb:cc:dd:ee:ff':
        #   {
        #       'user':'dupont',
        #       'port': 2,
        #       'ip': 10.0.0.1
        #   }
        #}

        self.host_progress={}
        #Permet de stocker la liste des machines en cours d'authentification
        #{'aa:bb:cc:dd:ee:ff':
        #   {
        #        'port': int,
        #        'match':[]
        #        'eap_id_waiting': 0
        #        'identity'
        #        'mac': aa:bb:cc:dd:ee:ff
        #   }
        #}

    def notify(self, type_notification,*args,**kwargs):
        #gestion des paquets recus par le dispatcher
        try:
            paquet = kwargs.pop('packet')
            port   = kwargs.pop('port')
        except:
            log.debug('Erreur dans le format de notification recu')
            return
                 
        if self.isRunningEAPSession(paquet.src,port):
            if not isinstance(paquet.next, eapol):
                return
            
            #Case EAPOL-Start packet > Reload Session-Authentification
            if paquet.next.type==1:
                self.sendRequestIdentity(paquet.src,port)
                
            else:
                self.continueEAPSession(self.getHostParams(paquet.src), paquet.next.next)
        else:
            log.debug('nouvelle session EAP')
            self.startEAPSession(paquet.src, port)
            
            
    def getHostParams(self,mac_addr):
        try:
            mac=EthAddr(mac_addr)
        except:
            log.debug("Format d'adresse mac non valide")
            
        if self.host_progress.has_key(mac):
            return self.host_progress[mac]
        else:
            return None
            
    
    def continueEAPSession(self, host_param, eap_pckt):
        """
        Cette fonction permet le passage d'un paquet EAP
        a un paquet Radius
        1- transpose le message EAP dans un AVP radius
        2- envoie le paquet au serveur Radius
        3- analyse la reponse du radius
            (accept, denied, continue challenge, ...)
        4- envoie la reponse a host
        """
        
        
        if int(eap_pckt.type)==1:
            host_param['identity'] = str(eap_pckt.data)
            
        rad_pckt = radius()
        rad_pckt.code = host_param['next-radius-code']
        rad_pckt.addAttribute(1, host_param['identity']) #User-Name
        rad_pckt.addAttribute(5, host_param['port']) #Nas-Port
        rad_pckt.addAttribute(31, host_param['mac']) #Calling-Station-Id
        rad_pckt.addAttribute(30, self.macaddr) #Called-Station-Id
        rad_pckt.addEAPAttribute(eap_pckt) #EAP Message
        
        if host_param.has_key('state-challenge'):
            state_challenge= host_param['state-challenge']
            if state_challenge is not None:
                rad_pckt.addAttribute(24, state_challenge)
                
        rad_pckt.messageAuthenticator(rad_secret)
        
        rad=self.radclient.send(rad_pckt)
        
        log.debug("reponse recu du serveur")
        type_radius_msg = int(rad.code)
        
        #Acess-Request
        if type_radius_msg == 11:
            attribute_eap = rad.getAttributeValue(79)
            state_challenge = rad.getAttributeValue(24)
            host_param['state-challenge']= state_challenge
            
            if  attribute_eap is not None:
                self.sendEAP(host_param,  None, attribute_eap)
                
            else:
                self.sendEAP(host_param, 1)
                
        #Access-Accept
        elif type_radius_msg == 2:
            self.deleteRunningSession(host_pram['mac'])
            self.addAuthenticated(host_param['mac'],\
                 host_param['port'], host_param['identity'])
            self.sendEAP(host_param, 3)
            
        #Access-Reject
        elif type_radius_msg == 3:
            log.debug('ACCESS REJECT')
            self.sendEAP(host_param, 4)
        else:
            log.debug('BAD Response from radius server [id=%s]' %(type_radius_msg))
            
            
    def sendEAP(self, host_param, code=None, eap_raw=None):
        
        if eap_raw is None:
            eap_pckt = eap(code=code if code is not None else 1, type_name=1, id=1, raw=eap_raw) 
        else:
            eap_pckt = eap(raw=eap_raw)
 
        eapol_pckt= eapol(version=2, type=0)
        eapol_pckt.next = eap_pckt

        e= ethernet(type= 0x888e,
                        src = EthAddr(self.macaddr),
                        dst = host_param['mac'])
        e.set_payload(eapol_pckt)

        #Envoie du paquet EAPOL/EAP
        msg= of.ofp_packet_out()
        msg.data = e.pack()
        action=of.ofp_action_output( port=of.OFPP_IN_PORT )
        msg.actions.append(action)
        msg.in_port= host_param['port']
        self.connection.send(msg)
            
        
    
    def isAuthenticated(self,mac,port):
        """
        Cette fonction permet de controler si une machine
        est identifiee sur le reseau
        """
        try:
            addr_mac=EthAddr(mac)
        except RuntimeError:
            return False

        if self.host_authenticated.has_key(addr_mac):
            if int(self.host_authenticated[addr_mac]['port'])==int(port):
                return True
            
        return False


    def isRunningEAPSession(self,mac,port):
        """
        Permet de controler si une session EAP est en cours avec cette machine
        cad identification en cours
        """
        try:
            addr_mac=EthAddr(mac)
        except RuntimeError:
            log.debug("Mauvais format d'adresse MAC")
            return False

        if self.host_progress.has_key(addr_mac):
            if int(self.host_progress[addr_mac]['port'])==int(port):
                return True
            else:
                return False

        return False


    def addAuthenticated(self,mac,port,user,ip=None):
        """
        Add user to authenticated array
        Remove user to progress_eap_session array
        """
        
        addr_mac=str(EthAddr(mac))
        port=int(port)
        addr_ip=str(IPAddr(addr_ip)) if ip is not None else ip
        
        del self.host_progress[mac_addr]
        self.host_authenticated[addr_mac]= {'user':user, 'port':port, 'ip': addr_ip}


    def startEAPSession(self, mac,port):
        """
        Demarre letablissement dune session EAP:
            1) Ajout des flux pour bloquer tout le traffic,
                excepte les trames EAP
            2) Demande a la machine son identite
        """
        mac_addr=EthAddr(mac)
        port=int(port)
        
        self.host_progress[mac_addr]={
                    'port': port,
                    'match': [],
                    'eap-id': 0,
                    'mac':mac_addr,
                    'identity': None,
                    'next-radius-code': 1
                    }
        self.flowModEAPStart(mac_addr, port)
        log.debug("ajout du flux 802.1x pour %s sur le port %i" %
                                      (mac_addr, port))


        self.sendRequestIdentity(mac_addr,port)
        self.host_progress[mac_addr]['seq'] = 0

  
    def sendRequestIdentity(self, macaddr_dst, port_switch__dst):
        """
        Send EAP-REQUEST-IDENTITY to host
        Use to initialize EAP-session by switch
        Start EAP-SESSION after EAPOL-START
        """
        
        if not isinstance(macaddr_dst, EthAddr):
            raise ValueError("Invalid mac address format")
        
        if not isinstance(port_switch__dst, int):
            raise ValueError("Invalid port format")
        
        #Requete EAPOL/EAP forgee
        eap_pckt = eap(code=1, type_name=1, id=1)
        eap_pckt.type = 1
        eapol_pckt= eapol(version=2, type=0)
        eapol_pckt.next = eap_pckt
        
        self.host_progress[macaddr_dst]['eap-id']=eapol_pckt.next.getID()

        e= ethernet(type= 0x888e,
                        src = EthAddr(self.macaddr),
                        dst = macaddr_dst)
        e.set_payload(eapol_pckt)   

        #Envoie du paquet EAPOL/EAP
        msg= of.ofp_packet_out()
        msg.data = e.pack()
        action=of.ofp_action_output( port=of.OFPP_IN_PORT )
        msg.actions.append(action)
        msg.in_port= port_switch__dst
        self.connection.send(msg)
        log.debug("envoi REQUEST IDENTITY a %s sur le port %s" %(macaddr_dst, port_switch__dst))
        

    def deleteRunningSession(self, mac_addr):
        if self.eap_running.has_key(mac_addr):
            table_matching=eap_running[mac_addr]['match']

            for match in table_matching:
                msg = of.ofp_flow_removed()
                msg.match=match
                self.connection.send(msg)

        del self.eap_running[mac_addr]



    def flowModEAPStart(self, mac_addr, port):
        """
        Cette fonction permet d ebloquer tout le traffic
        a destination d'une machine, excepte les flux EAP
        """

        #Bloque tout le traffic depuis et vers la machine concerne
        msg = of.ofp_flow_mod()
        msg.match= of.ofp_match()
        msg.match.in_port= port
        msg.match.dl_src= mac_addr
        msg.priority = 1
        self.connection.send(msg)
        self.host_progress[mac_addr]['match'].append(msg.match)

        msg = of.ofp_flow_mod()
        msg.match= of.ofp_match()
        msg.match.dl_dst= mac_addr
        msg.priority = 1
        self.connection.send(msg)
        self.host_progress[mac_addr]['match'].append(msg.match)

        #Ajout de 2 flux pour la gestion de 802.1x
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_type= 0x888e
        msg.match.in_port = port
        msg.match.dl_src = mac_addr
        msg.priority = 200
        action = of.ofp_action_output( port = of.OFPP_CONTROLLER )
        msg.actions.append(action)
        self.connection.send(msg)
        self.host_progress[mac_addr]['match'].append(msg.match)

        
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_type = 0x888e
        msg.match.in_port= of.OFPP_CONTROLLER
        msg.match.dl_dst = mac_addr
        action = of.ofp_action_output( port = port)
        msg.actions.append(action)
        msg.priority = 200
        self.connection.send(msg)
        self.host_progress[mac_addr]['match'].append(msg.match)
        