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
import time
from threading import Thread

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


#Intervall (minute) between 2 periodic authentication
INTERVALL = 1

#For Periodic authentication
#Max retry before close session
MAX_RETRY = 3

class Nas(Observable,Thread):
    """
    Create NAS (Network Access Control)
    for 802.1x authentication
    """

    def __init__(self, connection, transparent):
        Observable.__init__(self)
        Thread.__init__(self)
        self.radclient = radClient(rad_secret, rad_addr, rad_authport)


        self.connection = connection
        self.transparent = transparent
        
        self.host_authenticated={}
        #Permet de stocker la liste des adresses MAC authentifies
        #{'aa:bb:cc:dd:ee:ff':
        #   {
        #       'user':'dupont', #internal-identity
        #       'switch': mac_addr,
        #       'port': 2,
        #       'ip': 10.0.0.1,
        #       'timestamp': <timestamp>, #Time before restart authentication
        #       'count': 0 
        #   }
        #}

        self.host_progress={}
        #Permet de stocker la liste des machines en cours d'authentification
        #{'aa:bb:cc:dd:ee:ff':
        #   {
        #        'switch': mac_addr,
        #        'port': int,
        #        'match':[],
        #        'internal-identity': toto, 
        #        'external-identity': toto, 
        #        'mac': aa:bb:cc:dd:ee:ff,
        #        'authenticated': False  #Case for periodic-authenticated
        #   }
        #}
        self.start()

    def notify(self, type_notification,*args,**kwargs):
        """
        Gestion des paquets recus par le dispatcher
        """
        try:
            paquet = kwargs.pop('packet')
            port   = kwargs.pop('port')
            switch = kwargs.pop('switch')
        except:
            log.debug('Erreur dans le format de notification recu')
            return
        
        #Case where user is authenticated and send EAPoL Packet
        # 1) for close port (Type: Logoff)
        # 2) for periodic authentication
        if self.isAuthenticated(paquet.src, switch, port):
            if isinstance(paquet.next, eapol):
                #Case EAPoL-Logoff
                if paquet.next.type==2:
                    self.closeSession(paquet.src)
                    
                #Case EAPoL-Start 
                # User restart computer ?   
                elif paquet.next.type==1:
                    self.verifyIdentity(paquet.src)

                else:
                    self.continueEAPSession(self.getHostParams(paquet.src), paquet.next.next)
                    
                 
        elif self.isRunningEAPSession(paquet.src, switch, port):
            if not isinstance(paquet.next, eapol):
                return
            
            #Case EAPOL-Start packet > Reload Session-Authentification
            if paquet.next.type==1:
                self.sendRequestIdentity(paquet.src,port)
                
            else:
                self.continueEAPSession(self.getHostParams(paquet.src), paquet.next.next)
        else:
            log.debug('nouvelle session EAP')
            self.startEAPSession(paquet.src, switch, port)
            
            
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
            host_param['external-identity'] = str(eap_pckt.data)
            
        rad_pckt = radius()
        rad_pckt.addAttribute(1, host_param['external-identity']) #User-Name
        rad_pckt.addAttribute(87, host_param['port']) #Nas-Port-Id
        rad_pckt.addAttribute(31, host_param['mac']) #Calling-Station-Id
        rad_pckt.addAttribute(30, host_param['switch']) #Called-Station-Id
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
            log.debug('ACCESS ACCEPT ;)')
            authenticated = host_param['authenticated']
            host_param['internal-identity']= rad.getAttributeValue(1)
            
            self.deleteRunningSession(host_param['mac'])
            
            ip_host = rad.getAttributeValue(8)
            
            if not authenticated:
                self.addAuthenticated(host_param['mac'], host_param['switch'],\
                 host_param['port'], host_param['internal-identity'], ip_host)
                
                self.addFlowDHCP(host_param['mac'], host_param['port'])
            
            #We need to verify if user use the same internal-identity
            #for re-authenticate. If not, we need to destroy all existing
            #Flow tables    
            if authenticated:
                param_auth = self.host_authenticated[host_param['mac']]
                
                if param_auth['user']!= host_param['internal-identity']:
                     log.debug('''Different internal-identity 
                     use for connection (%s -> %s)''' %(param_auth['user'], host_param['internal-identity']))
                     log.debug('Delete all-flows for %s and add dhcp-flows' %(host_param['mac']))
                     
                     self.deleteFlows(host_param['mac'])
                     self.addFlowDHCP(host_param['mac'], host_param['port'])
                     self.host_authenticated[host_param['mac']]['user'] = \
                            host_param['internal-identity']
                
            #Set time to verifyIdentity of host
            self.host_authenticated[host_param['mac']]['timestamp'] = \
                int(time.time()) + INTERVALL * 60
                
            self.host_authenticated[host_param['mac']]['count'] = 0
                
            attribute_eap = rad.getAttributeValue(79)
            self.sendEAP(host_param, None, attribute_eap)
            
        #Access-Reject
        elif type_radius_msg == 3:
            log.debug('ACCESS REJECT')
            authenticated = host_param['authenticated']
            
            #Case periodic authentication
            #Delete all flows refere to mac-addr
            #Restart EAP-Session
            if authenticated:
                self.sendEAP(host_param, 4)
                self.closeSession(host_param['mac'])
                self.startEAPSession(host_param['mac'],\
                         host_param['swicth'], host_param['port'])
                          
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
                        src = EthAddr(host_param['switch']),
                        dst = host_param['mac'])
        e.set_payload(eapol_pckt)

        #Envoie du paquet EAPOL/EAP
        msg= of.ofp_packet_out()
        msg.data = e.pack()
        action=of.ofp_action_output( port=of.OFPP_IN_PORT )
        msg.actions.append(action)
        msg.in_port= host_param['port']
        self.connection.send(msg)
            
        
    
    def isAuthenticated(self,mac, switch, port):
        """
        Cette fonction permet de controler si une machine
        est identifiee sur le reseau
        """
        
        try:
            addr_mac=EthAddr(mac)
            switch= EthAddr(switch)
        except RuntimeError:
            return False

        if self.host_authenticated.has_key(addr_mac):
            if int(self.host_authenticated[addr_mac]['port'])==int(port) \
            and self.host_authenticated[addr_mac]['switch']==switch:
                return True
            
        return False


    def isRunningEAPSession(self,mac, switch, port):
        """
        Permet de controler si une session EAP est en cours avec cette machine
        cad identification en cours
        """
        try:
            addr_mac=EthAddr(mac)
            switch = EthAddr(switch)
        except RuntimeError:
            log.debug("Mauvais format d'adresse MAC")
            return False

        if self.host_progress.has_key(addr_mac):
            if int(self.host_progress[addr_mac]['port'])==int(port) \
            and self.host_progress[addr_mac]['switch']==switch:
                return True

        return False


    def addAuthenticated(self,mac,switch, port,user,ip=None):
        """
        Add user to authenticated array
        Remove user to progress_eap_session array
        """
        
        addr_mac=EthAddr(mac)
        switch = EthAddr(switch)
        port=int(port)
        addr_ip=str(IPAddr(ip)) if ip is not None else ip
        
        self.host_authenticated[addr_mac]= {'user':user, 'switch': switch,\
                    'port':port, 'ip': addr_ip, 'count':0}



    def authenticatedToProgress(self,mac_addr):
        """
        Create self.host_progress entry from self.host_authenticated
        entry. Is usefull for periodic authentication
        """
        
        try:
            mac = EthAddr(mac_addr)
        except:
            raise ValueError("Bad MAC address format")
        
        if self.host_authenticated.has_key(mac):
            auth_dict = self.host_authenticated[mac]
            
            self.host_progress[mac]={
                'internal-identity': auth_dict['user'],
                'external-identity': None,
                'switch': auth_dict['switch'],
                'port': auth_dict['port'],
                'mac':mac,
                'match':[],
                'authenticated':True        
                }
            
        else:
            raise Exception("User is not authenticated")
        
        
    def verifyIdentity(self, mac_addr):
        """
        retry authentication to check if is the same user who
        send packets
        """      
        try:
            mac_addr = EthAddr(mac_addr)
            
        except:
            raise ValueError("Bad MAC address format")
        
        self.authenticatedToProgress(mac_addr)
        port = self.host_progress[mac_addr]['port']
        
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
        
        self.sendRequestIdentity(mac_addr, self.host_progress[mac_addr]['port'])
        


    def startEAPSession(self, mac, switch, port):
        """
        Demarre letablissement dune session EAP:
            1) Ajout des flux pour bloquer tout le traffic,
                excepte les trames EAP
            2) Demande a la machine son identite
        """
        mac_addr=EthAddr(mac)
        switch = EthAddr(switch)
        port=int(port)
        
        self.host_progress[mac_addr]={
                    'switch': switch,
                    'port': port,
                    'match': [],
                    'mac':mac_addr,
                    'external-identity': None,
                    'authenticated':False
                    }
        self.flowModEAPStart(mac_addr, port)
        log.debug("ajout du flux 802.1x pour %s sur le port %i" %
                                      (mac_addr, port))


        self.sendRequestIdentity(mac_addr,port)

  
    def sendRequestIdentity(self, macaddr_dst, port_switch_dst):
        """
        Send EAP-REQUEST-IDENTITY to host
        Use to initialize EAP-session by switch
        Start EAP-SESSION after EAPOL-START
        """
        
        if not isinstance(macaddr_dst, EthAddr):
            raise ValueError("Invalid mac address format")
        
        if not isinstance(port_switch_dst, int):
            raise ValueError("Invalid port format")
        
        #Requete EAPOL/EAP forgee
        eap_pckt = eap(code=1, type_name=1, id=1)
        eap_pckt.type = 1
        eapol_pckt= eapol(version=2, type=0)
        eapol_pckt.next = eap_pckt
        
        self.host_progress[macaddr_dst]['eap-id']=eapol_pckt.next.getID()
        switch = self.host_progress[macaddr_dst]['switch']
        
        e= ethernet(type= 0x888e,
                        src = EthAddr(switch),
                        dst = macaddr_dst)
        e.set_payload(eapol_pckt)   

        #Envoie du paquet EAPOL/EAP
        msg= of.ofp_packet_out()
        msg.data = e.pack()
        action=of.ofp_action_output( port=of.OFPP_IN_PORT )
        msg.actions.append(action)
        msg.in_port= port_switch_dst
        self.connection.send(msg)
        log.debug("envoi REQUEST IDENTITY a %s sur le port %s" %(macaddr_dst, port_switch_dst))
        

    def deleteRunningSession(self, mac_addr):
        """
        1) Delete flows used for 802.1X authentication
        2) Delete host from host_progress
        """
        if self.host_progress.has_key(mac_addr):
            log.debug("suppresion des flux 802.1x pour %s" %(mac_addr))
            table_matching=self.host_progress[mac_addr]['match']

            for match in table_matching:
                msg = of.ofp_flow_mod(command=of.OFPFC_DELETE,match=match)
                self.connection.send(msg)
         
        del self.host_progress[mac_addr]


    def closeSession(self, mac):
        """
        Use for delete all reference off mac address in:
        - class variable
        - flows-table
        
        Typicall use: receive EAPoL-Logoff
        """
        try:
            mac = EthAddr(mac)
        except:
            raise ValueError("Bad MAC Address format")
        
        if self.host_progress.has_key(mac):
            del self.host_progress[mac]
            
        if self.host_authenticated.has_key(mac):
            del self.host_authenticated[mac]
            
        self.deleteFlows(mac_addr)
          
          
    def deleteFlows(self, mac_addr):
        try:
            mac_addr = EthAddr(mac_addr)
        except:
            raise ValueError("Bad MAC Address format")
             
        msg = of.ofp_flow_mod()
        msg.command = of.OFPFC_DELETE
        msg.match= of.ofp_match()
        msg.match.dl_src= mac_addr
        self.connection.send(msg)
        
        
        msg = of.ofp_flow_mod()
        msg.command = of.OFPFC_DELETE
        msg.match= of.ofp_match()
        msg.match.dl_dst= mac_addr
        self.connection.send(msg)


    def addFlowDHCP(self,mac,port):
        """
        Add redirection for DHCP request
        to controller
        """
        mac = EthAddr(mac)
        port = int(port)
            
        #TODO: test
        #Add Flow for dhcp
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_type = 0x0800
        msg.match.in_port= port
        msg.match.dl_src = mac
        msg.match.nw_proto = 0x11
        msg.match.tp_src = 68
        msg.match.tp_src = 67
        msg.buffer_id = None
        action = of.ofp_action_output( port = of.OFPP_CONTROLLER )
        msg.actions.append(action)
        msg.priority = 100
        self.connection.send(msg)
        
    
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
        
        
    def run(self):
        while True:
            now = int(time.time())
            
            for mac in self.host_authenticated.keys():
                host_params = self.host_authenticated[mac]
                
                if host_params['timestamp'] <= now:
                    #Increment counter and check if counter
                    # is > to MAX_RETRY
                    if host_params['count']+1 > MAX_RETRY:
                        log.debug("Echec de reauthentication")
                        
                    self.host_authenticated[mac]['count'] +=1 
                    host_params['timestamp'] = None
                    thread =Thread(target= self.verifyIdentity \
                            ,args=(mac,))
                    thread.start()
                    
                    
            #Must not lower than minimum time
            #to perform authentication by radius server
            time.sleep(10)
        