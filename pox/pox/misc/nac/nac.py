from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.packet.eap import eap
from pox.lib.packet.eapol import eapol
from pox.lib.packet.ethernet import ethernet

from pox.lib.addresses import EthAddr,IPAddr
from forwarding.l2_learning import LearningSwitch
from nas import Nas
from observable import Observable
log = core.getLogger()


class nac (Observable):
    """
    Cette classe permet la gestion de lidentification
    des utilisateurs sur le reseau
    """

    def __init__(self,connection,transparent):
        Observable.__init__(self)
        self.connection = connection
        self.transparent = transparent
        connection.addListeners(self)
        self.nas= Nas(connection, transparent)
        self.L2=LearningSwitch(connection, transparent)
        self.add_observer(self.nas,'nac')


    def _handle_PacketIn (self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """
        packet = event.parsed
        

        #Premier paquet arrivant apres lauthentification
        if self.nas.isAuthenticated(packet.src, dpid_to_str(event.dpid),event.port):
            if packet.type == 0x888e:
                log.debug("paquet EAP recu de %s" %(packet.src))
                self.notify_observers('nac',packet=packet, switch=dpid_to_str(event.dpid), port=event.port)
            else:
                log.debug("%s est authentifie" %(packet.src))
                self.L2._handle_PacketIn(event)
            
        #Traitement des paquets EAP
        elif packet.type == 0x888e:
            log.debug("paquet EAP recu de %s" %(packet.src))
            self.notify_observers('nac',packet=packet, switch=dpid_to_str(event.dpid), port=event.port)
            
        else:
            log.debug("autre")
            self.notify_observers('nac',packet=packet, switch=dpid_to_str(event.dpid), port=event.port)



class l2_nac (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    nac(event.connection, self.transparent)
    

def launch (transparent=False):
  """
  Demarrage du module NAC
  """
  core.registerNew(l2_nac, str_to_bool(transparent))
