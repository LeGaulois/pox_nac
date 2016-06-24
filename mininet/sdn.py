#-*- coding: utf-8 -*-
import sys
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Intf
from mininet.log import setLogLevel, info, error

def sdnTopo(interface_name):

    CONTROLLER_IP='10.0.0.200'

    net = Mininet( topo=None, build=False)

    # Create nodes
    h1 = net.addHost( 'h1', ip='10.0.0.1/8' )
    h2 = net.addHost( 'h2', ip='10.0.0.2/8' )

    # Create switches
    s1 = net.addSwitch( 's1')

    net.addLink(h1, s1, )
    net.addLink(h2, s1, )

    # Add Controllers
    odl_ctrl = net.addController( 'c0', controller=RemoteController, ip=CONTROLLER_IP)


    info( "*** Creation de l'architecture réseau\n" )
    net.build()

    # Connect each switch to a different controller
    s1.start( [odl_ctrl] )


    info( "*** Ajout de l'interface",interface_name,"au switch" )
    _intf = Intf( interface_name, node=s1)
    net.start()
    CLI( net )
    net.stop()

if __name__ == '__main__':
    intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'eth1'
    setLogLevel( 'info' )
    sdnTopo(intfName)





