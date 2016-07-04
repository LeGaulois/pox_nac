#-*- coding: utf-8 -*-
import struct
import os
from packet_utils import *
import random
from packet_base import packet_base
from _dbus_bindings import String
from Crypto.Random.random import randint, randrange
from pox.lib.addresses import EthAddr,IPAddr
import hmac
import six

class radius(packet_base):
    """
    RADIUS packet
    """
    
    MIN_LEN = 20

    def __init__(self, raw=None, prev=None,  **kw):
        packet_base.__init__(self)

        self.prev = prev
        self.code = 1
        self.id = random.randint(1,256)
        self.length = 0
        self.authenticator = os.urandom(16)

        self.attributes=[]
        
        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = '[RADIUS %d id=%d' % (self.code, self.id)
        return s + "]"


    def addEAPAttribute(self, eap_pckt):
   
        if eap_pckt.length>255:
            eap_attribute = eap_pckt.hdr()
            length_eap_attribute = eap_pckt.length
            
            #NB tour
            tmp = length_eap_attribute / 253
            nb_eap_attributes = tmp if (length_eap_attribute - tmp*253)==0 else tmp+1
            
            actual_position = 0 
            
            for i in range(0,nb_eap_attributes):
                max_position = min(actual_position +253 , length_eap_attribute)
                length_attribute = max_position +2 - actual_position
                
                self.attributes.append(struct.pack('!BB', 79, length_attribute) \
                                       + eap_attribute[actual_position:max_position])
                                       
                actual_position = max_position
                self.length+= length_attribute
                                                                              
        else:
            self.length+=eap_pckt.length
            self.attributes.append(struct.pack('!BB', 79, eap_pckt.length+2) + eap_pckt.hdr())
    
    
    def addAttribute(self, type, data):
        
        if isinstance(data, int):
            data=str(data)
            len_data = len(data)
            """
            if data<65536:
                self.length += 6
                self.attributes.append(struct.pack('!BBh', type, 4, data))
            elif data<4294967296:
                self.length += 6
                self.attributes.append(struct.pack('!BBi', type, 6, data))
            else:
                self.length += 10
                self.attributes.append(struct.pack('!BBq', type, 10, data))
                
            return 
             """   
        elif isinstance(data, str):
            len_data = len(data)
                       
        elif isinstance(data, EthAddr):   
            data = data.toStr(':', False)
            len_data=len(data)
            
        elif isinstance(data, IPAddr):
            len_data = 4
       
        else:
            raise ValueError('Format de donnee non pris en charge')
        
        self.length+= len_data
        self.attributes.append(struct.pack('!BB%is' %(len_data), type, len_data+2, data))
        
        
    def messageAuthenticator(self, secret):
        self.length+=18
        self.attributes.append(struct.pack('!BB16s' , 80, 18, 16 * six.b('\x00')))
        digest = hmac.new(secret.encode('ascii'), self.getRaw()).digest()
        self.attributes[-1]=struct.pack('!BB16s' , 80, 18, digest)
        
        
    def getMessageAuthentictorValue(self):
        """
        Check if attributes Message-Authenticator exist
        Replace Message-Authenticator string by
            16 octets of 0
        Return Message-Authenticator send by Radius-Server
        """
        
        i=0
        message_authenticator=None
        
        for attribute in self.attributes:
            try:
                type, length= struct.unpack('!BB', attribute[0:2])
                
                if type==80:
                    (message_authenticator,)= struct.unpack('!16s',attribute[2:18])
                    break
                else:
                    i+=1
            except:
                i+=1
                pass

            
        if message_authenticator is not None:
            self.attributes[i]=struct.pack('!BB16s' , 80, 18, 16 * six.b('\x00'))
            return message_authenticator
        
        else:
            raise Exception("Packet does not contain required Message-Authenticator attribute")
            
        
    def checkResponse(self, secret, request_authenticator, request_id):
        assert(isinstance(request_id, int))
        
        if request_id != self.id:
            raise Exception("Invalid request-id")
        
        self.checkMessageAuthenticator(secret, request_authenticator)
        
        
    def checkMessageAuthenticator(self, secret, request_authenticator):
        
        digest_recv= self.getMessageAuthentictorValue().encode('hex')
        
        tmp=self.authenticator
        self.authenticator= request_authenticator
        digest_calc = hmac.new(secret.encode('ascii'), self.getRaw()).hexdigest()
        
        self.authenticator=tmp
        
        if digest_recv!=digest_calc:
            raise Exception("invalid Message-Authenticator")
            
       
        
    def getHeader(self):
        return struct.pack("!BBH", self.code, self.id, self.length)
    
    def getRawAttributes(self):
        attrs=''
        
        for attribute in self.attributes:
            attrs+=attribute
        return attrs
    
    
    def getAttributeValue(self, type_attr):
        """
        Permet de receupérer un attribut EAP si disponible
        """
        
        value = ""
        
        if not isinstance(type_attr, int):
            raise ("Type Radius-Attribute must be a integer")
        
        for attribute in self.attributes:
            type, length= struct.unpack('!BB', attribute[0:2])
            
            if type == type_attr:
                value += attribute[2:]
                    
        return value if value !="" else None
    
    
    def getAuthenticator(self):
        return self.authenticator
        

    def parse(self, raw):
        assert isinstance(raw, bytes)
        
        self.raw = raw
        dlen = len(raw)
        if dlen < self.MIN_LEN:
            self.msg('(radius parse) warning RADIUS packet data too short to parse header: data len %u' % (dlen,))
            return


        # 1- Parse HEADER
        (self.code, self.id, self.length, self.authenticator) \
            = struct.unpack('!BBH16s', raw[:20])

        self.hdr_len = self.length
        self.payload_len = self.hdr_len - self.MIN_LEN
        self.parsed = True

        # 2- Parse RADIUS Attributes        
        actual_position = self.MIN_LEN
        self.attributes = []

        if self.length==self.MIN_LEN:
            return

        while True:
            type_attribute, len_attribute = struct.unpack('!BB', raw[actual_position:actual_position+2])

            if len_attribute <= 2:
                self.msg('(radius parse) warning RADIUS attribute length is too short %s' % (type_attribute))
                return

            self.attributes.append(raw[actual_position:actual_position+int(len_attribute)])
            
            actual_position+=int(len_attribute)
            
            if actual_position>=self.length:
                break
            

    def hdr(self, payload):
        return self.getRaw()
        
    def getRaw(self):
        attrs = self.getRawAttributes()
        self.length = len(attrs) + self.MIN_LEN
        
        return struct.pack('!BBH16s', self.code, self.id, self.length, self.authenticator) + attrs
    
    
    
    
    def setID(self):
        self.id= random.randint(0,256)
        
    