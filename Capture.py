__author__ = 'nacho'

import dpkt
import socket
import binascii
import sys
import time
import logging

from xml.dom import minidom


from cap_model import *
from sqlalchemy import func,event
from sqlalchemy.engine import Engine


class Capture():
    def __init__(self):
        engine = create_engine('sqlite:///orm_in_detail.sqlite')
        Session = sessionmaker()
        Session.configure(bind=engine)
        self.dbsession=Session()
        Base.metadata.create_all(engine)


        self.__well_known_tcp=dict()
        self.__well_known_udp=dict()
        self.__load_ports_from_xml()

        self.__ips=dict()
        self.__convs=[]
        self.__servers=[]
        self.__orphans=[]
        self.dbcapture=None


    def __load_ports_from_xml(self):
        xmldoc = minidom.parse('wkservices.xml')
        itemlist = xmldoc.getElementsByTagName('service')
        for s in itemlist:
            proto=s.getElementsByTagName('proto')[0].firstChild.data
            descr=s.getElementsByTagName('description')[0].firstChild.data
            port=s.getElementsByTagName('port')[0].firstChild.data
            if proto=="TCP":
                l=self.__well_known_tcp
            else:
                l=self.__well_known_udp
            l[port]=descr


    def open(self, fich):
        try:
            f = open(fich, "r")
            self.pcap = dpkt.pcap.Reader(f)
            self.npackets = len(list(self.pcap))
            self.processed_packets=0

            self.dbcapture = capture(filename=fich)
            self.dbsession.add(self.dbcapture)
            self.dbsession.flush()
            self.dbsession.commit()

            self.__ips=dict()
            self.__convs=[]
            self.__servers=[]
            self.__orphans=[]

            self.analyze()
            return 1
        except IOError:
            return 0

    def analyze(self):
        for ts,buf in self.pcap:
            p=self.decode_packet(buf)
            if p!=None:
                r=self.__analyze_packet(p)
            a=str(self.processed_packets)+"/"+str(self.npackets)
            print "{}\r".format(a),
        # OjO aqui
        print "\n"
        self.__flush()
        self.dbsession.flush()
        self.dbsession.commit()


    def decode_packet(self,buf):
        P=dict()
        eth=dpkt.ethernet.Ethernet(buf)
        self.processed_packets+=1
        packet_size=len(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            # IP packet
            ip = eth.data
            mac1=unicode(eth.src.encode('hex'))
            mac2=unicode(eth.dst.encode('hex'))
            ip1=unicode(socket.inet_ntoa(ip.src))
            ip2=unicode(socket.inet_ntoa(ip.dst))

            self.__ips[ip1]=mac1
            self.__ips[ip2]=mac2

            if ip.p==dpkt.ip.IP_PROTO_UDP or ip.p==dpkt.ip.IP_PROTO_TCP:
                data=ip.data
                port1=data.sport
                port2=data.dport
                if ip.p==dpkt.ip.IP_PROTO_TCP:
                    proto=u"tcp"
                    flags=data.flags
                else:
                    proto=u"udp"
                    flags=None
                P={'macsrc':mac1,
                   'macdst':mac2,
                   'ipsrc':ip1,
                   'ipdst':ip2,
                   'portsrc':port1,
                   'portdst':port2,
                   'proto':proto,
                   'bytes':packet_size,
                   'flags':flags}
                return P
            else:
                # Not TCP, not UDP
                # save somewhere
                return None
        else:
            # Not ethernet
            # save somewhere
            return None


    def __analyze_packet(self,pkt):
        (c,conv)=self.__match_conversation(pkt['ipsrc'],pkt['portsrc'],pkt['ipdst'],pkt['portdst'],pkt['proto'])
        if (c=='?'):
            if (pkt['proto']==u"tcp"):
                # TCP lets check if is a SYN
                if ((pkt['flags'] & dpkt.tcp.TH_SYN)!=0) and ((pkt['flags'] & dpkt.tcp.TH_ACK) ==0):
                    # Start of 3-way handshake
                    self.__add_conv(pkt['ipsrc'],pkt['ipdst'],pkt['proto'],pkt['portdst'],pkt['bytes'])
                    return "SYN"
            if pkt['macdst']=="ffffffffffff":
                # If broadcast, set server as the destination of the packet
                self.__add_conv(pkt['ipsrc'],pkt['ipdst'],pkt['proto'],pkt['portdst'],pkt['bytes'])
                return "Broadcast"
            if self.__is_multicast(pkt['ipdst']):
                # If multicast assume the destination as the server in the conversation
                self.__add_conv(pkt['ipsrc'],pkt['ipdst'],pkt['proto'],pkt['portdst'],pkt['bytes'])
                return "Multicast"
            # if well known port
            if self.__is_well_known(pkt['portsrc'],pkt['proto']):
                self.__add_conv(pkt['ipdst'],pkt['ipsrc'],pkt['proto'],pkt['portsrc'],pkt['bytes'])
                return "Port "+str(pkt['portsrc'])
            if self.__is_well_known(pkt['portdst'],pkt['proto']):
                self.__add_conv(pkt['ipsrc'],pkt['ipdst'],pkt['proto'],pkt['portdst'],pkt['bytes'])
                return "Port "+str(pkt['portdst'])

            # if end of conversation matches
            s={'port':pkt['portsrc'],'proto':pkt['proto'],'ip':pkt['ipsrc']}
            if s in self.__servers:
                self.__add_conv(pkt['ipdst'],pkt['ipsrc'],pkt['proto'],pkt['portsrc'],pkt['bytes'])
                return "Srv "+pkt['proto']+"/"+str(pkt['portsrc'])
            s={'port':pkt['portdst'],'proto':pkt['proto'],'ip':pkt['ipdst']}
            if s in self.__servers:
                self.__add_conv(pkt['ipsrc'],pkt['ipdst'],pkt['proto'],pkt['portdst'],pkt['bytes'])
                return "Srv "+pkt['proto']+"/"+str(pkt['portdst'])

            # if get here, then add orphan
            self.__add_orphan(pkt)
            return "o"
        else:
            # previous conversation
            conv['packets']+=1
            conv['bytes']+=pkt['bytes']
            # Ojo aqui
            #self.dbsession.flush()
            return "+"

    def analyze_orphans(self):
        self.__analyze_orphans()


    def __analyze_orphans(self):
        orphans=self.dbsession.query(orphan).filter(orphan.capture_id==self.dbcapture.id).all()
        for o in orphans:
            (c,conv)=self.__match_conversation_sql(o.ipsrc,o.portsrc,o.ipdst,o.portdst,o.proto)
            if (c=='?'):
                # does not belong to a conversation
                # let's check if there is any matching server
                s={'port':o.portsrc,'proto':o.proto,'ip':o.ipsrc}
                if s in self.servers:
                    self.__add_conv_sql(o.ipdst,o.ipsrc,o.proto,o.portsrc,o.bytes)
                    self.dbsession.delete(o)
                    self.dbsession.flush()
                    continue
                else:
                    s={'port':o.portdst,'proto':o.proto,'ip':o.ipdst}
                    if s in self.servers:
                        self.__add_conv_sql(o.ipsrc,o.ipdst,o.proto,o.portdst,o.bytes)
                        self.dbsession.delete(o)
                        self.dbsession.flush()
                        continue
            else:
                # belongs to a conversation
                conv.packets+=1
                conv.bytes+=o.bytes
                self.dbsession.delete(o)
                self.dbsession.flush()
                continue

        # if an endpoint is in two orphans lets assume that's the server
        orphans=self.dbsession.query(orphan).filter(orphan.capture_id==self.dbcapture.id).all()
        cont=0
        #borrar=[]
        while len(orphans)>1:
            o,orphans=orphans[0],orphans[1:]
            found=self.__match_orphan((o.ipsrc,o.portsrc,o.proto),orphans)
            if len(found)>0:
                c=self.__add_conv_sql(o.ipdst,o.ipsrc,o.proto,o.portsrc,o.bytes)
                self.dbsession.delete(o)
                self.dbsession.flush()
                #borrar.append(o)
                for f in found:
                    if f[0]=='<':
                        c=self.__add_conv_sql(f[1].ipdst,f[1].ipsrc,f[1].proto,f[1].portsrc,f[1].bytes)
                    else:
                        c=self.__add_conv_sql(f[1].ipsrc,f[1].ipdst,f[1].proto,f[1].portdst,f[1].bytes)
                    orphans.remove(f[1])
                    self.dbsession.delete(f[1])
                    self.dbsession.flush()
                    #borrar.append(f[1])
            else:
                found=self.__match_orphan((o.ipdst,o.portdst,o.proto),orphans)
                if len(found)>0:
                    c=self.__add_conv_sql(o.ipsrc,o.ipdst,o.proto,o.portdst,o.bytes)
                    self.dbsession.delete(o)
                    self.dbsession.flush()
                    #borrar.append(o)
                    for f in found:
                        if f[0]=='<':
                            c=self.__add_conv_sql(f[1].ipdst,f[1].ipsrc,f[1].proto,f[1].portsrc,f[1].bytes)
                        else:
                            c=self.__add_conv_sql(f[1].ipsrc,f[1].ipdst,f[1].proto,f[1].portdst,f[1].bytes)
                        orphans.remove(f[1])
                        self.dbsession.delete(f[1])
                        self.dbsession.flush()
                        #borrar.append(f[1])
            cont+=1

        self.dbsession.commit()


    def reverse_orphan(self,i):
        """
        Reverses the flow of an orphan
        :param i: index of the orphan in the list of orphans
        :return:
        """
        list=self.dbsession.query(orphan).filter(orphan.capture_id==self.dbcapture.id).all()
        o=list[i]
        ip,prt=o.ipsrc,o.portsrc
        o.ipsrc=o.ipdst
        o.portsrc=o.portdst
        o.ipdst=ip
        o.portdst=prt
        self.dbsession.flush()
        self.dbsession.commit()

    def orphan_to_conv(self,index):
        orphs=self.dbsession.query(orphan).filter(orphan.capture_id==self.dbcapture.id).all()
        o=orphs[index-1]
        self.add_conv_sql(o.ipsrc,o.ipdst,o.proto,o.portdst,o.bytes,o.packets)
        #self.__orphans.remove(o)
        self.dbsession.delete(o)
        self.dbsession.flush()
        self.dbsession.commit()

    def load(self,capid):
        self.__ips=dict()
        self.__convs=[]
        self.__servers=[]
        self.__orphans=[]

        self.dbcapture=self.dbsession.query(capture).filter(capture.id==capid).all()[0]
        for c in self.dbsession.query(conversation).filter(conversation.capture_id==capid).all():
            self.__add_conv(c.ipsrc_ip,c.ipdst_ip,c.proto,c.port,c.bytes,c.packets)


    def __match_conversation(self,ip1,port1,ip2,port2,proto):
        possconv=[item for item in self.__convs if item['proto']==proto and item['port']==port1 and
                  item['ipsrc']==ip2 and item['ipdst']==ip1]

        if len(possconv)>0:
            return('<',possconv[0])
        else:
            possconv=[item for item in self.__convs if item['proto']==proto and item['port']==port2 and
                  item['ipsrc']==ip1 and item['ipdst']==ip2]
            if len(possconv)>0:
                return('>',possconv[0])
            else:
                return ('?',None)

    def __match_conversation_sql(self,ip1,port1,ip2,port2,proto):
        possconv=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id, \
                                      conversation.proto==proto, \
                                      conversation.ipsrc_ip==ip2, \
                                      conversation.ipdst_ip==ip1, \
                                      conversation.port==port1).first()
        if possconv!=None:
            # found matching conversation
            return ('<',possconv)
        else:
            possconv=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id, \
                                      conversation.proto==proto, \
                                      conversation.ipsrc_ip==ip1, \
                                      conversation.ipdst_ip==ip2, \
                                      conversation.port==port2).first()
            if possconv!=None:
                # found match in the other direction
                return ('>',possconv)
            else:
                # Conversation not found
                return ('?',None)

    def __match_orphan(self,ep,l):
        # looks for coincidences of the endpoints ep in l
        found=[]
        for i in l:
            ep2=(i.ipsrc,i.portsrc,i.proto)
            if ep==ep2:
                found.append(("<",i))
                #l.remove(i)
                continue
            ep2=(i.ipdst,i.portdst,i.proto)
            if ep==ep2:
                found.append((">",i))
                #l.remove(i)
                continue
        return found

    def __add_conv(self,ips,ipd,proto,port,packet_size,packets=1):
        a={'ipsrc':ips,'ipdst':ipd,'proto':proto,'port':port,'bytes':packet_size,'packets':packets}
        self.__convs.append(a)
        b={'proto':proto,'port':port,'ip':ipd}
        self.__servers.append(b)
        return a

    def __add_conv_sql(self,ips,ipd,proto,port,packet_size,packets=1):
        """Adds a new (assumes doesn't exist previously) conversation to the current capture"""

        ## CHECK IF PREVIOUSLY EXISTS?????

        conv1=conversation(ipsrc_ip=ips,ipdst_ip=ipd,proto=proto,port=port, \
                            capture_id=self.dbcapture.id,packets=packets,bytes=packet_size)
        self.dbsession.add(conv1)
        return conv1

    def __add_orphan(self,pkt):
        # macsrc,ipsrc,portsrc,macdst,ipdst,portdst,proto,bytes):
        ipsrc=pkt['ipsrc']
        ipdst=pkt['ipdst']
        portsrc=pkt['portsrc']
        portdst=pkt['portdst']
        proto=pkt['proto']
        bytes=pkt['bytes']

        # check if the flow already exists (this enables grouping orphans)
        o=[item for item in self.__orphans if item['proto']==proto and item['portsrc']==portsrc and
                  item['ipsrc']==ipsrc and item['portdst']==portdst and item['ipdst']==ipdst]
        if len(o)==1:
            o[0]['packets']+=1
            o[0]['bytes']+=bytes
        else:
            o=[item for item in self.__orphans if item['proto']==proto and item['portsrc']==portdst and
                  item['ipsrc']==ipdst and item['portdst']==portsrc and item['ipdst']==ipsrc]
            if len(o)==1:
                o[0]['packets']+=1
                o[0]['bytes']+=bytes
            else:
                # new orphan
                o=dict(pkt)
                o['packets']=1
                self.__orphans.append(o)
        return o


    def __flush(self):
        for c in self.__convs:
            conv=conversation(ipsrc_ip=c['ipsrc'],ipdst_ip=c['ipdst'],port=c['port'],proto=c['proto'],
                              packets=c['packets'],bytes=c['bytes'],capture_id=self.dbcapture.id)
            self.dbsession.add(conv)
            serv=self.dbsession.query(service).filter(service.port==c['port'],service.proto==c['proto'],                                                      service.capture_id==self.dbcapture.id).first()
            if serv==None:
                # service not found, we add it
                if c['proto']==u"tcp":
                    descr=self.__well_known_tcp.get(str(c['port']),u"-")
                else:
                    descr=self.__well_known_udp.get(str(c['port']),u"-")

                serv=service(port=c['port'],proto=c['proto'],description=descr,capture_id=self.dbcapture.id)
                self.dbsession.add(serv)
        for i in self.__ips:
            a=ip(ip=i,mac=self.__ips[i],capture_id=self.dbcapture.id)
            self.dbsession.add(a)
        for o in self.__orphans:
            orph=orphan(macsrc=o['macsrc'],macdst=o['macdst'],ipsrc=o['ipsrc'],ipdst=o['ipdst'],
                        proto=o['proto'],portsrc=o['portsrc'],portdst=o['portdst'],
                        bytes=o['bytes'],packets=o['packets'],capture_id=self.dbcapture.id)
            self.dbsession.add(orph)



    def __is_multicast(self,ip):
        a=int(ip.split('.')[0])
        if a>=224 and a<=239:
            return True
        else:
            return False

    def __is_well_known(self,port,proto):
        if proto==u"tcp":
            l=self.__well_known_tcp
        else:
            l=self.__well_known_udp
        if str(port) in l:
            return True
        else:
            return False

    @property
    def conversations(self):
        convs=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id).all()
        convs_list=map(lambda c: (c.ipsrc_ip,c.ipdst_ip,c.port,c.proto,c.packets,c.bytes), convs)
        return convs_list


    @property
    def orphans(self):
        orphs=self.dbsession.query(orphan).filter(orphan.capture_id==self.dbcapture.id).all()
        orphan_list=map(lambda w: (w.ipsrc,w.portsrc,w.ipdst,w.portdst,w.proto,w.packets,w.bytes), orphs)
        return orphan_list

    @property
    def services(self):
        servs=self.dbsession.query(service).order_by(service.proto.asc(),service.port.asc()).all()
        services=map(lambda s: (s.proto,s.port,s.description), servs)
        return services

    @property
    def captures(self):
        caps=self.dbsession.query(capture).all()
        captures=map(lambda c: (c.id,c.filename,c.description), caps)
        return captures

    @property
    def servers(self):
        p=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id).all()
        servers=[]
        for i in p:
            servers.append((i.ipdst_ip,i.port,i.proto))
        return servers
