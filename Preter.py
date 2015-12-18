__author__ = 'nacho'

import sys
import operator
import Capture
import cmd

from os import listdir

class Preter(cmd.Cmd):
    """Interpreter"""

    def __init__(self):
        cmd.Cmd.__init__(self)
        cmd.Cmd.prompt='>>> '
        self.cap=Capture.Capture()

    def do_quit(self,line):
        return True

    def do_open(self,fich):
        cod=self.cap.open(fich)

    def help_open(self):
        print 'opens a pcap file'
        print 'Usage: open <file>'


    def do_show(self,line):
        l=line.split()
        if len(l)!=1:
            print "One parameter needed:"
            print "\tconversations|conv|c: Shows conversations"
            print "\torphans|orph|c: Shows orphans"
            print "\tservices|serv|s: Shows services"
            print "\tservers|srvr|v: Show servers"
            print "\tcaptures|capt|k: Shows captures in the database"
            return
        else:
            arg=line.lower()
            if arg=="captures" or arg=="capt" or arg=="k":
                caps=self.cap.captures
                for id,f,des in caps:
                    print str(id)+"\t("+f+"):\t"+str(des)
            else:
                if self.cap.dbcapture==None:
                    print "No capture loaded."
                    return
                else:
                    if arg=="conversations" or arg=="conv" or arg=="c":
                        convs=self.cap.conversations
                        cont=1
                        for c in convs:
                            print str(cont)+") "+c[0]+"->"+c[1]+":"+str(c[2])+"/"+c[3]+" ("+str(c[4])+" packets, "+str(c[5])+" bytes)"
                            cont+=1
                    elif arg=="orphans" or arg=="orph" or arg=="o":
                        orphan=self.cap.orphans
                        cont=1
                        for i in orphan:
                            print str(cont)+") "+i[0]+":"+str(i[1])+" -> "+i[2]+":"+str(i[3])+" "+i[4]
                            cont+=1
                    elif arg=="services" or arg=="serv" or arg=="s":
                        servs=self.cap.services
                        cont=1
                        for i in servs:
                            print str(cont)+") "+i[0]+"/"+str(i[1])+" "+str(i[2])
                            cont+=1
                    elif arg=="servers" or arg=="srvr" or arg=="v":
                        convs=self.cap.conversations
                        svs=map(lambda s: (s[1],s[2],s[3]), convs)
                        servers=list(set(svs))
                        ## WATCHOUT, IF I SORT THE LIST, THEN THE REFERENCES TO THE RETURNED QUERY WILL BE WRONG
                        servers=sorted(servers, key=lambda e: (e[2],e[1],e[0]))
                        cont=1
                        for s in servers:
                            print str(cont)+") "+s[0]+":"+str(s[1])+"/"+s[2]
                            cont+=1
                    else:
                        print "Don't know about that"

    def help_show(self):
        print "Shows data about the capture."
        print "Usage:"
        print "\tshow parameter"
        print "Parameter:"
        print "\tconversations|conv|c: Shows conversations"
        print "\torphans|orph|c: Shows orphans"
        print "\tservices|serv|s: Shows services"
        print "\tcaptures|capt|k: Shows captures in the database"
        return

    def do_descr(self,line):
        if self.cap.dbcapture==None:
            print "No capture loaded."
            return
        else:
            print self.cap.get_description()

    def do_set_descr(self,line):
        if self.cap.dbcapture==None:
            print "No capture loaded."
            return
        else:
            self.cap.set_description(line)

    def help_descr(self):
        print "Shows the description of the current capture"

    def help_set_descr(self):
        print "Sets the description of the current capture"
        print "Usage:"
        print "\tset_descr description"

    def do_analyze(self,line):
        self.cap.analyze_orphans()
        self.cap.dbsession.commit()

    def help_analyze(self):
        print "Tries to match previously unmatched packets"
        return

    def do_orphans(self,line):
        p=PreterOrphan(self.cap)
        p.cmdloop()

    def help_orphans(self,line):
        print "Enter orphan mode"
        return

    def do_stats(self,line):
        p=PreterStats(self.cap)
        p.cmdloop()

    def help_stats(self):
        print "Enter stats mode"
        return

    def do_services(self,line):
        p=PreterSvcs(self.cap)
        p.cmdloop()

    def help_services(self):
        print "Enter services mode"
        return

    def do_config(self,line):
        p=PreterConf(self.cap)
        p.cmdloop()

    def help_config(self):
        print "Enter configuration mode"

    def do_ls(self,dire):
        l=listdir('.')
        print l

    def help_ls(self):
        print "Lists files in the directory"

    def do_load_db(self,line):
        l=line.split()
        if len(l)==0:
            print "*** need to provide a capture identifier (try list_captures)"
            return
        try:
            cap_id=int(l[0])
        except ValueError:
            print "*** capture identifier should be an integer"
            return
        self.cap.load(cap_id)

    def help_load_db(self):
        print "Loads a previously saved capture"


class PreterOrphan(cmd.Cmd):
    def __init__(self,cap):
        cmd.Cmd.__init__(self)
        self.old_prompt=cmd.Cmd.prompt
        cmd.Cmd.prompt='Orphans>>> '
        self.cap=cap

    def do_quit(self,line):
        cmd.Cmd.prompt=self.old_prompt
        return True

    def do_show(self,line):
        orphan=self.cap.orphans
        print "id  Src IP           SrcPort  Dst IP           DstPort  Proto  nPkts  bytes"
        cont=1
        for i in orphan:
            c=str(cont)+")"
            print("{:<3} {:<16} :{:<7} {:<16} :{:<7} {:<6} {:<6} {:<6}".format(c,*i))
            cont+=1

    def do_reverse(self,line):
        if len(line)<1:
            print "One parameter needed:"
            print "\treverse id"
            return

        i=int(line)
        list=self.cap.orphans
        lon=len(list)
        if (i<1) or (i>lon):
            print "Id must be between 1 and "+str(lon)
        else:
            self.cap.reverse_orphan(i-1)

    def do_conv(self,line):
        orphans=self.cap.orphans
        num=len(orphans)
        i=int(line)
        if (i>num):
            print "Not such orphan"
            return
        else:
            self.cap.orphan_to_conv(i)

    def help_conv(self,line):
        print "Converts an orphan to conversation"
        print "Usage: conv id"

    def do_merge(self,line):
        """Merges orphans with conversations"""
        self.cap.merge()
        self.cap.dbsession.commit()

    def help_merge(self):
        print "Merges orphans with conversations"
        print "Usage: merge"



class PreterStats(cmd.Cmd):
    def __init__(self,cap):
        cmd.Cmd.__init__(self)
        self.old_prompt=cmd.Cmd.prompt
        cmd.Cmd.prompt='Stats>>> '
        self.cap=cap
        self.cap.statistics()

    def do_quit(self,line):
        cmd.Cmd.prompt=self.old_prompt
        return True

    def do_stats(self,line):
        D=self.cap.statistics()
        print "Capture: "+str(D['id'])+" ("+D['filename']+")"
        print "Description: "+str(D['description'])
        print "Packets: "+str(D['packets'])
        print "Bytes: "+str(D['bytes'])
        print "Conversations: "+str(D['nconversations'])
        print "Orphans: "+str(D['norphans'])

    def do_protocol_stats(self,line):
        l=line.split()
        if len(l)!=2:
            print "*** need to provide two parameters:"
            print "\t (t(cp)|u(dp)) (p(ackets)|b(ytes))"
            return

        if l[1][0]=="b":
            dato="bytes"
        else:
            dato="packets"

        if l[0][0]=="u":
            proto=u"udp"
        else:
            proto=u"tcp"

        stotal=dato+"_"+proto
        total=self.cap.stats[stotal]

        s=self.cap.proto_share(proto,dato)
        sorted_s = sorted(s.items(), key=operator.itemgetter(1))

        for i in sorted_s:
            print str(i[0])+"/"+proto+" "+str(i[1])+" "+dato+" ("+str(total)+")"

    def do_share(self,line):
        l=line.split()
        if len(l)!=2:
            print "*** need to provide two parameters:"
            print "\t (t(cp)|u(dp)|a(ll)) (p(ackets)|b(ytes))"
            return

        if l[1][0]=="b":
            dato="bytes"
        else:
            dato="packets"

        if l[0][0]=="u":
            proto=u"udp"
        elif l[0][0]=="t":
            proto=u"tcp"
        else:
            proto=u"tcp/udp"


        if proto==u"tcp":
            if dato=="bytes":
                d=self.cap.stats['bytes_tcpshare']
                total=self.cap.stats['bytes_tcp']
            else:
                d=self.cap.stats['pkts_tcpshare']
                total=self.cap.stats['packets_tcp']
            sorted_d = sorted(d.items(), key=operator.itemgetter(1), reverse=True)
            lista=map(lambda c: (u"tcp",c[0],c[1]), sorted_d)
        elif proto==u"udp":
            if dato=="bytes":
                d=self.cap.stats['bytes_udpshare']
                total=self.cap.stats['bytes_udp']
            else:
                d=self.cap.stats['pkts_udpshare']
                total=self.cap.stats['packets_udp']
            sorted_d = sorted(d.items(), key=operator.itemgetter(1), reverse=True)
            lista=map(lambda c: (u"tcp",c[0],c[1]), sorted_d)
        else: # proto tcp_udp
            if dato=="bytes":
                x=self.cap.stats['bytes_udpshare'].items()
                b=map(lambda x: (u"udp",x[0],x[1]), x)
                x=self.cap.stats['bytes_tcpshare'].items()
                c=map(lambda x: (u"tcp",x[0],x[1]), x)
                b.extend(c)
                lista=sorted(b, key=lambda tup: tup[2],reverse=True)
                total=self.cap.stats['bytes_tcp']+self.cap.stats['bytes_udp']
            else:
                x=self.cap.stats['pkts_udpshare'].items()
                b=map(lambda x: (u"udp",x[0],x[1]), x)
                x=self.cap.stats['pkts_tcpshare'].items()
                c=map(lambda x: (u"tcp",x[0],x[1]), x)
                b.extend(c)
                lista=sorted(b, key=lambda tup: tup[2],reverse=True)
                total=self.cap.stats['packets_tcp']+self.cap.stats['packets_udp']
        print dato+":"
        for i in lista:
            n=self.cap.service_name(i[0],i[1])
            pct="{0:.0f}%".format((float(i[2])/total)*100)
            print("{:<12} {:<12} {:<4} {:<20}".format(i[0]+"/"+str(i[1]), str(i[2]), pct, n))


class PreterSvcs(cmd.Cmd):
    def __init__(self,cap):
        cmd.Cmd.__init__(self)
        self.old_prompt=cmd.Cmd.prompt
        cmd.Cmd.prompt='Services>>> '
        self.cap=cap

    def do_quit(self,line):
        cmd.Cmd.prompt=self.old_prompt
        return True

    def do_show(self,line):
        servs=self.cap.services
        cont=1
        for i in servs:
            print str(cont)+") "+i[0]+"/"+str(i[1])+" "+str(i[2])
            cont+=1

    def do_descr(self,line):
        l=line.split()
        if len(l)==0:
            print "Usage:"
            print "\tdescr id"
        else:
            i=int(l[0])
            svcs=self.cap.services
            num=len(svcs)
            if (i>num):
                print "Not such service"
                return
            else:
                proto=svcs[i-1][0]
                port=svcs[i-1][1]
                s = unicode(raw_input("Description: "))
                self.cap.set_service_name(proto,port,s)

    # def do_add(self,line):
    #     a=''
    #     while a not in ['t','u']:
    #         a=raw_input('Protocol (tcp|udp): ')
    #         if a[0]=='t':
    #             proto='tcp'
    #         elif a[0]=='u':
    #             proto='udp'
    #         else:
    #             print "Protocol must be UDP or TCP"
    #     ok=False
    #     while not ok:
    #         a=raw_input('Port: ')
    #         if a.isdigit():
    #             port=int(a)
    #             if port>=0 and port<=65535:
    #                 ok=True
    #     descr=raw_input('Description: ')
    #     if len(descr)==0:
    #         descr='-'
    #     self.cap.add_service_sql(port,proto,descr)
    #

class PreterConf(cmd.Cmd):
    def __init__(self,cap):
        cmd.Cmd.__init__(self)
        self.old_prompt=cmd.Cmd.prompt
        cmd.Cmd.prompt='Config>>> '
        self.cap=cap

    def do_quit(self,line):
        cmd.Cmd.prompt=self.old_prompt
        return True

    def do_services(self,line):
        l=line.split()
        if len(l)==0:
            self.help_services()
            return

        servs=self.cap.wkservices
        if l[0]=='show':
            cont=1
            for i in servs:
                print str(cont)+") "+i[0]+"/"+str(i[1])+" "+str(i[2])
                cont+=1
        elif l[0]=='add':
            a='x'
            while a[0] not in ['t','u']:
                a=raw_input('Protocol (tcp|udp): ')
                if a[0]=='t':
                    proto='tcp'
                elif a[0]=='u':
                    proto='udp'
                else:
                    print "Protocol must be UDP or TCP"
            ok=False
            while not ok:
                a=raw_input('Port: ')
                if a.isdigit():
                    port=int(a)
                    if port>=0 and port<=65535:
                        ok=True
            descr=raw_input('Description: ')
            if len(descr)==0:
                descr='-'
            self.cap.add_wkservice_sql(port,proto,descr)
        elif l[0]=='del':
            if l[1].isdigit():
                try:
                    idx=int(l[1])
                    proto=servs[idx][0]
                    port=servs[idx][1]
                    self.cap.del_wkservice(proto,port)
                except IndexError:
                    print "Index error accessing well known service."
            else:
                print "Need an id. Try: services show"
        elif l[0]=='reset':
            self.cap.reset_wkservice()
        else:
            self.help_services()



    def help_services(self):
            print "Usage: "
            print "\tservices show"
            print "\tservices (add|del) id"
            print "\tservices reset"