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

    def do_analyze_orphans(self,line):
        self.cap.analyze_orphans()
        self.cap.dbsession.commit()

    def help_analyze_orphans(self):
        print "Tries to match previously unmatched packets"
        return

    def do_orphans(self,line):
        p=PreterOrphan(self.cap)
        p.cmdloop()

    def help_orphans(self,line):
        print "Enter orphan mode"
        return

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

