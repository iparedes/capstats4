__author__ = 'nacho'

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, BigInteger,String, ForeignKey, Unicode, Binary, LargeBinary, Time, DateTime, Date, Text, Boolean
from sqlalchemy.orm import relationship, backref, deferred
from sqlalchemy.orm import sessionmaker

Base=declarative_base()

class capture (Base):
    __tablename__ = "capture"
    id = Column('id', Integer, primary_key = True)
    filename=Column('filename',String)
    description = deferred(Column('Description', Text))
    ips=relationship("ip",backref="capture")
    conversations=relationship("conversation",backref="capture")
    orphans=relationship("orphan",backref="capture")
    services=relationship("service",backref="capture")

class ip(Base):
    __tablename__ = "ip"
    #id = Column('id', Integer, primary_key = True)
    mac = Column('mac', Unicode)
    ip = Column('ip', Unicode,primary_key=True)
    description=Column('description',Unicode)
    capture_id=Column(Integer,ForeignKey('capture.id'),primary_key=True)
    convsrc=relationship('conversation',backref=backref('ip'),primaryjoin="conversation.ipsrc_ip==ip.ip")
    convdst=relationship('conversation',primaryjoin="conversation.ipdst_ip==ip.ip")

class conversation(Base):
    __tablename__="conversation"
    id = Column('id',Integer,primary_key=True)
    port = Column('port',Integer)
    proto = Column('proto',Unicode)
    packets = Column('packets',Integer)
    bytes = Column('bytes',Integer)
    capture_id=Column(Integer,ForeignKey('capture.id'))
    #service_id=Column(Unicode,ForeignKey('service.id'))
    ipsrc_ip=Column(Unicode,ForeignKey('ip.ip'))
    ipdst_ip=Column(Unicode,ForeignKey('ip.ip'))

class orphan(Base):
    __tablename__="orphan"
    id=Column('id',Integer,primary_key=True)
    macsrc=Column('macsrc',Unicode)
    macdst=Column('macdst',Unicode)
    ipsrc=Column('ipsrc',Unicode)
    ipdst=Column('ipdst',Unicode)
    portsrc=Column('portsrc',Integer)
    portdst=Column('portdst',Integer)
    proto=Column('proto',Integer)
    packets=Column('packets',Integer)
    bytes=Column('bytes',Integer)
    capture_id=Column(Integer,ForeignKey('capture.id'))

class service(Base):
    __tablename__="service"
    id=Column('id',Integer,primary_key=True)
    port = Column('port',Integer)
    proto = Column('proto',Unicode)
    description=Column('description',Unicode)
    capture_id=Column(Integer,ForeignKey('capture.id'))
