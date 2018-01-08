#!/usr/bin/python3
#
# by Tomas Hlavacek (tmshlvck@gmail.com)

import socket
import threading
import socketserver
import struct
import ipaddress
import psycopg2

import password

HOST, PORT = "0.0.0.0", 15432


def dbg(m):
    print(m)


db_host=password.db_host
db_name=password.db_name
db_user=password.db_user
db_passwd=password.db_passwd
   
def dbconn():
    return 'host=%s dbname=%s user=%s password=%s' % (db_host, db_name, db_user, db_passwd)


def dbselect(select):
    conn = psycopg2.connect(dbconn())
    cur = conn.cursor()
    cur.execute(select)
    for r in cur:
        yield r

    cur.close()
    conn.close()

def dbexec(statement):
    conn = psycopg2.connect(dbconn())
    cur = conn.cursor()
    cur.execute(statement)
    conn.commit()
    cur.close()
    conn.close()




class RTRDatabase(object):
    def __init__(self):
        self.last_serial = 0
        self.connected_routers = set()

    def get_serial(self):
        return self.last_serial

    def set_serial(self, serial):
        self.last_serial = serial

    def get_announcements4(self, serial=0):
        if serial > self.last_serial:
            #return dbselect("select asn, prefix, max_length from payload_roas where filtered = false and family(prefix) = 4;")
            return [(29134, '217.31.48.0/20', 20), (29134, '62.109.128.0/19', 19)]
        else:
            return []

    def get_withdrawals4(self, serial=0):
        return []

    def get_announcements6(self, serial=0):
        return []

    def get_withdrawals6(self, serial=0):
        return []

    def connected(self, host):
        print("Connected from %s" % host)
        self.connected_routers.add(host)
        dbexec("insert into rtr_status_entries (router, state) values ('%s', 1);" % host)

    def disconnected(self, host=None):
        def dbdis(host):
            dbexec("insert into rtr_status_entries (router, state) values ('%s', 0);" % host)

        dbg("Disconnected %s" % str(host))
        if host:
            dbdis(host)
            self.connected_routers.remove(host)
        else:
            for h in self.connected_routers:
                dbdis(h)
            self.connected_routers = set()



class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, bind, handler, db):
        super().__init__(bind, handler)
        self.db = db


class RTRConnHandler(socketserver.BaseRequestHandler):
    PROTO_VERSION = 0

    def setup(self):
        self.session_id = 2345
        self.serial = 1024

        dbg("New connection from: %s " % str(self.client_address))
        self.server.db.connected(self.client_address[0])
        # TODO: register for notifies

    def finish(self):
        self.server.db.disconnected(self.client_address[0])
        # TODO: de-register

    HEADER_LEN = 8
    def decode_header(self, buf):
        # common header in all received packets
        return struct.unpack('!BBHI', buf)
        # reutnrs (proto_ver, pdu_type, sess_id, length)


    SERNOTIFY_TYPE = 0
    SERNOTIFY_LEN = 12
    def send_sernotify(self,serial):
        # serial notify PDU
        dbg("<Serial Notify session_id=%d serial=%d" % (self.session_id, serial))
        self.request.send(struct.pack('!BBHII', self.PROTO_VERSION, self.SERNOTIFY_TYPE,
                                        self.session_id, self.SERNOTIFY_LEN, serial))


    CACHERESPONSE_TYPE = 3
    CACHERESPONSE_LEN = 8
    def send_cacheresponse(self):
        # cache response PDU
        dbg("<Cache response session_id=%d" % self.session_id)
        self.request.send(struct.pack('!BBHI', self.PROTO_VERSION, self.CACHERESPONSE_TYPE,
                                        self.session_id, self.CACHERESPONSE_LEN))


    FLAGS_ANNOUNCE = 1
    FLAGS_WITHDRAW = 0

    IPV4_TYPE = 4
    IPV4_LEN = 20
    def send_ipv4(self, ipnet, asn, maxlen, flags):
        # IPv4 PDU
        dbg("<IPv4 net=%s asn=%d maxlen=%d flags=%d" % (ipnet, asn, maxlen, flags))
        ip = ipaddress.IPv4Network(ipnet)
        self.request.send(struct.pack('!BBHIBBBB4sI', self.PROTO_VERSION, self.IPV4_TYPE,
                                        0, self.IPV4_LEN, flags, ip.prefixlen,
                                        maxlen, 0, ip.network_address.packed, asn))


    def announce_ipv4(self, ipnet, asn, maxlen):
        self.send_ipv4(ipnet, asn, maxlen, self.FLAGS_ANNOUNCE)


    def withdraw_ipv4(self, ipnet, asn, maxlen):
        self.send_ipv4(ipnet, asn, maxlen, self.FLAGS_WITHDRAW)


    IPV6_TYPE = 6
    IPV6_LEN = 32
    def send_ipv6(self, ipnet, asn, maxlen, flags):
        # IPv6 PDU
        dbg("<IPv6 net=%s asn=%d maxlen=%d flags=%d" % (ipnet, asn, maxlen, flags))
        ip = ipaddress.IPv6Network(ipnet)
        self.request.send(struct.pack('!BBHIBBBB16sI', self.PROTO_VERSION, self.IPV6_TYPE,
                                        0, self.IPV6_LEN, flags, ip.prefixlen,
                                        maxlen, 0, ip.network_address.packed, asn))


    def announce_ipv6(self, ipnet, asn, maxlen):
        self.send_ipv6(ipnet, asn, maxlen, self.FLAGS_ANNOUNCE)


    def withdraw_ipv6(self, ipnet, asn, maxlen):
        self.send_ipv6(ipnet, asn, maxlen, self.FLAGS_WITHDRAW)


    EOD_TYPE = 7
    EOD_LEN = 12
    def send_endofdata(self, serial):
        # end of data PDU
        dbg("<End of Data session_id=%d serial=%d" % (self.session_id, serial))
        self.server.db.set_serial(serial)
        self.request.send(struct.pack('!BBHII', self.PROTO_VERSION, self.EOD_TYPE,
                                        self.session_id, self.EOD_LEN, serial))


    CACHERESET_TYPE = 8
    CACHERESET_LEN = 8
    def send_cachereset(self):
        # cache reset PDU
        dbg("<Cache Reset")
        self.request.send(struct.pack('!BBHI', self.PROTO_VERSION, self.CACHERESET_TYPE,
                                        0, self.CACHERESET_LEN))



    SERIAL_QUERY_TYPE = 1
    SERIAL_QUERY_LEN = 12
    def handle_serial_query(self, buf):
        serial = struct.unpack('!I', buf)[0]
        dbg(">Serial query: %d" % serial)
        self.send_cacheresponse()

        for asn, ipnet, maxlen in self.server.db.get_announcements4(serial):
            self.announce_ipv4(ipnet, asn, maxlen)

        for asn, ipnet, maxlen in self.server.db.get_withdrawals4(serial):
            self.withdraw_ipv4(ipnet, asn, maxlen)

        for asn, ipnet, maxlen in self.server.db.get_announcements6(serial):
            self.announce_ipv6(ipnet, asn, maxlen)

        for asn, ipnet, maxlen in self.server.db.get_withdrawals6(serial):
            self.withdraw_ipv6(ipnet, asn, maxlen)

        self.send_endofdata(self.serial)

    RESET_TYPE = 2
    def handle_reset(self):
        dbg(">Reset")
        self.session_id += 1
        self.send_cacheresponse()

        for asn, ipnet, maxlen in self.server.db.get_announcements4(self.serial):
            self.announce_ipv4(ipnet, asn, maxlen)

        for asn, ipnet, maxlen in self.server.db.get_announcements6(self.serial):
            self.announce_ipv6(ipnet, asn, maxlen)

        self.send_endofdata(self.serial)

    ERROR_TYPE = 10
    def handle_error(self, buf):
        dbg(">Error: %s" % str(buf))
 

    def handle(self):
        try:
            while True:
                b = self.request.recv(self.HEADER_LEN, socket.MSG_WAITALL)
                proto_ver, pdu_type, sess_id, length = self.decode_header(b)
                dbg(">Header proto_ver=%d pdu_type=%d sess_id=%d length=%d" % (proto_ver, pdu_type, sess_id, length))

                if pdu_type == self.SERIAL_QUERY_TYPE:
                    b = self.request.recv(self.SERIAL_QUERY_LEN - self.HEADER_LEN,
                        socket.MSG_WAITALL)
                    self.handle_serial_query(b)

                elif pdu_type == self.RESET_TYPE:
                    self.handle_reset()

                elif pdu_type == self.ERROR_TYPE:
                    b = self.request.recv(length - self.HEADER_LEN, socket.MSG_WAITALL)
                    self.handle_error(b)
        except:
            pass



def main():
    db = RTRDatabase()
    server = ThreadedTCPServer((HOST, PORT), RTRConnHandler, db)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        db.disconnected()
        raise

if __name__ == "__main__":
    main()

