#!/usr/bin/python
import os
import sys
import contextlib
import collections
import getopt
import struct
import pcapfile
import pcapfile.savefile as pcapsavefile
import dpkt, dpkt.ethernet, dpkt.ip, dpkt.tcp

debug=False
def dprint(s):
    if debug:
        print s

def tcpseq_after(a, b):
    return int(a - b) > 0
def tcpseq_afteror(a, b):
    return int(a - b) >= 0
def tcpseq_before(a, b):
    return int(a - b) < 0
def tcptuple(src, sport, dst, dport):
    return "%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d" % (
        (src >> 24) & 0xff,
        (src >> 16) & 0xff,
        (src >> 8) & 0xff,
        (src >> 0) & 0xff,
        sport,
        (dst >> 24) & 0xff,
        (dst >> 16) & 0xff,
        (dst >> 8) & 0xff,
        (dst >> 0) & 0xff,
        dport)
def parse_inet_endpoint(ep):
    import re
    m = re.match("(\d+).(\d+).(\d+).(\d+):(\d+)", ep)
    addr = (int(m.group(1))<<24) + (int(m.group(2))<<16) + (int(m.group(3))<<8) + (int(m.group(4)))
    port = int(m.group(5))
    return addr, port

class TCPPacket(object):
    ORIGIN = 1
    REPLY = 2
    FIN = 0x1
    SYN = 0x2
    RST = 0x4
    PSH = 0x8
    ACK = 0x10
    URG = 0x20
    SYNTEST = (SYN | RST | ACK)
    def __init__(self, ip, th, dir, when):
        self._src = struct.unpack(">I", ip.src)[0]
        self._dst = struct.unpack(">I", ip.dst)[0]
        self._payloadlen = ip.len - ip.hl * 4 - th.off * 4
        self._th = th
        self._dir = dir
        self._when = when
    @property
    def src(self):
        return self._src
    @property
    def dst(self):
        return self._dst
    @property
    def sport(self):
        return self._th.sport
    @property
    def dport(self):
        return self._th.dport
    @property
    def dir(self):
        return self._dir
    @property
    def is_origin(self):
        return self._dir == TCPPacket.ORIGIN
    @property
    def is_reply(self):
        return self._dir == TCPPacket.REPLY
    @property
    def seq(self):
        return self._th.seq
    @property
    def endseq(self):
        return (self._payloadlen > 0 and self._th.seq + self._payloadlen - 1) or self._th.seq
    @property
    def ackseq(self):
        return self._th.ack
    @property
    def payloadlen(self):  # payload len
        return max(0, self._payloadlen)
    @property
    def is_syn(self):
        return (self._th.flags & self.SYNTEST) == (self.SYN); 
    @property
    def is_synack(self):
        return (self._th.flags & self.SYNTEST) == (self.SYN | self.ACK);
    @property
    def is_fin(self):
        return (self._th.flags & (self.SYN | self.FIN | self.ACK | self.RST)) == (self.FIN | self.ACK);
    @property
    def is_rst(self):
        return (self._th.flags & self.RST) == (self.RST);
    @property
    def when(self):
        return self._when

    def __str__(self):
        flags = self._th.flags
        return "%u:%06u %s %s %c%c%c%c %u%s(%d), ACK %u" % (int(self.when), int(1000000 * (self.when - int(self.when))), tcptuple(self.src, self.sport, self.dst, self.dport),
                      (self.is_origin and "ORIGIN") or "REPLY ", 
                                                                                          (flags & self.SYN and "S") or "-",
                                                                                          (flags & self.ACK and "A") or "-",
                                                                                          (flags & self.FIN and "F") or "-",
                                                                                          (flags & self.RST and "R") or "-",
                                                                                          self.seq, 
                                                                                          (self._payloadlen > 0 and "-%u" % (self.seq + self._payloadlen - 1)) or "",
                      self._payloadlen,
                                                                                          self.ackseq)

class M(object):
    # A simplified conntrack, focus on established only
    S_NONE = 0
    S_SYN_SENT = 1
    S_SYN_RECV = 2
    S_ESTABLISHED = 3
    S_CLOSE = 4
    S_IGNORE = 5
    def __init__(self):
        self.state = self.S_NONE
        self.iss = 0
        self.snd_una = 0
        self.snd_max = 0
        self.snd_nrtx = 0
        self.inflights = list()

    def dump_ts(self, info):
        str1 = "TXQ %s: " % info
        for p in self.inflights:
            str1 = str1 + "(%d, %f)," % p
        dprint(str1)

    def enque_ts(self, endseq, ts):
        dprint("enque_ts(%u, %f)" % (endseq, ts))
        t = (endseq, ts)
        self.inflights.append(t)
        self.dump_ts("ADDED")
    
    def ack_ts(self, ackseq, ts):
        dprint("ack_ts(%u, %f)" % (ackseq, ts))
        last_ackpkt = None
        acked = 0
        while len(self.inflights) > 0:
            t = self.inflights[0]
            if tcpseq_after(ackseq, t[0]):
                self.inflights.pop(0)
                last_ackpkt = t
                acked = acked + 1
            else:
                break
        if acked >= ack_threshold and last_ackpkt is not None:
            print "RTT/%u: %f # SEND@%f, ACK@%f, acked=%d" % (last_ackpkt[0], ts - last_ackpkt[1], last_ackpkt[1], ts, acked)
            self.dump_ts("ACKED")

    def delete_ts(self, ackseq):
        dprint("delete_ts(%u)" % ackseq)
        poped = False
        while len(self.inflights) > 0:
            t = self.inflights[0]
            if tcpseq_after(ackseq, t[0]):
                self.inflights.pop(0)
                poped = True
            else:
                break
        if poped:
            self.dump_ts("DELED")

    def clear_ts(self):
        self.inflights = list()

    def send(self, packet):
        if self.state != self.S_NONE and (packet.is_fin or packet.is_rst):
            dprint("[Connection] CLOSED")
            self.state = self.S_CLOSE
            self.clear_ts()
            return 0

        if self.state == self.S_NONE or self.state == self.S_SYN_SENT:
            if not packet.is_syn:
                return -1
            dprint("[Connection] SYN_SENT")
            self.iss = packet.seq
            self.syn_ts = packet.when
            self.state = self.S_SYN_SENT
            return 0
        elif self.state == self.S_SYN_RECV:
            if packet.seq != (self.iss + 1):
                return -1
            dprint("[Connection] ESTABLISHED")
            self.snd_una = packet.seq
            self.snd_max = packet.seq
            self.snd_nrtx = packet.seq
            self.state = self.S_ESTABLISHED
            self.dump_ts("INIT")
            return 0

        if self.state == self.S_ESTABLISHED:
            if packet.payloadlen == 0:
                pass
            elif tcpseq_afteror(packet.seq, self.snd_max):
                self.enque_ts(packet.endseq, packet.when)
                self.snd_max = packet.endseq + 1
            elif tcpseq_before(packet.endseq, self.snd_una):
                # a old duplicated 
                pass
            elif tcpseq_afteror(packet.endseq, self.snd_nrtx):
                dprint("retx packet founded.")
                self.delete_ts(packet.endseq)
                self.snd_nrtx = packet.endseq + 1

    def recv(self, packet):
        if packet.is_rst or packet.is_fin:
            dprint("[Connection] CLOSED")
            self.state = self.S_CLOSE
            self.clear_ts()
            return

        if self.state == self.S_SYN_SENT:
            if packet.is_synack: 
                if not packet.ackseq == (self.iss + 1):
                    return -1
                dprint("[Connection] SYN_RECV")
                print "RTT/SYN: %f # SYN@%f, SYNACK@%f" % (packet.when - self.syn_ts, self.syn_ts, packet.when)
                self.state = self.S_SYN_RECV
                return 0
        
        if self.state == self.S_ESTABLISHED:
            if tcpseq_before(packet.ackseq, self.snd_una):
                pass # duplicated ack
            elif tcpseq_after(packet.ackseq, self.snd_max):
                pass # ack to data never sent?
            else:
                self.ack_ts(packet.ackseq, packet.when)
                self.snd_una = packet.ackseq
                if tcpseq_after(packet.ackseq, self.snd_nrtx):
                    self.snd_nrtx = packet.ackseq

def usage(out):
    '''
    Analysis tcp packet rtt.
    -l ip:port  -- bound local address of connnection
    -r ip:port  -- bound remote address of connection
    -t number   -- calculate RTT when acked #number of packets, default 1
    -d          -- debug
    ### -x n    -- parse the n-th connection in this pcap file, default 1  
    '''
    print >>out, usage.__doc__


def parse_options():
    opts, args = getopt.gnu_getopt(sys.argv[1:], "l:r:x:ht:d")
    if len(args) == 0:
        print >>sys.stderr, "No input pcap file."
        usage(sys.stderr)
        exit(1)
    elif len(args) > 1:
        print >>sys.stderr, "Only one pcap file expected, but got ", args
        usage(sys.stderr)
        exit(1)
    global laddr, lport, raddr, rport, pcap_filename
    laddr = lport = raddr = rport = 0
    pcap_filename = args[0]
    global debug,ack_threshold
    ack_threshold=1
    for key, value in opts:
        if key == '-h':
            usage(sys.stdout)
            exit(1)
        elif key == '-l':
            laddr, lport = parse_inet_endpoint(value)
        elif key == '-r':
            raddr, rport = parse_inet_endpoint(value)
        elif key == '-d':
            debug = True
        elif key == '-t':
            ack_threshold = int(value)
        
def parse_packet(lltype, packet):
    global laddr, lport, raddr, rport, pcap_filename
    eth = dpkt.ethernet.Ethernet(packet.raw())
    if eth.type != 0x0800:
        return None
    ip = eth.data
    if ip.v != 4:
        return None
    if ip.p != 6:   # TCP
        return None
    src = struct.unpack(">I", ip.src)[0]
    dst = struct.unpack(">I", ip.dst)[0]
    th = ip.data
    if not (laddr and raddr) \
            and (th.flags & TCPPacket.SYNTEST) == TCPPacket.SYN:
        if laddr:
            if src != laddr and th.sport != lport:
                return None
            dprint("bind remote: %s" % tcptuple(src, th.sport, dst, th.dport))
            raddr = dst
            rport = th.dport
        elif raddr:
            if dst != raddr and th.dport != rport:
                return None
            dprint("bind local: %s" % tcptuple(src, th.sport, dst, th.dport))
            laddr = src
            lport = th.sport
        else:
            dprint("bind full:  %s" % tcptuple(src, th.sport, dst, th.dport))
            laddr = src
            raddr = dst
            lport = th.sport
            rport = th.dport
        
    if laddr and raddr:
        if src == laddr and dst == raddr \
                and th.sport == lport and th.dport == rport:
            return TCPPacket(ip, th, TCPPacket.ORIGIN, packet.timestamp + packet.timestamp_us / 1000000.0)
        elif src == raddr and dst == laddr \
                and th.sport == rport and th.dport == lport:
            return TCPPacket(ip, th, TCPPacket.REPLY, packet.timestamp + packet.timestamp_us / 1000000.0)
    return None

def read_packet():
    with contextlib.closing(file(pcap_filename, 'rb')) as fp:
        reader = pcapsavefile.load_savefile(fp)
        for packet in reader.packets:
            try:
                p = parse_packet(reader.header.ll_type, packet)
                if p:
                    yield p
            except dpkt.UnpackError as e:
                print e
    return

def pcap_input_loop():
    m = M()
    for p in read_packet():
        if p:
            dprint(str(p))
            if p.is_origin:
                m.send(p)
            elif p.is_reply:
                m.recv(p)
                
def main():
    parse_options()
    pcap_input_loop()

if __name__ == "__main__":
    main()

