from __future__ import print_function, unicode_literals
from collections import namedtuple, deque

(PING, PONG) = (b"\x00", b"\x01")
(OPEN, DATA, CLOSE, ACK) = (b"\x02", b"\x03", b"\x04", b"\x05")

Message = namedtuple("Message", ["id", "seqnum", "type", "data"])

def encode(m):
    if m.type in (PING, PONG):
        return m.type + m.id
    data = m.data if m.data is not None else b""
    if m.type in (OPEN, DATA, CLOSE):
        return m.type + m.id + be4(m.seqnum) + data
    elif m.type == ACK:
        return m.type + be4(m.seqnum)
    raise ValueError("unknown m.type {}".format(m.type))

# message queue, ack, dispatch
class L4(object):
    """I represent the durable per-Wormhole 'level-4' connection.

    Each dilated Wormhole has exactly one of these, created at the
    moment of dilation, and destroyed along with the Wormhole. At any
    given time, this L4 connection has either zero or one L3
    connections, which is used to deliver data."""

    def __init__(self, eventual_queue):
        self._outbound_queue = deque()
        self._next_outbound_seqnum = 0
        self._highest_inbound_acked = -1
        self._made_first_connection = False
        self._first_connected = OneShotObserver(eventual_queue)

    def when_first_connected(self):
        return self._first_connected.when_fired()

    def _get_next_seqnum(self):
        seqnum = self._next_outbound_seqnum
        self._next_outbound_seqnum += 1
        return seqnum

    def got_message(self, frame):
        msgtype = frame[0:1]
        if msgtype == PING:
            ping_id = frame[1:5]
            self.handle_ping(ping_id)
        elif msgtype == PONG:
            ping_id = frame[1:5]
            self.handle_pong(ping_id)
        elif msgtype == OPEN:
            scid = frame[1:5]
            seqnum = frame[5:9]
            self.handle_open(scid)
            self.ack(seqnum)
        elif msgtype == DATA:
            scid = frame[1:5]
            seqnum = frame[5:9]
            data = frame[9:]
            self.handle_data(scid, data)
            self.ack(seqnum)
        elif msgtype == CLOSE:
            scid = frame[1:5]
            seqnum = frame[5:9]
            self.handle_close(scid)
            self.ack(seqnum)
        elif msgtype == ACK:
            resp_seqnum = frame[1:5]
            self.handle_ack(resp_seqnum)
        else:
            log.err("received unknown message type {}".format(frame))

    def send_ping(self, ping_id):
        if self._l3:
            m = Message(type=PING, id=ping_id, seqnum=None, data=None)
            self._l3.encrypt_and_send(encode(m))

    def send_pong(self, ping_id):
        if self._l3:
            m = Message(type=PONG, id=ping_id, seqnum=None, data=None)
            self._l3.encrypt_and_send(encode(m))

    def send_open(self, scid):
        m = Message(type=OPEN, id=scid, seqnum=self._get_next_seqnum(),
                    data=None)
        self._queue_and_send(m)

    def send_data(self, scid, data):
        m = Message(type=DATA, id=scid, seqnum=self._get_next_seqnum(),
                    data=data)
        self._queue_and_send(m)
    def send_close(self, scid):
        m = Message(type=CLOSE, id=scid, seqnum=self._get_next_seqnum(),
                    data=None)
        self._queue_and_send(m)

    def _queue_and_send(self, m):
        self._outbound_queue.append(m)
        if self._l3:
            self._l3.encrypt_and_send(encode(m))

    def subchannel_closed(self, scid, t):
        assert self._subchannels[scid] is t
        del self._subchannels[scid]

    def ack(self, resp_seqnum):
        # ACKs are not queued
        if self._l3:
            m = Message(type=ACK, id=NONE, seqnum=seqnum, data=None)
            self._l3.encrypt_and_send(encode(m))
        self._highest_inbound_acked = resp_seqnum

    def handle_ping(self, ping_id):
        self.send_pong(ping_id)

    def handle_pong(self, ping_id):
        # TODO: update is-alive timer
        pass

    def handle_open(self, scid):
        if scid in self._open_subchannels:
            log.err("received duplicate OPEN for {}".format(scid))
            return
        host_addr = _SubchannelAddress(scid)
        peer_addr = _SubchannelAddress(scid)
        t = SubChannel(scid, self, host_addr, peer_addr)
        self._open_subchannels[scid] = t
        self._listener_endpoint._got_open(t)

    def handle_data(self, scid, data):
        t = self._open_subchannels.get(scid)
        if t is None:
            log.err("received DATA for non-existent subchannel {}".format(scid))
            return
        t.remote_data(data)

    def handle_close(self, scid):
        t = self._open_subchannels.get(scid)
        if t is None:
            log.err("received CLOSE for non-existent subchannel {}".format(scid))
            return
        t.remote_close(data)

    def handle_ack(self, resp_seqnum):
        while (self._outbound_queue and
               self._outbound_queue[0].seqnum <= resp_seqnum):
            self._outbound_queue.popleft()
        self._highest_inbound_acked = max(self._highest_inbound_acked,
                                          resp_seqnum)

    def pauseProducing(self):
        for t in self._subchannels.values():
            t.pauseProducing()

    def resumeProducing(self):
        for t in self._subchannels.values():
            t.resumeProducing()

    def l3_connected(self, l3):
        assert not self._l3
        self._l3 = l3
        for m in self._outbound_queue:
            self._l3.encrypt_and_send(encode(m))
        for t in self._subchannels.values():
            t.resumeProducing()
        if not self._made_first_connection:
            self._made_first_connection = True
            self._first_connected.fire(None)

    def l3_disconnected(self):
        assert self._l3
        self._l3 = None
        for t in self._subchannels.values():
            t.pauseProducing()
        if self._role is LEADER and self._active:
            self._gm.lost()

# the GenerationManager only exists on the Leader side, not the Follower


# TODO: flow control routing

