from __future__ import print_function, unicode_literals
from collections import namedtuple, deque
from attr import attrs, attrib
from attr.validators import instance_of
from automat import MethodicalMachine
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue
from twisted.python import log
from .._interfaces import IWormhole
from ..util import dict_to_bytes, bytes_to_dict
from .l4connection import L4
from .l5_subchannel import (ControlEndpoint, SubchannelConnectorEndpoint,
                            SubchannelListenerEndpoint, _SubchannelAddress)
from .connector import Connector


PAUSED, RESUMED = object(), object()
LEADER, FOLLOWER = object(), object()

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

class OldPeerCannotDilateError(Exception):
    pass

@attrs
class Dilation(object):
    _wormhole = attrib(validator=instance_of(IWormhole))
    _eventual_queue = attrib()

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    def __attrs_post_init__(self):
        self._l4 = L4(self._eventual_queue)
        self._got_versions_d = Deferred()

        self._outbound_queue = deque()
        self._next_outbound_seqnum = 0
        self._highest_inbound_acked = -1
        self._made_first_connection = False
        self._first_connected = OneShotObserver(self._eventual_queue)

    # current scheme:
    # * only the leader sends DILATE, only follower sends PLEASE
    # * follower sends PLEASE upon w.dilate
    # * leader doesn't send DILATE until receiving PLEASE and local w.dilate
    # * leader handles either order of (w.dilate, rx_PLEASE)
    # * maybe signal warning if we stay in a "want" state for too long
    # * after sending DILATE, leader sends HINTS without waiting for response
    # * nobody sends HINTS until they're ready to receive
    # * nobody sends HINTS unless they've called w.dilate()
    # * nobody connects to inbound hints unless they've called w.dilate()
    # * if leader calls w.dilate() but not follower, leader waits forever in
    #   "want" (doesn't send anything)
    # * if follower calls w.dilate() but not leader, follower waits forever
    #   in "want", leader waits forever in "wanted"

    # We're "idle" until all three of:
    # 1: we receive the initial VERSION message and learn our peer's "side"
    #    value (then we compare sides, and the higher one is "leader", and
    #    the lower one is "follower")
    # 2: the peer is capable of dilation, qv version["can-dilate"] which is
    #    a list of integers, require some overlap, "1" is current
    # 3: the local app calls w.dilate()

    @m.state(initial=True)
    def idle(self): pass # pragma: no cover

    @m.state()
    def leader_wanting(self): pass # pragma: no cover
    @m.state()
    def leader_wanted(self): pass # pragma: no cover
    @m.state()
    def leader_connecting(self): pass # pragma: no cover
    @m.state()
    def leader_connected(self): pass # pragma: no cover

    @m.state()
    def follower_wanting(self): pass # pragma: no cover
    @m.state()
    def follower_connecting(self): pass # pragma: no cover
    @m.state()
    def follower_connected(self): pass # pragma: no cover

    @m.input()
    def start_leader(self): pass # pragma: no cover
    @m.input()
    def start_follower(self): pass # pragma: no cover
    @m.input()
    def rx_PLEASE(self): pass # pragma: no cover
    @m.input()
    def rx_DILATE(self, generation): pass # pragma: no cover
    @m.input()
    def rx_HINTS(self, hints): pass # pragma: no cover

    # Both leader and follower are given l2_connected. The leader sees this
    # when the first connection passes negotiation.
    @m.input()
    def l2_connected(self, l2): pass # pragma: no cover
    # leader reacts to l2_lost
    @m.input()
    def l2_lost(self): pass # pragma: no cover
    # follower doesn't react to l2_lost, but waits for a new LETS_DILATE

    def send_dilation_phase(self, **fields):
        dilation_phase = self._next_dilation_phase
        self._next_dilation_phase += 1
        self._S.send("dilate-%d" % dilation_phase, dict_to_bytes(fields))

    @m.output()
    def send_please(self):
        self.send_dilation_phase(type="please")

    @m.output()
    def send_dilate(self):
        self._current_generation = self._next_generation
        self._next_generation += 1
        self.send_dilation_phase(type="dilate",
                                 generation=self._current_generation)

    @m.output()
    def start_connecting_for_generation(self, generation):
        if self._connector:
            self._connector.stop()
        self._current_generation = generation
        self._start_connecting()

    def _start_connecting(self):
        self._connector = Connector(self._current_generation,
                                    self._transit_key,
                                    self._relay_url)
        self._connector.start()

    @m.output()
    def start_connecting(self):
        self._start_connecting()

    def send_hints(self, hints): # from Connector
        self.send_dilation_phase(type="hints", hints=hints)

    @m.output()
    def use_hints(self, hints):
        self._connector.use_hints(hints)

    @m.output()
    def use_connection(self, l2):
        self._l2 = l2
        self._queued_unsent = self._queued.copy()
        # the connection can tell us to pause when we send too much data
        l2.registerProducer(self, True) # IPushProducer: pause+resume
        # that should call self.resumeProducing right away, which will send our
        # queued messages and unpause our subchannels. TODO: confirm this
        if not self._made_first_connection:
            self._made_first_connection = True
            self._first_connected.fire(None)

    @m.output()
    def stop_using_connection(self):
        self.pauseProducing()
        del self._l2
    @m.output()
    def disconnect(self):
        self._l2.loseConnection() # TODO: maybe already gone, for leader

    # PLEASE should only be sent by the follower
    idle.upon(rx_PLEASE, enter=leader_wanted, outputs=[])
    leader_wanted.upon(start_leader, enter=leader_connecting,
                       outputs=[send_dilate, start_connecting])
    idle.upon(start_leader, enter=leader_wanting, outputs=[])
    leader_wanting.upon(rx_PLEASE, enter=leader_connecting,
                        outputs=[send_dilate, start_connecting])

    leader_connecting.upon(rx_HINTS, enter=leader_connecting,
                           outputs=[use_hints])
    leader_connecting.upon(l2_connected, enter=leader_connected,
                           outputs=[use_connection])
    # leader shouldn't be getting rx_DILATE, and l2_lost only happens while
    # connected

    leader_connected.upon(rx_HINTS, enter=leader_connected,
                          outputs=[]) # too late, ignore them
    leader_connected.upon(l2_lost, enter=leader_connecting,
                          outputs=[stop_using_connection,
                                   send_dilate,
                                   start_connecting])
    # shouldn't happen: rx_DILATE, l2_connected


    idle.upon(start_follower, enter=follower_wanting, outputs=[send_please])
    # leader shouldn't send DILATE before receiving PLEASE
    follower_wanting.upon(rx_DILATE, enter=follower_connecting,
                          outputs=[start_connecting_for_generation])

    follower_connecting.upon(rx_HINTS, enter=follower_connecting,
                             outputs=[use_hints])
    follower_connecting.upon(l2_connected, enter=follower_connected,
                             outputs=[use_connection])
    # shouldn't happen: l2_lost
    #follower_connecting.upon(l2_lost, enter=follower_connecting, outputs=[?])
    follower_connecting.upon(rx_DILATE, enter=follower_connecting,
                             outputs=[start_connecting_for_generation])
    # receiving rx_DILATE while we're still working on the last one means the
    # leader thought we'd connected, then thought we'd been disconnected, all
    # before we heard about that connection

    follower_connected.upon(l2_lost, enter=follower_wanting,
                            outputs=[stop_using_connection])
    @m.output()
    def switch_to_generation(self, generation):
        self.stop_using_connection()
        self._current_generation = generation
        self._start_connecting()
    follower_connected.upon(rx_DILATE, enter=follower_connecting,
                            outputs=[switch_to_generation])
    follower_connected.upon(rx_HINTS, enter=follower_connected,
                            outputs=[]) # too late, ignore them
    # shouldn't happen: l2_connected


    # subchannel maintenance
    def allocate_subchannel_id(self):
        # am I the leader or the follower?
        pass

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

    # from our L5 subchannels
    def subchannel_pauseProducing(self, sc):
        was_paused = bool(self._paused_subchannels)
        self._paused_subchannels.add(sc)
        if not was_paused:
            self._l2.pauseProducing()

    def subchannel_resumeProducing(self, sc):
        self._paused_subchannels.discard(sc)
        if not self._paused_subchannels:
            self._l2.resumeProducing()

    def subchannel_stopProducing(self, sc):
        self._paused_subchannels.discard(sc)


    # from our active L2 connection

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

    # IProducer
    def pauseProducing(self):
        self._paused = True
        for t in self._subchannels.values():
            t.pauseProducing()

    def resumeProducing(self):
        self._paused = False

        # first, send any queued messages that we haven't yet sent for this
        # connection, checking for a pause after each one
        while self._queued_unsent:
            m = self._queued_unsent.popleft()
            self.encrypt_and_send(encode(m))
            if self._paused:
                return

        # TODO: For fairness, keep a deque of subchannels. Each time the
        # channel opens up, pop one from the front, move it to the back, then
        # resume it. If that doesn't pause us, do the same for the next one,
        # etc, until either we're paused or everything got resumed.

        for t in self._subchannels.values():
            t.resumeProducing() # TODO


    # from wormhole
    @inlineCallbacks
    def dilate(self, eventual_queue):
        # called when w.dilate() is invoked

        # first, we wait until we hear the VERSION message, which tells us 1:
        # the PAKE key works, so we can talk securely, 2: their side, so we
        # know who will lead, and 3: that they can do dilation at all

        (role, dilation_version) = yield self._got_versions_d

        if not dilation_version: # 1 or None
            raise OldPeerCannotDilateError()

        if role is LEADER:
            self.start_leader()
        else:
            self.start_follower()

        yield self._l4.when_first_connected()
        peer_addr = _SubchannelAddress()
        control_ep = ControlEndpoint(peer_addr) # needs gluing
        connect_ep = SubchannelConnectorEndpoint(self._l4)
        listen_ep = SubchannelListenerEndpoint(self._l4)
        endpoints = (control_ep, connect_ep, listen_ep)
        returnValue(endpoints)

    # from Boss
    def got_wormhole_versions(self, our_side, their_side,
                              their_wormhole_versions):
        # this always happens before received_dilate
        my_role = LEADER if our_side > their_side else FOLLOWER
        dilation_version = None
        their_dilation_versions = their_wormhole_versions.get("can-dilate", [])
        if 1 in their_dilation_versions:
            dilation_version = 1
        self._got_versions_d.callback( (my_role, dilation_version) )

    def received_dilate(self, plaintext):
        # this receives new in-order DILATE-n payloads, decrypted but not
        # de-JSONed.
        message = bytes_to_dict(plaintext)
        type = message["type"]
        if type == "please":
            self.rx_PLEASE(message)
        elif type == "dilate":
            self.rx_DILATE(message)
        elif type == "connection-hints":
            self.rx_HINTS(message)
        else:
            log.err("received unknown dilation message type: {}".format(message))
            return
