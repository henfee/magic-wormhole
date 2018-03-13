from __future__ import print_function, unicode_literals
from collections import namedtuple, deque
from attr import attrs, attrib
from automat import MethodicalMachine
from zope.interface import implementer
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue
from twisted.python import log
from .._interfaces import IDilationManager, ISend
from ..util import dict_to_bytes, bytes_to_dict
from ..observer import OneShotObserver
from .encode import to_be4
from .subchannel import (SubChannel, _SubchannelAddress, _WormholeAddress,
                         ControlEndpoint, SubchannelConnectorEndpoint,
                         SubchannelListenerEndpoint)
from .connector import Connector, parse_hint
from .roles import LEADER, FOLLOWER

PAUSED, RESUMED = object(), object()

(PING, PONG) = (b"\x00", b"\x01")
(OPEN, DATA, CLOSE, ACK) = (b"\x02", b"\x03", b"\x04", b"\x05")

Message = namedtuple("Message", ["id", "seqnum", "type", "data"])

def encode(m):
    if m.type in (PING, PONG):
        assert m.id is not None, m.id
        return m.type + m.id
    data = m.data if m.data is not None else b""
    if m.type in (OPEN, DATA, CLOSE):
        assert m.id is not None, m.id
        return m.type + m.id + to_be4(m.seqnum) + data
    elif m.type == ACK:
        assert m.id is None, m.id
        return m.type + to_be4(m.seqnum)
    raise ValueError("unknown m.type {}".format(m.type))

class OldPeerCannotDilateError(Exception):
    pass

@attrs
@implementer(IDilationManager)
class _ManagerBase(object):
    _eventual_queue = attrib()

    def __attrs_post_init__(self):
        self._got_versions_d = Deferred()

        self._started = False
        self._endpoints = OneShotObserver(self._eventual_queue)

        self._next_subchannel_id = 0 # increments by 2
        self._outbound_queue = deque()
        self._next_outbound_seqnum = 0
        self._highest_inbound_acked = -1
        self._made_first_connection = False
        self._first_connected = OneShotObserver(self._eventual_queue)
        self._host_addr = _WormholeAddress()

    def send_dilation_phase(self, **fields):
        dilation_phase = self._next_dilation_phase
        self._next_dilation_phase += 1
        self._S.send("dilate-%d" % dilation_phase, dict_to_bytes(fields))

    def send_hints(self, hints): # from Connector
        self.send_dilation_phase(type="hints", hints=hints)


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
        if self._connection:
            self._connection.encrypt_and_send(encode(m))

    def subchannel_closed(self, scid, t):
        assert self._subchannels[scid] is t
        del self._subchannels[scid]

    # from our L5 subchannels
    def subchannel_pauseProducing(self, sc):
        was_paused = bool(self._paused_subchannels)
        self._paused_subchannels.add(sc)
        if not was_paused:
            self._connection.pauseProducing()

    def subchannel_resumeProducing(self, sc):
        self._paused_subchannels.discard(sc)
        if not self._paused_subchannels:
            self._connection.resumeProducing()

    def subchannel_stopProducing(self, sc):
        self._paused_subchannels.discard(sc)

    def _start_connecting(self, role):
        self._connector = Connector(self._transit_key, self._relay_url, self,
                                    self._reactor, self._no_listen, self._tor,
                                    self._timing, self._side,
                                    self._eventual_queue,
                                    role)
        self._connector.start()
    # our Connector calls these, through our connecting/connected state machine

    def _use_connection(self, c):
        self._connection = c
        self._queued_unsent = self._queued.copy()
        # the connection can tell us to pause when we send too much data
        c.registerProducer(self, True) # IPushProducer: pause+resume
        # that should call self.resumeProducing right away, which will send our
        # queued messages and unpause our subchannels. TODO: confirm this
        if not self._made_first_connection:
            self._made_first_connection = True
            self._first_connected.fire(None)

    def _stop_using_connection(self):
        # the connection is already lost by this point
        self.pauseProducing()
        del self._connection


    # from our active L2 connection

    def bad_frame(self, c):# TODO: delete this
        if self._selected_l2 is None:
            # well, we certainly aren't selecting this one
            c.disconnect()
        else:
            # make it go away. if that was our selected L2, this will start a
            # new generation
            c.disconnect()

    def good_frame(self, c, payload):
        if self._selected_l2 is None:
            # we're waiting for selection to complete
            # if we're the leader, this could be a KCM frame from a new L2
            if self._role is LEADER:
                if payload != b"":
                    log.err("weird, Follower's KCM wasn't empty")
                self._connector.add_candidate(c)
            if self._role is FOLLOWER:
                # as follower, we expect to see one KCM frame from the selected
                # L2, and silence from the rest. So use the L2 for the first
                # good frame we get.
                if payload != b"":
                    log.err("weird, Leader's KCM wasn't empty")
                self._connector.accept(c)
        else:
            self._got_message(payload)

    def _got_message(self, frame):
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

    def when_first_connected(self):
        return self._first_connected.when_fired()

    def _get_next_seqnum(self):
        seqnum = self._next_outbound_seqnum
        self._next_outbound_seqnum += 1
        return seqnum

    def send_ping(self, ping_id):
        if self._connection:
            m = Message(type=PING, id=ping_id, seqnum=None, data=None)
            self._connection.encrypt_and_send(encode(m))

    def send_pong(self, ping_id):
        if self._connection:
            m = Message(type=PONG, id=ping_id, seqnum=None, data=None)
            self._connection.encrypt_and_send(encode(m))

    def ack(self, resp_seqnum):
        # ACKs are not queued
        if self._connection:
            m = Message(type=ACK, id=None, seqnum=resp_seqnum, data=None)
            self._connection.encrypt_and_send(encode(m))
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
        peer_addr = _SubchannelAddress(scid)
        t = SubChannel(scid, self, self._host_addr, peer_addr)
        self._open_subchannels[scid] = t
        self._listener_endpoint._got_open(t, peer_addr)

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
        t.remote_close()

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

class ManagerLeader(_ManagerBase):
    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    @m.state(initial=True)
    def IDLE(self): pass # pragma: no cover

    @m.state()
    def WANTING(self): pass # pragma: no cover
    @m.state()
    def WANTED(self): pass # pragma: no cover
    @m.state()
    def CONNECTING(self): pass # pragma: no cover
    @m.state()
    def CONNECTED(self): pass # pragma: no cover
    @m.state(terminal=True)
    def STOPPED(self): pass # pragma: no cover

    @m.input()
    def start(self): pass # pragma: no cover
    @m.input()
    def rx_PLEASE(self): pass # pragma: no cover
    @m.input()
    def rx_DILATE(self): pass # pragma: no cover
    @m.input()
    def rx_HINTS(self, hint_message): pass # pragma: no cover

    @m.input()
    def connection_made(self, c): pass # pragma: no cover
    @m.input()
    def connection_lost(self): pass # pragma: no cover

    @m.input()
    def stop(self): pass # pragma: no cover

    # these Outputs behave differently for the Leader vs the Follower
    @m.output()
    def send_dilate(self):
        self.send_dilation_phase(type="dilate")

    @m.output()
    def start_connecting(self):
        self._start_connecting(LEADER)

    # these Outputs delegate to the same code in both the Leader and the
    # Follower, but they must be replicated here because the Automat instance
    # is on the subclass, not the shared superclass

    @m.output()
    def use_hints(self, hint_message):
        hint_objs = filter(lambda h: h, # ignore None, unrecognizable
                           [parse_hint(hs) for hs in hint_message["hints"]])
        self._connector.got_hints(hint_objs)
    @m.output()
    def stop_connecting(self):
        self._connector.stop()
    @m.output()
    def use_connection(self, c):
        self._use_connection(c)
    @m.output()
    def stop_using_connection(self):
        self._stop_using_connection()
    @m.output()
    def signal_error(self):
        pass # TODO
    @m.output()
    def signal_error_hints(self, hint_message):
        pass # TODO

    IDLE.upon(rx_HINTS, enter=STOPPED, outputs=[signal_error_hints]) # too early
    IDLE.upon(stop, enter=STOPPED, outputs=[])
    IDLE.upon(rx_PLEASE, enter=WANTED, outputs=[])
    IDLE.upon(start, enter=WANTING, outputs=[])
    WANTED.upon(start, enter=CONNECTING, outputs=[send_dilate,
                                                  start_connecting])
    WANTED.upon(stop, enter=STOPPED, outputs=[])
    WANTING.upon(rx_PLEASE, enter=CONNECTING, outputs=[send_dilate,
                                                       start_connecting])
    WANTING.upon(stop, enter=STOPPED, outputs=[])

    CONNECTING.upon(rx_HINTS, enter=CONNECTING, outputs=[use_hints])
    CONNECTING.upon(connection_made, enter=CONNECTED, outputs=[use_connection])
    CONNECTING.upon(stop, enter=STOPPED, outputs=[stop_connecting])
    # leader shouldn't be getting rx_DILATE, and connection_lost only happens
    # while connected

    CONNECTED.upon(rx_HINTS, enter=CONNECTED, outputs=[]) # too late, ignore
    CONNECTED.upon(connection_lost, enter=CONNECTING,
                   outputs=[stop_using_connection,
                            send_dilate,
                            start_connecting])
    CONNECTED.upon(stop, enter=STOPPED, outputs=[stop_using_connection])
    # shouldn't happen: rx_DILATE, connection_made

    # we should never receive DILATE, we're the leader
    IDLE.upon(rx_DILATE, enter=STOPPED, outputs=[signal_error])
    WANTED.upon(rx_DILATE, enter=STOPPED, outputs=[signal_error])
    WANTING.upon(rx_DILATE, enter=STOPPED, outputs=[signal_error])
    CONNECTING.upon(rx_DILATE, enter=STOPPED, outputs=[signal_error])
    CONNECTED.upon(rx_DILATE, enter=STOPPED, outputs=[signal_error])

    def allocate_subchannel_id(self):
        # scid 0 is reserved for the control channel. the leader uses odd
        # numbers starting with 1
        scid_num = self._next_outbound_seqnum + 1
        self._next_outbound_seqnum += 2
        return to_be4(scid_num)

class ManagerFollower(_ManagerBase):
    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    @m.state(initial=True)
    def IDLE(self): pass # pragma: no cover

    @m.state()
    def WANTING(self): pass # pragma: no cover
    @m.state()
    def CONNECTING(self): pass # pragma: no cover
    @m.state()
    def CONNECTED(self): pass # pragma: no cover
    @m.state(terminal=True)
    def STOPPED(self): pass # pragma: no cover

    @m.input()
    def start(self): pass # pragma: no cover
    @m.input()
    def rx_PLEASE(self): pass # pragma: no cover
    @m.input()
    def rx_DILATE(self): pass # pragma: no cover
    @m.input()
    def rx_HINTS(self, hint_message): pass # pragma: no cover

    @m.input()
    def connection_made(self, c): pass # pragma: no cover
    @m.input()
    def connection_lost(self): pass # pragma: no cover
    # follower doesn't react to connection_lost, but waits for a new LETS_DILATE

    @m.input()
    def stop(self): pass # pragma: no cover

    # these Outputs behave differently for the Leader vs the Follower
    @m.output()
    def send_please(self):
        self.send_dilation_phase(type="please")

    @m.output()
    def start_connecting(self):
        self._start_connecting(FOLLOWER)

    # these Outputs delegate to the same code in both the Leader and the
    # Follower, but they must be replicated here because the Automat instance
    # is on the subclass, not the shared superclass

    @m.output()
    def use_hints(self, hint_message):
        hint_objs = filter(lambda h: h, # ignore None, unrecognizable
                           [parse_hint(hs) for hs in hint_message["hints"]])
        self._connector.got_hints(hint_objs)
    @m.output()
    def stop_connecting(self):
        self._connector.stop()
    @m.output()
    def use_connection(self, c):
        self._use_connection(c)
    @m.output()
    def stop_using_connection(self):
        self._stop_using_connection()
    @m.output()
    def signal_error(self):
        pass # TODO
    @m.output()
    def signal_error_hints(self, hint_message):
        pass # TODO

    IDLE.upon(rx_HINTS, enter=STOPPED, outputs=[signal_error_hints]) # too early
    IDLE.upon(rx_DILATE, enter=STOPPED, outputs=[signal_error]) # too early
    # leader shouldn't send us DILATE before receiving our PLEASE
    IDLE.upon(stop, enter=STOPPED, outputs=[])
    IDLE.upon(start, enter=WANTING, outputs=[send_please])
    WANTING.upon(rx_DILATE, enter=CONNECTING, outputs=[start_connecting])
    WANTING.upon(stop, enter=STOPPED, outputs=[])

    CONNECTING.upon(rx_HINTS, enter=CONNECTING, outputs=[use_hints])
    CONNECTING.upon(connection_made, enter=CONNECTED, outputs=[use_connection])
    # shouldn't happen: connection_lost
    #CONNECTING.upon(connection_lost, enter=CONNECTING, outputs=[?])
    CONNECTING.upon(rx_DILATE, enter=CONNECTING, outputs=[stop_connecting,
                                                          start_connecting])
    # receiving rx_DILATE while we're still working on the last one means the
    # leader thought we'd connected, then thought we'd been disconnected, all
    # before we heard about that connection
    CONNECTING.upon(stop, enter=STOPPED, outputs=[stop_connecting])

    CONNECTED.upon(connection_lost, enter=WANTING, outputs=[stop_using_connection])
    CONNECTED.upon(rx_DILATE, enter=CONNECTING, outputs=[stop_using_connection,
                                                         start_connecting])
    CONNECTED.upon(rx_HINTS, enter=CONNECTED, outputs=[]) # too late, ignore
    CONNECTED.upon(stop, enter=STOPPED, outputs=[stop_using_connection])
    # shouldn't happen: connection_made

    # we should never receive PLEASE, we're the follower
    IDLE.upon(rx_PLEASE, enter=STOPPED, outputs=[signal_error])
    WANTING.upon(rx_PLEASE, enter=STOPPED, outputs=[signal_error])
    CONNECTING.upon(rx_PLEASE, enter=STOPPED, outputs=[signal_error])
    CONNECTED.upon(rx_PLEASE, enter=STOPPED, outputs=[signal_error])

    def allocate_subchannel_id(self):
        # the follower uses even numbers starting with 2
        scid_num = self._next_outbound_seqnum + 2
        self._next_outbound_seqnum += 2
        return to_be4(scid_num)


class Dilator(object):
    """I launch the dilation process.

    I am created with every Wormhole (regardless of whether .dilate()
    was called or not), and I handle the initial phase of dilation,
    before we know whether we'll be the Leader or the Follower. Once we
    hear the other side's VERSION message (which tells us that we have a
    connection, they are capable of dilating, and which side we're on),
    then we build a DilationManager and hand control to it.
    """

    def wire(self, sender):
        self._S = ISend(sender)

    # this is the primary entry point, called when w.dilate() is invoked
    def dilate(self):
        if not self._started:
            self._started = True
            self._start().addBoth(self._endpoints.fire)
        yield self._endpoints.when_fired()

    @inlineCallbacks
    def _start(self):
        # first, we wait until we hear the VERSION message, which tells us 1:
        # the PAKE key works, so we can talk securely, 2: their side, so we
        # know who will lead, and 3: that they can do dilation at all

        (role, dilation_version) = yield self._got_versions_d

        if not dilation_version: # 1 or None
            raise OldPeerCannotDilateError()

        if role is LEADER:
            self._manager = ManagerLeader(self._eventual_queue)
        else:
            self._manager = ManagerFollower(self._eventual_queue)

        yield self._manager.when_first_connected()
        peer_addr = _SubchannelAddress()
        control_ep = ControlEndpoint(peer_addr)
        # TODO glue: call control_ep._subchannel_zero_opened(sc)
        connect_ep = SubchannelConnectorEndpoint(self)
        listen_ep = SubchannelListenerEndpoint(self, self._host_addr)
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
            self._manager.rx_PLEASE(message)
        elif type == "dilate":
            self._manager.rx_DILATE(message)
        elif type == "connection-hints":
            self._manager.rx_HINTS(message)
        else:
            log.err("received unknown dilation message type: {}".format(message))
            return
