from __future__ import print_function, unicode_literals
from collections import namedtuple, deque
from attr import attrs, attrib
from attr.validators import instance_of
from automat import MethodicalMachine
from zope.interface import implementer
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue
from twisted.python import log
from .._interfaces import IWormhole, IDilationManager
from ..util import dict_to_bytes, bytes_to_dict
from ..observer import OneShotObserver
from .encode import to_be4
from .subchannel import (SubChannel, _SubchannelAddress, _WormholeAddress,
                         ControlEndpoint, SubchannelConnectorEndpoint,
                         SubchannelListenerEndpoint)
from .connector import Connector
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
class DilationManager(object):
    _eventual_queue = attrib()

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

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

    @m.input()
    def allocate_subchannel_id(self): pass # pragma: no cover

    @m.output()
    def allocate_leader_subchannel_id(self):
        # scid 0 is reserved for the control channel. the leader uses odd
        # numbers starting with 1
        scid_num = self._next_outbound_seqnum + 1
        self._next_outbound_seqnum += 2
        return to_be4(scid_num)

    @m.output()
    def allocate_follower_subchannel_id(self):
        # the follower uses even numbers starting with 2
        scid_num = self._next_outbound_seqnum + 2
        self._next_outbound_seqnum += 2
        return to_be4(scid_num)

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
                                    self._relay_url,
                                    self)
        self._connector.start()

    @m.output()
    def start_connecting(self):
        self._start_connecting()

    def send_hints(self, hints): # from Connector
        self.send_dilation_phase(type="hints", hints=hints)

    @m.output()
    def use_hints(self, hints):
        self._connector.got_hints(hints)

    # from the Connector: use_connection
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
        # the connection is already lost by this point
        self.pauseProducing()
        del self._l2
    @m.output()
    def disconnect(self):
        self._l2.disconnect() # TODO: maybe already gone, for leader

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

    leader_wanting.upon(allocate_subchannel_id, enter=leader_wanting,
                        outputs=[allocate_leader_subchannel_id],
                        collector=lambda l: l[0])
    leader_wanted.upon(allocate_subchannel_id, enter=leader_wanted,
                       outputs=[allocate_leader_subchannel_id],
                       collector=lambda l: l[0])
    leader_connecting.upon(allocate_subchannel_id, enter=leader_connecting,
                           outputs=[allocate_leader_subchannel_id],
                           collector=lambda l: l[0])
    leader_connected.upon(allocate_subchannel_id, enter=leader_connected,
                          outputs=[allocate_leader_subchannel_id],
                          collector=lambda l: l[0])

    follower_wanting.upon(allocate_subchannel_id, enter=follower_wanting,
                          outputs=[allocate_follower_subchannel_id],
                          collector=lambda l: l[0])
    follower_connecting.upon(allocate_subchannel_id, enter=follower_connecting,
                            outputs=[allocate_follower_subchannel_id],
                            collector=lambda l: l[0])
    follower_connected.upon(allocate_subchannel_id, enter=follower_connected,
                            outputs=[allocate_follower_subchannel_id],
                            collector=lambda l: l[0])


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
        if self._l2:
            self._l2.encrypt_and_send(encode(m))

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

    def bad_frame(self, l2):
        if self._selected_l2 is None:
            # well, we certainly aren't selecting this one
            l2.disconnect()
        else:
            # make it go away. if that was our selected L2, this will start a
            # new generation
            l2.disconnect()

    def good_frame(self, l2, payload):
        if self._selected_l2 is None:
            # we're waiting for selection to complete
            # if we're the leader, this could be a KCM frame from a new L2
            if self._role is LEADER:
                if payload != b"":
                    log.err("weird, Follower's KCM wasn't empty")
                self._connector.add_candidate(l2)
            if self._role is FOLLOWER:
                # as follower, we expect to see one KCM frame from the selected
                # L2, and silence from the rest. So use the L2 for the first
                # good frame we get.
                if payload != b"":
                    log.err("weird, Leader's KCM wasn't empty")
                self._connector.accept(l2)
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
        if self._l2:
            m = Message(type=PING, id=ping_id, seqnum=None, data=None)
            self._l2.encrypt_and_send(encode(m))

    def send_pong(self, ping_id):
        if self._l2:
            m = Message(type=PONG, id=ping_id, seqnum=None, data=None)
            self._l2.encrypt_and_send(encode(m))

    def ack(self, resp_seqnum):
        # ACKs are not queued
        if self._l2:
            m = Message(type=ACK, id=None, seqnum=resp_seqnum, data=None)
            self._l2.encrypt_and_send(encode(m))
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


    # from Boss

    # this is the primary entry point.
    def dilate(self):
        # called when w.dilate() is invoked
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
            self.start_leader()
        else:
            self.start_follower()

        yield self._l4.when_first_connected()
        peer_addr = _SubchannelAddress()
        control_ep = ControlEndpoint(peer_addr)
        # TODO glue: call control_ep._subchannel_zero_opened(sc)
        connect_ep = SubchannelConnectorEndpoint(self)
        listen_ep = SubchannelListenerEndpoint(self, self._host_addr)
        endpoints = (control_ep, connect_ep, listen_ep)
        returnValue(endpoints)

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
