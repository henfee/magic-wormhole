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
        self._l4.set_l2(l2)
        self._flag = RESUMED
        self._l4.send_queued_messages()
        if self._flag is RESUMED:
            self._l4.resume_all_subchannels() # might get us paused


    @m.output()
    def stop_using_connection(self):
        self._l4.pause_all_subchannels()
        self._flag = PAUSED
        self._l4.remove_l2()
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
    #follower_connecting.upon(l2_lost, enter=follower_connecting, outputs=[?])
    follower_connecting.upon(rx_DILATE, enter=follower_connecting,
                             outputs=[start_connecting_for_generation])
    # receiving rx_DILATE while we're still working on the last one means the
    # leader thought we'd connected, then thought we'd been disconnected, all
    # before we heard about that connection

    # shouldn't happen: l2_lost

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
