import struct
from attr import attrs, attrib
from attr.validators import instance_of
from twisted.internet.interfaces import ITransport, IProducer, IConsumer
from automat import MethodicalMachine
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
from . import _interfaces



@attrs
@implementer(_interfaces.IDilatedConnection)
class DilatedConnection(object):
    _wormhole = attrib()
    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    # I represent the durable connection for any Wormhole that has been
    # dilated. At any given time, I am either connected or not (there are
    # exactly 0 or 1 live connections). I manage the queue of messages and
    # their acks.

    def __attrs_post_init__(self):
        self._unacked_messages = []
        self._queued_messages = []
        self._connection = None

    @m.state(initial=True)
    def not_connected(self): pass # pragma: no cover

    @m.state()
    def connected(self): pass # pragma: no cover

    @m.input()
    def connection_made(self, connection):
        pass

    @m.input()
    def connection_lost(self):
        pass

    @m.input()
    def send(self, message):
        pass
    @m.input()
    def receive_ack(self, ack):
        pass

    @m.output()
    def send_queued_messages(self, connection):
        XXX
    @m.output()
    def queue_message(self, message):
        XXX
    @m.output()
    def queue_and_send_message(self, message):
        XXX
    @m.output()
    def process_ack(self, ack):
        XXX

    not_connected.upon(connection_made, enter=connected,
                       outputs=[send_queued_messages])
    not_connected.upon(send, enter=not_connected, outputs=[queue_message])
    connected.upon(send, enter=connected, outputs=[queue_and_send_message])
    connected.upon(receive_ack, enter=connected, outputs=[process_ack])
    connected.upon(connection_lost, enter=not_connected, outputs=[])

class OldPeerCannotDilateError(Exception):
    pass

@attrs
class Dilation(object):
    _w = attrib(validator=instance_of(IWormhole))

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    def __attrs_post_init__(self):
        self._l3_waiters = []
        self._l3 = None

    # We're "undecided" until we receive the initial VERSION message and learn
    # our peer's "side" value. Once we learn that, we compare sides, and the
    # higher one is "leader", and the lower one is "follower".

    # "wanted" means the local side has called w.dilate()
    @m.state(initial=True)
    def undecided_unwanted(self): pass # pragma: no cover
    @m.state()
    def undecided_wanted(self): pass # pragma: no cover

    # "impossible" means the other side isn't capable of dilation
    @m.state()
    def impossible(self): pass # pragma: no cover

    @m.state()
    def leader_unwanted(self): pass # pragma: no cover
    @m.state()
    def leader_connecting(self): pass # pragma: no cover
    @m.state()
    def leader_connected(self): pass # pragma: no cover

    # "requested" means the leader has asked us to dilate. This only lasts if
    # we haven't seen a local w.dilate(), which might be transitory, or maybe
    # the local application just really never wants to dilate.
    @m.state()
    def follower_unwanted(self): pass # pragma: no cover
    @m.state()
    def follower_wanted(self): pass # pragma: no cover
    @m.state()
    def follower_unwanted_but_requested(self): pass # pragma: no cover
    @m.state()
    def follower_connecting(self): pass # pragma: no cover
    @m.state()
    def follower_connected(self): pass # pragma: no cover

    # local w.dilate() causes this to trigger
    @m.input()
    def dilate(self): pass # pragma: no cover
    @m.input()
    def become_leader(self): pass # pragma: no cover
    @m.input()
    def become_follower(self): pass # pragma: no cover
    @m.input()
    def rx_LETS_DILATE(self): pass # pragma: no cover

    # Both leader and follower are given l2_connected. The leader sees this
    # when the first connection passes negotiation.
    @m.input()
    def l2_connected(self): pass # pragma: no cover
    # leader reacts to l2_lost
    @m.input()
    def l2_lost(self): pass # pragma: no cover
    # follower doesn't react to l2_lost, but waits for a new LETS_DILATE

    @m.output()
    def send_lets_dilate(self):
        pass


    def rx_versions(self, their_side, their_versions):
        if self._MY_SIDE > their_side:
            self.become_leader()
        else:
            self.become_follower()

    def rx_hints(self, n, hints):
        if n != self.n:
            return
        self.rx_hints_current(hints)

    @m.input()
    def rx_hints_current(self, hints): pass # pragma: no cover

    def do_leader_connect(self):
        # send LETS-DILATE-n
        # initiate connections?
        # initiate listeners
        # start sending HINTS-n
        pass
    def do_leader_connected(self):
        # (send L2-you-are-winner?)
        # drop all other connections
        # shut down listeners
        # L3.connected
        # notify status delegate?
        pass
    def do_leader_reconnect(self):
        # increment N
        # notify status delegate (l2 offline)
        # send LETS-DILATE-n
        # initiate listeners
        # start sending HINTS-n
        pass
    def do_follower_connect(self):
        # initiate connections? (relay)
        # initiate listeners
        # send HINTS=n
        pass
    def do_follower_connected(self):
        # drop/cancel other connections
        # shut down listeners
        # L3.connected
        # notify status delegate
        pass
    def do_follower_disconnect(self):
        # drop L2
        # increment N
        # notify status delegate
        pass


    undecided_unwanted.upon(become_leader, enter=leader_unwanted, outputs=[])
    undecided_unwanted.upon(become_follower, enter=follower_unwanted, outputs=[])
    undecided_unwanted.upon(dilate, enter=undecided_wanted)
    undecided_wanted.upon(become_follower, enter=follower_wanted)
    undecided_wanted.upon(become_leader, enter=leader_connecting,
                          outputs=[do_leader_connect])
    leader_unwanted.upon(dilate, enter=leader_connecting,
                         outputs=[do_leader_connect])

    follower_unwanted.upon(dilate, enter=follower_wanted)
    follower_unwanted.upon(rx_LETS_DILATE, enter=follower_unwanted_but_requested)
    follower_wanted.upon(rx_LETS_DILATE, enter=follower_connecting,
                         outputs=[do_follower_connect])
    follower_unwanted_but_requested.upon(dilate, enter=follower_connecting,
                                         outputs=[do_follower_connect])

    leader_connecting.upon(l2_connected, enter=leader_connected,
                           outputs=[do_leader_connected])
    leader_connecting.upon(rx_hints_current, enter=leader_connecting,
                           outputs=[initiate_connections])
    # upon(listeners ready): send HINTS-n
    leader_connected.upon(l2_lost, enter=leader_connecting,
                          outputs=[do_leader_reconnect])
    leader_connected.upon(rx_hints_current, enter=leader_connected, outputs=[])
    # upon(listeners ready): huh? too late.

    follower_connecting.upon(l2_connected, enter=follower_connected,
                             outputs=[do_follower_connected])
    follower_connecting.upon(rx_hints_current, enter=follower_connecting,
                             outputs=[initiate_connections])
    follower_connected.upon(rx_hints_current, enter=follower_connected,
                            outputs=[])
    follower_connected.upon(l2_lost, enter=follower_connecting,
                            outputs=[do_follower_disconnect])

        
    def _wait_for_l3(self):
        d = Deferred()
        if self._l3 is not None:
            d.callback(self._l3)
        else:
            self._l3_waiters.append(d)
        return d

    def _l3_created(self, l3):
        assert self._l3 is None
        self._l3 = l3
        for d in self._l3_waiters:
            d.callback(l3)
        del self._l3_waiters

    def start(self):
        # we return the Endpoints right away, but any connections or listeners
        # must wait until we get the keys and version data
        ccep = ControlChannelEndpoint(self._wait_for_l3())
        osep = OutboundSubchannelEndpoint(self._wait_for_l3())
        isep = InboundSubchannelEndpoint(self._wait_for_l3())

        d = self._w._get_wormhole_versions()
        def _derive_keys(res):
            our_side, their_side, wormhole_versions = res
            can_dilate = wormhole_versions.get("can-dilate", 0) # int
            if can_dilate < 1:
                self._l3_created(Failure(OldPeerCannotDilateError()))
                return
            self._is_leader = our_side > their_side
            lf_key = self._w.derive_key("dilation: leader->follower",
                                        SecretBox.KEY_SIZE)
            fl_key = self._w.derive_key("dilation: follower->leader",
                                        SecretBox.KEY_SIZE)
            if self._is_leader:
                inbound_box = SecretBox(fl_key)
                outbound_box = SecretBox(lf_key)
            else:
                inbound_box = SecretBox(lf_key)
                outbound_box = SecretBox(fl_key)
            l3 = L3Connection(self._w, self._is_leader,
                              inbound_box, outbound_box)
            l3.start()
            self._l3_created(l3)
            # except that we don't do this, L3 does when it lacks an L2
            self._w._boss._S.send("lets-dilate-1", something)
        d.addCallback(_derive_keys)
        d.addErrback(log.err)

        return (ccep, osep, isep)

def start_dilator(w):
    d = Dilator(w)
    endpoints = d.start()
    return endpoints

# An object to manage the connection process for LETS-DILATE-n (one such object
# per 'n').

class ConnectorThingy:
    n = attrib()

    def event_rx_hints(hints): pass
        # initiate outbound connection to each hint
    def event_listener_ready(hint): pass
    def event_connection_finished_negotiation(p):
        # might cancel all orhers, or might wait for something better
        pass
    def event_nothing_better_timer_fired(): pass
    def event_cancel(): pass

    def output_notify_l3(): pass
    
    
