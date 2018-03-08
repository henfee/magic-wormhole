from __future__ import print_function, unicode_literals
from collections import namedtuple
from attr import attrs, attrib
from attr.validators import instance_of, provides
from automat import MethodicalMachine
from twisted.python import log
from twisted.python.internet import Protocol
from noise.connection import NoiseConnection
from noise.exceptions import NoiseInvalidMessage
from .._interfaces import IDilationConnector
from .encode import to_be4, from_be4
from .roles import LEADER

PROLOGUE_LEADER   = b"Magic-Wormhole Dilation Handshake v1 Leader\n\n"
PROLOGUE_FOLLOWER = b"Magic-Wormhole Dilation Handshake v1 Follower\n\n"
NOISEPROTO = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s"

RelayOK = namedtuple("RelayOk", [])
Prologue = namedtuple("Prologue", [])
Frame = namedtuple("Frame", ["frame"])
Disconnect = namedtuple("Disconnect", [])

def first(l):
    return l[0]

@attrs
class DilatedConnectionProtocol(Protocol):
    """I manage an L2 connection.

    When a new L2 connection is needed (as determined by the Leader),
    both Leader and Follower will initiate many simultaneous connections
    (probably TCP, but conceivably others). A subset will actually
    connect. A subset of those will successfully pass negotiation by
    exchanging handshakes to demonstrate knowledge of the session key.
    One of the negotiated connections will be selected by the Leader for
    active use, and the others will be dropped.

    At any given time, there is at most one active L2 connection.
    """

    _connector = attrib(validator=provides(IDilationConnector))
    _dilation_key = attrib(validator=instance_of(bytes))
    _role = attrib()
    _got_prologue = False

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    def __attrs_post_init__(self):
        self._disconnected = OneShotObserver()
        self._buffer = b""
        # encryption: let's use Noise NNpsk0 (or maybe NNpsk2). That uses
        # ephemeral keys plus a pre-shared symmetric key (the Transit key), a
        # different one for each potential connection.
        self._noise = NoiseConnection.from_name(NOISEPROTO)
        self._noise.set_psks(self._dilation_key)
        if self._role is LEADER:
            self._noise.set_as_initiator()
            self._send_prologue = PROLOGUE_LEADER
            self._expected_prologue = PROLOGUE_FOLLOWER
        else:
            self._noise.set_as_responder()
            self._send_prologue = PROLOGUE_FOLLOWER
            self._expected_prologue = PROLOGUE_LEADER
        self._noise.start_handshake()

    def when_disconnected(self):
        return self._disconnected.when_fired()

    @m.state(initial=True)
    def connecting_no_relay(self): pass # pragma: no cover
    @m.state()
    def connecting_with_relay(self): pass # pragma: no cover
    @m.state()
    def want_relay_ok(self): pass # pragma: no cover
    @m.state()
    def want_prologue(self): pass # pragma: no cover
    @m.state()
    def want_ephemeral(self): pass # pragma: no cover
    @m.state(initial=True)
    def ready(self): pass # pragma: no cover

    @m.input()
    def use_relay(self): pass
    @m.input()
    def connected(self): pass
    @m.input()
    def got_more_data(self): pass
    @m.input()
    def got_relay_ok(self): pass
    @m.input()
    def got_prologue(self): pass
    @m.input()
    def got_frame(self, frame): pass

    @m.output()
    def store_relay_handshake(self, relay_handshake):
        self._relay_handshake = relay_handshake
        self._expected_relay_handshake = b"ok\n"
    @m.output()
    def send_relay_handshake(self):
        self.transport.write(self._relay_handshake)

    @m.output()
    def parse_relay_ok(self):
        lerh = len(self._expected_relay_handshake)
        if self._buffer.startswith(self._expected_relay_handshake):
            self._buffer = self._buffer[lerh:]
            return RelayOK()
        return None

    @m.output()
    def parse_prologue(self):
        lb = len(self._buffer)
        lep = len(self._expected_prologue)
        if self._buffer.startswith(self._expected_prologue):
            # prologue good, consume it and process the rest, if any
            self._buffer = self._buffer[lep:]
            return Prologue()
        elif self._buffer != self._expected_prologue[:lb]:
            # the data we've received so far does not match the prologue,
            # so this can't possibly be right. Don't complain until we see
            # the expected length, or a newline, so we can capture the
            # weird input in the log for debugging.
            if (b"\n" in self._buffer or lb >= lep):
                log.msg("bad prologue {}".format(self._buffer[:lep]))
                return Disconnect()
            return None # wait a bit longer
        else:
            # good so far, just waiting for the rest of the prologue
            return None

    @m.output()
    def parse_frame(self):
        if len(self._buffer) < 4:
            return None
        frame_length = from_be4(self._buffer[0:4])
        if len(self._buffer) < frame_length:
            return None
        frame = self._buffer[4:4+frame_length]
        self._buffer = self._buffer[4+frame_length:] # TODO: avoid copy
        return Frame(frame=frame)

    @m.output()
    def send_prologue(self):
        self.transport.write(self._send_prologue)
    @m.output()
    def send_handshake(self):
        message1 = self._noise.write_message() # generate the ephemeral key
        self.transport.write(message1)
    @m.output()
    def process_handshake(self, frame):
        payload = self._noise.read_message()
        del payload # we don't send plaintext in the handshake
        if self._role is LEADER:
            self.kcm_leader_got_handshake()
        else:
            self.kcm_follower_got_handshake()

    @m.output()
    def process_decrypt(self, frame):
        try:
            payload = self._noise.decrypt(frame)
        except NoiseInvalidMessage:
            # if this happens during tests, flunk the test
            log.err("bad inbound frame")
            self.loseConnection()
            return
        if payload is not None:
            # this will deliver the payload to our Manager, if selected
            self.kcm_good_frame(payload)

    connecting_no_relay.upon(use_relay, enter=connecting_with_relay,
                             outputs=[store_relay_handshake])
    connecting_with_relay.upon(connected, enter=want_relay_ok,
                               outputs=[send_relay_handshake])
    want_relay_ok.upon(got_more_data, enter=want_relay_ok,
                       outputs=[parse_relay_ok], collector=first)
    want_relay_ok.upon(got_relay_ok, enter=want_prologue,
                       outputs=[send_prologue])

    connecting_no_relay.upon(connected, enter=want_prologue,
                             outputs=[send_prologue])

    want_prologue.upon(got_more_data, enter=want_prologue,
                       outputs=[parse_prologue], collector=first)
    want_prologue.upon(got_prologue, enter=want_ephemeral, outputs=[])
    # the Noise mode we use (NNpsk0) has exactly one handshake message
    want_ephemeral.upon(got_more_data, enter=want_ephemeral,
                        outputs=[parse_frame], collector=first)
    want_ephemeral.upon(got_frame, enter=ready, outputs=[process_handshake])
    ready.upon(got_more_data, enter=ready,
               outputs=[parse_frame], collector=first)
    ready.upon(got_frame, enter=ready, outputs=[process_decrypt])

    def connectionMade(self):
        self.connected()

    def dataReceived(self, data):
        self._buffer += data
        while True:
            token = self.got_more_data()
            if isinstance(token, RelayOK):
                self.got_relay_ok()
            elif isinstance(token, Prologue):
                self.got_prologue()
            elif isinstance(token, Frame):
                self.got_frame(token.frame)
            elif isinstance(token, Disconnect):
                self.loseConnection()
            else:
                break

    def connectionLost(self, why=None):
        self._disconnected.fire(self)

    # from L3 above
    def encrypt_and_send(self, payload):
        frame = self._noise.send(payload)
        self.transport.write(to_be4(len(frame)) + frame)

    def disconnect(self):
        self.transport.loseConnection()


# This is a separate Confirmation machine. We send an empty payload in the
# first encrypted Noise packet in each direction, and call it the KCM (Key
# Confirmation Message) frame. The Follower sends this as soon as the
# encrypted connection is established (which is right after the ephemeral
# key packet arrives at the follower), then it waits for a response. The
# Leader waits to see this KCM, which indicates that the connection is a
# viable contender, and it goes into the selection pool. Later, when the
# pool resolves and a winner is picked, the Leader sends its own KCM on the
# winning connection and drops the others. When the Follower sees that KCM,
# it selects that connection for use and drops the others too.

    # This would be too messy to merge into the machine above: the distinction
    # between leader and follower would double the number of states.

@attr
class KCMLeader(object):
    _connection = attrib(validator=instance_of(DilatedConnectionProtocol))

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    @m.state(initial=True)
    def IDLE(self): pass # pragma: no cover
    @m.state()
    def WAITING(self): pass # pragma: no cover
    @m.state()
    def SELECTING(self): pass # pragma: no cover
    @m.state()
    def SELECTED(self): pass # pragma: no cover

    # we "start" as soon as the handshake has been received
    @m.input()
    def got_handshake(self):
        pass
    @m.input()
    def good_frame(self, frame):
        pass
    @m.input()
    def win(self):
        pass

    @m.output()
    def add_contender(self, frame):
        # note: add_contender should not call our .win right away, else Automat
        # will probably get confused. Use eventually().
        self._connector.add_contender(self._connection)
    @m.output()
    def send_kcm(self):
        self._connection.encrypt_and_send(b"")

    @m.output()
    def select(self):
        self._connector.select(self)

    @m.output()
    def deliver_frame(self, frame):
        self._manager.good_frame(frame)

    IDLE.upon(got_handshake, enter=WAITING, outputs=[]) # do not send KCM yet
    WAITING.upon(good_frame, enter=SELECTING, outputs=[add_contender])
    SELECTING.upon(win, enter=SELECTED, outputs=[select, send_kcm]) # now
    SELECTED.upon(good_frame, enter=SELECTED, outputs=[deliver_frame])


class KCMFollower(object):
    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    @m.state(initial=True)
    def IDLE(self): pass # pragma: no cover
    @m.state()
    def WAITING(self): pass # pragma: no cover
    @m.state()
    def SELECTING(self): pass # pragma: no cover
    @m.state()
    def SELECTED(self): pass # pragma: no cover

    # we "start" as soon as the handshake has been received
    @m.input()
    def got_handshake(self):
        pass
    @m.input()
    def good_frame(self, frame):
        pass
    @m.input()
    def win(self):
        pass

    @m.output()
    def send_kcm(self):
        self._connection.encrypt_and_send(b"")

    @m.output()
    def select(self, frame):
        assert frame == b"", frame # empty KCM frame
        self._connector.select(self)

    @m.output()
    def deliver_frame(self, frame):
        self._manager.good_frame(frame)

    IDLE.upon(got_handshake, enter=SELECTING, outputs=[send_kcm])
    SELECTING.upon(good_frame, enter=SELECTED, outputs=[select])
    SELECTED.upon(good_frame, enter=SELECTED, outputs=[deliver_frame])
