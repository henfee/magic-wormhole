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
from ..observer import OneShotObserver
from .encode import to_be4, from_be4

RelayOK = namedtuple("RelayOk", [])
Prologue = namedtuple("Prologue", [])
Frame = namedtuple("Frame", ["frame"])
Disconnect = namedtuple("Disconnect", [])
KCM = namedtuple("KCM", [])
Payload = namedtuple("Payload", ["payload"])

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
    _noise = attrib(validator=instance_of(NoiseConnection))
    _send_prologue = attrib(validator=instance_of(bytes))
    _expected_prologue = attrib(validator=instance_of(bytes))
    _got_prologue = False

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    def __attrs_post_init__(self):
        self._manager = None # set if/when we are selected
        self._disconnected = OneShotObserver()
        self._buffer = b""
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
    @m.state()
    def selecting(self): pass # pragma: no cover
    @m.state(final=True)
    def selected(self): pass # pragma: no cover

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
    @m.input()
    def select(self, manager): pass

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
        self._connector.got_handshake(self)

    def _decrypt(self, frame):
        try:
            return self._noise.decrypt(frame)
        except NoiseInvalidMessage:
            # if this happens during tests, flunk the test
            log.err("bad inbound frame")
            self.loseConnection()
            return None # TODO: handle this in decrypt_kcm/decrypt_payload

    @m.output()
    def decrypt_kcm(self, plaintext):
        assert plaintext == b"", plaintext # KCM is supposed to be empty
        return KCM()
    @m.output()
    def decrypt_payload(self, plaintext):
        return Payload(plaintext)

    @m.output()
    def record_manager(self, manager):
        self._manager = manager

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
    want_ephemeral.upon(got_frame, enter=selecting,
                        outputs=[process_handshake], collector=first)
    selecting.upon(got_more_data, enter=selecting,
                   outputs=[parse_frame], collector=first)
    selecting.upon(got_frame, enter=selecting,
                   outputs=[decrypt_kcm], collector=first)
    selecting.upon(select, enter=selected, outputs=[record_manager])
    selected.upon(got_more_data, enter=selected,
                  outputs=[parse_frame], collector=first)
    selected.upon(got_frame, enter=selecting,
                  outputs=[decrypt_payload], collector=first)

    def connectionMade(self):
        self.connected()

    def dataReceived(self, data):
        self._buffer += data
        while True:
            token = self.got_more_data() # parsing depends upon protocol state
            if isinstance(token, RelayOK):
                self.got_relay_ok()
            elif isinstance(token, Prologue):
                self.got_prologue()
            elif isinstance(token, Frame):
                payload = self.got_frame(token.frame)
                if isinstance(payload, KCM):
                    # we haven't been selected yet, so this must be the KCM
                    self._connector.got_kcm(self)
                elif isinstance(payload, Payload):
                    # we've been selected, forward frames upstairs
                    self._manager.good_frame(payload.payload)
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


# The first encrypted Noise packet in each direction is called the KCM (Key
# Confirmation Message) and it has an empty payload. The Follower sends
# this as soon as the encrypted connection is established (which is right after
# the ephemeral key packet arrives at the follower), then it waits for a
# response. The Leader waits to see this KCM, which indicates that the
# connection is a viable contender, and it goes into the selection pool. Later,
# when the pool resolves and a winner is picked, the Leader sends its own KCM
# on the winning connection and drops the others. When the Follower sees that
# KCM, it selects that connection for use and drops the others too.
