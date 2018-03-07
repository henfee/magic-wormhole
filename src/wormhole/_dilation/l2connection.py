from attr import attrs, attrib
from attr.validators import instance_of, provides
from automat import MethodicalMachine
from twisted.python import log
from twisted.python.internet import Protocol
from noise.connection import NoiseConnection
from noise.exceptions import NoiseInvalidMessage
from .._interfaces import IDilationManager
from .encode import to_be4, from_be4
from .roles import LEADER

PROLOGUE_LEADER   = b"Magic-Wormhole Dilation Handshake v1 Leader\n\n"
PROLOGUE_FOLLOWER = b"Magic-Wormhole Dilation Handshake v1 Follower\n\n"
NOISEPROTO = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s"

@attrs
class L2Protocol(Protocol):
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

    _manager = attrib(validator=provides(IDilationManager))
    _dilation_key = attrib(validator=instance_of(bytes))
    _role = attrib()
    _got_prologue = False

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    def __attrs_post_init__(self):
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

    @m.state(initial=True)
    def want_prologue(self): pass # pragma: no cover
    @m.state(initial=True)
    def want_ephemeral(self): pass # pragma: no cover
    @m.state(initial=True)
    def ready(self): pass # pragma: no cover

    @m.input()
    def got_prologue(self):
        pass
    @m.input()
    def got_frame(self, frame):
        pass

    @m.output()
    def process_handshake(self, frame):
        payload = self._noise.read_message()
        del payload # we don't send plaintext in the handshake

    @m.output()
    def process_decrypt(self, frame):
        try:
            # TODO: first mesasge must use read_message, later must .decrypt
            payload = self._noise.read_message(frame)
        except NoiseInvalidMessage:
            # if this happens during tests, flunk the test
            log.err("bad inbound frame")
            self._manager.bad_frame(self)
            return
        if payload is not None:
            self._manager.good_frame(self, payload)

    want_prologue.upon(got_prologue, enter=want_ephemeral, outputs=[])
    want_ephemeral.upon(got_frame, enter=ready, outputs=[process_handshake])
    ready.upon(got_frame, enter=ready, outputs=[process_decrypt])

    def connectionMade(self):
        self.transport.write(self._send_prologue)
        message1 = self._noise.write_message() # generate the ephemeral key
        self.transport.write(message1)

    def dataReceived(self, data):
        self._buffer += data
        if not self._got_prologue:
            lb = len(self._buffer)
            lep = len(self._expected_prologue)
            if self._buffer.startswith(self._expected_prologue):
                self._got_prologue = True
                self._buffer = self._buffer[lep:]
                # prologue good, consume it and process the rest, if any
            elif self._buffer != self._expected_prologue[:lb]:
                # the data we've received so far does not match the prologue,
                # so this can't possibly be right. Don't complain until we see
                # the expected length, or a newline, so we can capture the
                # weird input in the log for debugging.
                if (b"\n" in self._buffer or lb >= lep):
                    log.msg("bad prologue {}".format(self._buffer[:lep]))
                    self.loseConnection()
                    return
                return # wait a bit longer
            else:
                # good so far, just waiting for the rest of the prologue
                return
        while True:
            if len(self._buffer) < 4:
                return
            frame_length = from_be4(self._buffer[0:4])
            if len(self._buffer) < frame_length:
                return
            frame = self._buffer[4:4+frame_length]
            self._buffer = self._buffer[4+frame_length:] # TODO: avoid copy
            self.got_frame(frame)

    def connectionLost(self, why=None):
        self._manager.lost_connection(self)

    # from L3 above
    def encrypt_and_send(self, payload):
        frame = self._noise.send(payload)
        self.transport.write(to_be4(len(frame)) + frame)

    def disconnect(self):
        self.transport.loseConnection()

