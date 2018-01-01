from attr import attrs, attrib
from attr.validators import instance_of
from automat import MethodicalMachine
from . import _interfaces

assert len(struct.pack("<L", 0)) == 4
assert len(struct.pack("<Q", 0)) == 8

def le4(value):
    return struct.pack("<L", value)
def from_le4(b):
    assert len(b) == 4
    return struct.unpack("<L")[0]

def le8(value):
    return struct.pack("<Q", value)
def from_le8(b):
    assert len(b) == 8
    return struct.unpack("<Q")[0]

# L2 protocol:
#  all frames are LENGTH(le4) + SEQNUM(le4) + ENCRYPTED_BODY
#  LENGTH includes seqnum and encrypted_body, but not itself
#  seqnum is also the encryption nonce, separate keys in each direction
#  after decryption, BODY is one of:
#   0x00 "ACK" + inbound seqnum(le4)
#   0x01 "OPEN" + subchannel-id(le4)
#   0x02 "DATA" + subchannel-id(le4) + data-payload
#   0x03 "CLOSE" + subchannel-id(le4)
# data-payload does not need a length, since the frame has one
# recipient ACKs all OPEN/DATA/CLOSE it receives
# recipient then ignores OPEN/DATA/CLOSE with a seqnum it has seen before

@attrs
class Message(object):
    _seqnum = attrib(validator=int)
    _outbound_box = attrib(validator=instance_of(SecretBox))
    _plaintext = attrib(validator=bytes)

    def __bytes__(self):
        SEQNUM = le4(self._seqnum)
        nonce = le4(self._seqnum) # but expand to 24 bytes?
        ENCBODY = self._outbound_box.encrypt(nonce, self._plaintext)
        length = len(SEQNUM) + len(ENCBODY)
        LENGTH = le4(length)
        return LENGTH + SEQNUM + ENCBODY

def make_ack(self, seqnum, outbound_box):
    return Message(seqnum, outbound_box, b"\x00")

def make_open(self, seqnum, outbound_box, subchannel_id):
    return Message(seqnum, outbound_box, b"\x01" + le4(subchannel_id))

def make_data(self, seqnum, outbound_box, subchannel_id, payload):
    assert isinstance(payload, bytes)
    return Message(seqnum, outbound_box, b"\x02" + le8(subchannel_id) +
                   le8(len(payload)) + payload)

def make_close(self, seqnum, outbound_box, subchannel_id):
    return Message(seqnum, outbound_box, b"\x03" + le8(subchannel_id))

@attrs
class L2Protocol(Protocol):
    _outbound_key = attrib(validator=bytes)
    _inbound_key = attrib(validator=bytes)

    def __attrs_post_init__(self):
        self._buffer = b""
        self._subchannel_transports = {}
        self._subchannel_producers = set()
        self._next_subchannel_producers = []
        self._inbound_box = SecretBox(self._inbound_key)
        self._outbound_box = SecretBox(self._outbound_key)

    def dataReceived(self, data):
        self.buffer += data
        while True:
            if len(self.buffer) < 4:
                return
            frame_length = from_le4(self.buffer[0:4])
            if len(self.buffer) < 4+frame_length:
                return
            seqnum_and_frame = self.buffer[4:4+frame_length]
            self.buffer = self.buffer[4+frame_length:] # TODO: avoid copy
            self.seqnumAndFrameReceived(seqnum_and_frame)

    def seqnumAndFrameReceived(self, seqnum_and_frame):
        seqnum = from_le4(seqnum_and_frame[0:4])
        frame = seqnum_and_frame[4:]
        body = self._inbound_box.decrypt(nonce=seqnum, frame)
        self.bodyReceived(seqnum, body)

    def bodyReceived(self, seqnum, body):
        if body[0] == b"\x00":
            inbound_seqnum = from_le4(body[1:])
            self.ackReceived(inbound_seqnum)
        elif body[0] == b"\x01":
            subchannel = from_le4(body[1:])
            self.openReceived(seqnum, subchannel)
        elif body[0] == b"\x02":
            subchannel = from_le4(body[1:1+4])
            payload = body[1+4:]
            self.payloadReceived(seqnum, subchannel, payload)
        elif body[0] == b"\x03":
            subchannel = from_le4(body[1:1+4])
            self.closeReceived(seqnum, subchannel)
        else:
            pass

    def pauseProducing(self):
        for t in self.subchannel_producers:
            t.pauseProducing()
    def resumeProducing(self):
        XXX

    def sendMessage(self, msg):
        self.transport.write(bytes(msg))

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
