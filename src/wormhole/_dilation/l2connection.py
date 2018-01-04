
assert len(struct.pack("<L", 0)) == 4
assert len(struct.pack("<Q", 0)) == 8

def le4(value):
    if not 0 <= value < 2**32:
        raise ValueError
    return struct.pack("<L", value)
def from_le4(b):
    if len(b) != 4:
        raise ValueError
    return struct.unpack("<L")[0]

def le8(value):
    if not 0 <= value < 2**64:
        raise ValueError
    return struct.pack("<Q", value)
def from_le8(b):
    if len(b) != 8:
        raise ValueError
    return struct.unpack("<Q")[0]

def noncebuf(nonce):
    if not 0 <= nonce < 2**32:
        raise ValueError
    b = le4(nonce) + (b"\x00"*20)
    assert len(b) == SecretBox.NONCE_SIZE

# L2 protocol:
#  all frames are LENGTH(le4) + SEQNUM(le4) + ENCRYPTED_BODY
#  LENGTH includes seqnum and encrypted_body, but not itself
#  seqnum is also the encryption nonce, separate keys in each direction
#  after decryption, BODY is one of:
#   0x00 "PING"
#   0x01 "ACK" + inbound seqnum(le4)
#   0x02 "OPEN" + subchannel-id(le4)
#   0x03 "DATA" + subchannel-id(le4) + data-payload
#   0x04 "CLOSE" + subchannel-id(le4)
# data-payload does not need a length, since the frame has one
# recipient ACKs all PING/OPEN/DATA/CLOSE it receives
# recipient then ignores PING/OPEN/DATA/CLOSE with a seqnum it has seen before

def _message(seqnum, outbound_box, plaintext):
    assert isinstance(seqnum, int)
    assert 0 <= seqnum < 2**32
    assert isinstance(outbound_box, SecretBox)
    assert isinstance(plaintext, bytes)
    assert len(plaintext) < 2**32 - 100 # TODO: be more exact about overhead

    SEQNUM = le4(self._seqnum)
    nonce = le4(self._seqnum) # but expand to 24 bytes?
    ENCBODY = self._outbound_box.encrypt(self._plaintext, nonce)
    length = len(SEQNUM) + len(ENCBODY)
    LENGTH = le4(length)
    return LENGTH + SEQNUM + ENCBODY

def make_ping(self, seqnum, outbound_box):
    return _message(seqnum, outbound_box, b"\x00")

def make_ack(self, seqnum, outbound_box, inbound_seqnum):
    return _message(seqnum, outbound_box, b"\x01" + le4(inbound_seqnum))

def make_open(self, seqnum, outbound_box, subchannel_id):
    return _message(seqnum, outbound_box, b"\x02" + le4(subchannel_id))

def make_data(self, seqnum, outbound_box, subchannel_id, payload):
    assert isinstance(payload, bytes)
    return _message(seqnum, outbound_box, b"\x03" + le8(subchannel_id) +
                    le8(len(payload)) + payload)

def make_close(self, seqnum, outbound_box, subchannel_id):
    return _message(seqnum, outbound_box, b"\x04" + le8(subchannel_id))

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

    _inbound_box = attrib(validator=instance_of(SecretBox))
    _outbound_box = attrib(validator=instance_of(SecretBox))
    _l3 = attrib(validator=instance_of(L3Connection))

    def __attrs_post_init__(self):
        self._buffer = b""
        self._negotiation_state = 0# ??
        self._subchannel_transports = {}
        self._subchannel_producers = set()
        self._next_subchannel_producers = []

    def dataReceived(self, data):
        self._buffer += data
        while True:
            if len(self._buffer) < 4:
                return
            frame_length = from_le4(self._buffer[0:4])
            if len(self._buffer) < 4+frame_length:
                return
            seqnum_and_frame = self._buffer[4:4+frame_length]
            self._buffer = self._buffer[4+frame_length:] # TODO: avoid copy
            self.seqnumAndFrameReceived(seqnum_and_frame)

    def seqnumAndFrameReceived(self, seqnum_and_frame):
        seqnum = from_le4(seqnum_and_frame[0:4])
        frame = seqnum_and_frame[4:]
        try:
            body = self._inbound_box.decrypt(frame, nonce=noncebuf(seqnum))
            self.bodyReceived(seqnum, body)
        except CryptoError:
            # if this happens during tests, flunk the test
            log.err("bad inbound frame, seqnum=%d" % seqnum)
            # but we ignore it at runtime: just drop the packet

    def bodyReceived(self, seqnum, body):
        if body[0] == b"\x00":
            self._l3.pingReceived()
        elif body[0] == b"\x01":
            inbound_seqnum = from_le4(body[1:])
            self._l3.ackReceived(inbound_seqnum)
        elif body[0] == b"\x02":
            subchannel_id = from_le4(body[1:])
            self._l3.openReceived(seqnum, subchannel_id)
        elif body[0] == b"\x03":
            subchannel_id = from_le4(body[1:1+4])
            payload = body[1+4:]
            self._l3.payloadReceived(seqnum, subchannel_id, payload)
        elif body[0] == b"\x04":
            subchannel_id = from_le4(body[1:1+4])
            self._l3.closeReceived(seqnum, subchannel_id)
        else:
            log.err("unrecognized message type received")

    def pauseProducing(self):
        for t in self.subchannel_producers:
            t.pauseProducing()
    def resumeProducing(self):
        XXX

    def sendMessage(self, msg):
        self.transport.write(bytes(msg))
