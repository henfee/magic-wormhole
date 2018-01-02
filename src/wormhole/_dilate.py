from attr import attrs, attrib
from attr.validators import instance_of
from twisted.internet.interfaces import ITransport, IProducer, IConsumer
from automat import MethodicalMachine
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
from . import _interfaces

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
#   0x00 "ACK" + inbound seqnum(le4)
#   0x01 "OPEN" + subchannel-id(le4)
#   0x02 "DATA" + subchannel-id(le4) + data-payload
#   0x03 "CLOSE" + subchannel-id(le4)
# data-payload does not need a length, since the frame has one
# recipient ACKs all OPEN/DATA/CLOSE it receives
# recipient then ignores OPEN/DATA/CLOSE with a seqnum it has seen before

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

def make_ack(self, seqnum, outbound_box):
    return _message(seqnum, outbound_box, b"\x00")

def make_open(self, seqnum, outbound_box, subchannel_id):
    return _message(seqnum, outbound_box, b"\x01" + le4(subchannel_id))

def make_data(self, seqnum, outbound_box, subchannel_id, payload):
    assert isinstance(payload, bytes)
    return _message(seqnum, outbound_box, b"\x02" + le8(subchannel_id) +
                    le8(len(payload)) + payload)

def make_close(self, seqnum, outbound_box, subchannel_id):
    return _message(seqnum, outbound_box, b"\x03" + le8(subchannel_id))

@attrs
class L2Protocol(Protocol):
    _inbound_box = attrib(validator=instance_of(SecretBox))
    _outbound_box = attrib(validator=instance_of(SecretBox))
    _l3 = attrib(validator=instance_of(L3Connection))

    def __attrs_post_init__(self):
        self._buffer = b""
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
            inbound_seqnum = from_le4(body[1:])
            self._l3.ackReceived(inbound_seqnum)
        elif body[0] == b"\x01":
            subchannel = from_le4(body[1:])
            self._l3.openReceived(seqnum, subchannel)
        elif body[0] == b"\x02":
            subchannel = from_le4(body[1:1+4])
            payload = body[1+4:]
            self._l3.payloadReceived(seqnum, subchannel, payload)
        elif body[0] == b"\x03":
            subchannel = from_le4(body[1:1+4])
            self._l3.closeReceived(seqnum, subchannel)
        else:
            log.err("unrecognized message type received")

    def pauseProducing(self):
        for t in self.subchannel_producers:
            t.pauseProducing()
    def resumeProducing(self):
        XXX

    def sendMessage(self, msg):
        self.transport.write(bytes(msg))

class L3Connection(object):
    """I represent the durable per-Wormhole 'level-3' connection.

    Each dilated Wormhole has exactly one of these, created at the
    moment of dilation, and destroyed along with the Wormhole. At any
    given time, this L3 connection has either zero or one L2
    connections, which is used to deliver data.
    """

    def __init__(self, inbound_key, outbound_key):
        self._inbound_box = SecretBox(inbound_key)
        self._outbound_box = SecretBox(outbound_key)
        self.next_outbound_seqnum = 0
        self.outbound_queue = deque()
        self.next_subchannel_id = 1

    def buildProtocol(self, addr):
        l2 = L2Protocol(self._inbound_box, self._outbound_box)
        l2.factory = self
        return l2

    def seqnum(self):
        s = self.next_outbound_seqnum
        self.next_outbound_seqnum += 1
        return s

    def l2Opened(self, l2):
        self.l2 = l2
        for (seqnum, msg) in self.outbound_queue:
            l2.sendMessage(msg)

    def l2Closed(self):
        self.l2 = None

    def ackReceived(self, inbound_seqnum):
        while self.outbound_queue.first()[0] <= inbound_seqnum: # ??
            self.outbound_queue.pop_first() # ??

    def openReceived(self, seqnum, subchannel):
        pass

    def payloadReceived(self, seqnum, subchannel, payload):
        pass

    def closeReceived(self, seqnum, subchannel):
        pass

    def send(self, seqnum, msg):
        self.outbound_queue.append( (seqnum, msg) )
        if self.l2:
            self.l2.sendMessage(msg)


    # interface for the controlling side
    def openSubchannel(self):
        seqnum = self.seqnum()
        subchannel_id = self.next_subchannel_id
        self.next_subchannel_id += 1
        self.send(seqnum, make_open(seqnum, self._outbound_box, subchannel_id))
        sc = Subchannel(self)
        self._subchannels[subchannel_id] = sc
        return sc

    def closeSubchannel(self, sc):
        seqnum = self.seqnum()
        self.send(seqnum, make_close(seqnum, self._outbound_box, subchannel_id))

    # interface for the L4 connection object
    def sendData(self, subchannel_id, data):
        seqnum = self.seqnum()
        self.send(seqnum, make_data(seqnum, self._outbound_box, subchannel_id,
                                    payload))
    def sendClose(self, subchannel_id):
        seqnum = self.seqnum()
        self.send(seqnum, make_close(seqnum, self._outbound_box, subchannel_id))
        # XXX remove from self._subchannels ?


@attrs
@implementer(_interfaces.ISubChannel)
class SubChannel(object):
    _id = attrib(validator=int)
    _l3 = attrib(validator=instance_of(L3Connection))

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    def __attrs_post_init__(self):
        #self._mailbox = None
        #self._pending_outbound = {}
        #self._processed = set()
        pass

    @m.state(initial=True)
    def idle(self): pass # pragma: no cover

    @m.state()
    def open(self): pass # pragma: no cover

    @m.state()
    def closing(): pass # pragma: no cover

    @m.state()
    def closed(): pass # pragma: no cover


    @m.input()
    def remote_open(self): pass
    @m.input()
    def remote_data(self, data): pass
    @m.input()
    def local_data(self, data): pass
    @m.input()
    def local_close(self): pass
    @m.input()
    def remote_close(self): pass


    @m.output()
    def send_close(self):
        self._l3.sendClose(self._id)

    # things that can happen when idle
    @m.output()
    def error_early_remote_data(self, data):
        raise Error
    @m.output()
    def error_early_local_data(self, data):
        raise Error
    @m.output()
    def error_early_local_close(self):
        raise Error
    @m.output()
    def error_early_remote_close(self):
        raise Error


    # things that can happen while open
    @m.output()
    def error_double_remote_open(self):
        raise Error
    @m.output()
    def accept_data(self, data):
        XXX
    @m.output()
    def send_data(self, data):
        XXX
    @m.output()
    def send_close(self):
        XXX
    @m.output()
    def send_close_and_close_subchannel(self):
        XXX


    # things that can happen while closing
    @m.output()
    def error_double_remote_open(self):
        raise Error
    @m.output()
    def ignore_remote_data(self, data):
        pass
    @m.output()
    def error_late_local_data(self, data):
        raise Error
    @m.output()
    def error_double_local_close(self):
        raise Error
    @m.output()
    def finished_closing(self):
        XXX


    # things that can happen while closed
    @m.output()
    def error_reopened(self):
        raise Error
    @m.output()
    def error_late_remote_data(self, data):
        raise Error
    @m.output()
    def error_late_local_data(self, data):
        raise Error
    @m.output()
    def error_late_local_close(self):
        raise Error
    @m.output()
    def error_late_remote_close(self):
        raise Error

    # primary transitions
    idle.upon(remote_open, enter=open, outputs=[])
    open.upon(remote_data, enter=open, outputs=[accept_data])
    open.upon(local_data, enter=open, outputs=[send_data])
    open.upon(remote_close, enter=closed, outputs=[send_close_and_close_subchannel])
    open.upon(local_close, enter=closing, outputs=[send_close])
    closing.upon(remote_close, enter=closed, outputs=[finished_closing])

    # error cases
    idle.upon(remote_data, enter=idle, outputs=[error_early_remote_data])
    idle.upon(local_data, enter=idle, outputs=[error_early_local_data])
    idle.upon(local_close, enter=idle, outputs=[error_early_local_close])
    idle.upon(remote_close, enter=idle, outputs=[error_early_remote_close])
    open.upon(remote_open, enter=open, outputs=[error_double_remote_open])
    closing.upon(remote_open, enter=closing, outputs=[error_double_remote_open])
    closing.upon(remote_data, enter=closing, outputs=[ignore_remote_data])
    closing.upon(local_data, enter=closing, outputs=[error_late_local_data])
    closing.upon(local_close, enter=closing, outputs=[error_double_local_close])
    closed.upon(remote_open, enter=closed, outputs=[error_reopened])
    closed.upon(remote_data, enter=closed, outputs=[error_late_remote_data])
    closed.upon(local_data, enter=closed, outputs=[error_late_local_data])
    closed.upon(local_close, enter=closed, outputs=[error_late_local_close])
    closed.upon(remote_close, enter=closed, outputs=[error_late_remote_close])



@attrs
@implementer(ITransport)
@implementer(IProducer)
@implementer(IConsumer)
class Subchannel(object):
    _l3 = attrib(validator=instance_of(L3Connection))
    _l4 = attrib(validator=instance_of(SubChannel))

    def __attrs_post_init__(self):
        pass

    def write(self, data):
        self._l4.local_data(data)
    def writeSequence(self, iovec):
        self.write(b"".join(iovec))
    def loseConnection(self):
        self._l4.local_close()
    def getPeer(self):
        return None # XXX
    def getHost(self):
        return None # XXX

    # IProducer
    def stopProducing(self):
        pass
    def pauseProducing(self):
        pass
    def resumeProducing(self):
        pass

    # IConsumer
    def registerProducer(self, producer, streaming):
        # streaming==True: IPushProducer (pause/resume)
        # streaming==False: IPullProducer (just resume)
        pass
    def unregisterProducer(self):
        pass


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
