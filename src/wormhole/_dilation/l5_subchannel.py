from attr import attrs, attrib
from attr.validators import instance_of
from zope.interface import implementer
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue
from twisted.internet.interfaces import (ITransport, IProducer, IConsumer,
                                         IAddress, IListeningPort,
                                         IStreamClientEndpoint,
                                         IStreamServerEndpoint)
from automat import MethodicalMachine
from .. import _interfaces
from .l4connection import L4



class SingleUseEndpointError(Exception):
    pass

# created in the (OPEN) state, by either:
#  * receipt of an OPEN message
#  * or local client_endpoint.connect()
# then transitions are:
# (OPEN) rx DATA: deliver .dataReceived(), -> (OPEN)
# (OPEN) rx CLOSE: deliver .connectionLost(), send CLOSE, -> (CLOSED)
# (OPEN) local .write(): send DATA, -> (OPEN)
# (OPEN) local .loseConnection(): send CLOSE, -> (CLOSING)
# (CLOSING) local .write(): error
# (CLOSING) local .loseConnection(): error
# (CLOSING) rx DATA: deliver .dataReceived(), -> (CLOSING)
# (CLOSING) rx CLOSE: deliver .connectionLost(), -> (CLOSED)
# object is deleted upon transition to (CLOSED)

class AlreadyClosedError(Exception):
    pass

@implementer(IAddress)
class _SubchannelAddress(object):
    pass


@attrs
@implementer(ITransport)
@implementer(IProducer)
@implementer(IConsumer)
@implementer(_interfaces.ISubChannel)
class SubChannel(object):
    _id = attrib(validator=int)
    _l4 = attrib(validator=instance_of(L4Connection))
    _host_addr = attrib(validator=instance_of(_SubchannelAddress))
    _peer_addr = attrib(validator=instance_of(_SubchannelAddress))

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    def __attrs_post_init__(self):
        #self._mailbox = None
        #self._pending_outbound = {}
        #self._processed = set()
        self._protocol = None
        self._pending_dataReceived = []
        self._pending_connectionLost = (False, None)

    @m.state(initial=True)
    def open(self): pass # pragma: no cover

    @m.state()
    def closing(): pass # pragma: no cover

    @m.state()
    def closed(): pass # pragma: no cover

    @m.input()
    def remote_data(self, data): pass
    @m.input()
    def remote_close(self): pass

    @m.input()
    def local_data(self, data): pass
    @m.input()
    def local_close(self): pass


    @m.output()
    def send_data(self, data):
        self._l4.send_data(self._id, data)

    @m.output()
    def send_close(self):
        self._l4.send_close(self._id)

    @m.output()
    def signal_dataReceived(self, data):
        if self._protocol:
            self._protocol.dataReceived(data)
        else:
            self._pending_dataReceived.append(data)

    @m.output()
    def signal_connectionLost(self):
        if self._protocol:
            self._protocol.connectionLost(what)
        else:
            self._pending_connectionLost = (True, what)
        self._l4.subchannel_closed(self._id, self)
        # we're deleted momentarily

    @m.output()
    def error_closed(self):
        raise AlreadyClosedError("write/loseConnection not allowed on closed subchannel")

    # primary transitions
    open.upon(remote_data, enter=open, outputs=[signal_dataReceived])
    open.upon(local_data, enter=open, outputs=[send_data])
    open.upon(remote_close, enter=closed, outputs=[signal_connectionLost])
    open.upon(local_close, enter=closing, outputs=[send_close])
    closing.upon(remote_data, enter=closing, outputs=[signal_dataReceived])
    closing.upon(remote_close, enter=closed, outputs=[signal_connectionLost])

    # error cases
    # we won't ever see an OPEN, since L4 will log+ignore those for us
    closing.upon(local_data, enter=closing, outputs=[error_closed])
    closing.upon(local_close, enter=closing, outputs=[error_closed])
    # the CLOSED state won't ever see messages, since we'll be deleted

    # our endpoints use this

    def _set_protocol(self, protocol):
        assert not self._protocol
        self._protocol = protocol
        if self._pending_dataReceived:
            for d in self._pending_dataReceived:
                self._protocol.dataReceived(data)
            self._pending_dataReceived =  []
        cl, what = self._pending_connectionLost[0]
        if cl:
            self._protocol.connectionLost(what)

    # ITransport
    def write(self, data):
        assert isinstance(data, type(b""))
        self.local_data(data)
    def writeSequence(self, iovec):
        self.write(b"".join(iovec))
    def loseConnection(self):
        self.local_close()
    def getHost(self):
        return self._host_addr
    def getPeer(self):
        return self._peer_addr

    # IProducer
    def stopProducing(self):
        self._l4.subchannel_stopProducing(self)
    def pauseProducing(self):
        self._l4.subchannel_pauseProducing(self)
    def resumeProducing(self):
        self._l4.subchannel_resumeProducing(self)

    # IConsumer
    def registerProducer(self, producer, streaming):
        # streaming==True: IPushProducer (pause/resume)
        # streaming==False: IPullProducer (just resume)
        pass
    def unregisterProducer(self):
        pass


@implementer(IStreamClientEndpoint)
class ControlEndpoint(object):
    _used = False
    def __init__(self, peer_addr):
        self._subchannel_zero = Deferred()
        self._peer_addr = peer_addr

    def subchannel_zero_opened(self, subchannel):
        self._cp.callback(control_protocol)

    @inlineCallbacks
    def connect(self, protocolFactory):
        # return Deferred that fires with IProtocol or Failure(ConnectError)
        if self._used:
            raise SingleUseEndpointError
        self._used = True
        t = yield self._subchannel_zero
        p = protocolFactory.buildProtocol(self._peer_addr)
        t._set_protocol(p)
        p.makeConnection(t) # set p.transport = t and call connectionMade()
        returnValue(p)

@implementer(IStreamClientEndpoint)
@attrs
class SubchannelConnectorEndpoint(object):
    _l4 = attrib(validator=instance_of(L4))

    @inlineCallbacks
    def connect(self, protocolFactory):
        # return Deferred that fires with IProtocol or Failure(ConnectError)
        scid = self._l4.allocate_subchannel_id()
        self._l4.send_open(scid)
        host_addr = _SubchannelAddress(scid)
        peer_addr = _SubchannelAddress(scid)
        # ? f.doStart()
        # ? f.startedConnecting(CONNECTOR) # ??
        t = SubChannel(scid, self._l4, host_addr, peer_addr)
        p = protocolFactory.buildProtocol(peer_addr)
        t._set_protocol(p)
        p.makeConnection(t) # set p.transport = t and call connectionMade()
        returnValue(p)

@implementer(IStreamServerEndpoint)
@attrs
class SubchannelListenerEndpoint(object):
    _l4 = attrib(validator=instance_of(L4))

    def __attrs_post_init__(self):
        self._factory = None
        self._pending_opens = []

    # our L4 points here
    def _got_open(self, t):
        if self._factory:
            self._connect(t)
        else:
            self._pending_opens.append(t)

    def _connect(self, t):
        p = self._factory.buildProtocol(peer_addr)
        t._set_protocol(p)
        p.makeConnection(t)

    # IStreamServerEndpoint

    @inlineCallbacks
    def listen(self, protocolFactory):
        self._factory = protocolFactory
        for t in self._pending_opens:
            self._connect(t)
        self._pending_opens = []


@inlineCallbacks
def start_dilation(w, reactor):
    res = yield w._get_wormhole_versions_and_sides()
    (our_side, their_side, their_wormhole_versions) = res
    my_role = LEADER if our_side > their_side else FOLLOWER
    # the control connection is defined to be an IStreamClientEndpoint on
    # both sides. In the fake dilation, we do this by connecting from
    # FOLLOWER to LEADER and then building a special endpoint around both
    # sides.
    peer_addr = _SubchannelAddress()
    control_ep = ControlEndpoint(peer_addr)
    connect_ep = SubchannelConnectorEndpoint()
    listen_ep = SubchannelListenerEndpoint()
    endpoints = (control_ep, connect_ep, listen_ep)
    returnValue(endpoints)








@implementer(IListeningPort)
class _SubchannelListener(object):
    def startListening(self):
        pass
    def stopListening(self):
        pass
    def getHost(self):
        return _SubchannelAddress()


@implementer(IStreamServerEndpoint)
@attrs
class InboundSubchannelEndpoint(object):
    _l3d = attrib(validator=instance_of(Deferred))
    def __attrs_post_init__(self):
        self._used = False
    @inlineCallbacks
    def listen(self, f):
        if self._used:
            raise SingleUseEndpointError
        self._used = True
        l3 = yield self._l3d
        l3.registerInboundSubchannelFactory(f)
        returnValue(_SubchannelListener())
