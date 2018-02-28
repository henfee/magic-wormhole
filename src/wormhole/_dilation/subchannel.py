
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
    _l3 = attrib(validator=instance_of(L3Connection))
    _l4 = attrib(validator=instance_of(L4Connection))
    _host_addr = attrib(validator=instance_of(_SubchannelAddress))
    _peer_addr = attrib(validator=instance_of(_SubchannelAddress))

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    def __attrs_post_init__(self):
        #self._mailbox = None
        #self._pending_outbound = {}
        #self._processed = set()
        pass

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
        self._l4.sendData(self._id, data)

    @m.output()
    def send_close(self):
        self._l4.sendClose(self._id)

    @m.output()
    def signal_loseConnection(self):
        self._protocol.loseConnection(what)
        self._l4.subchannel_closed(self)
        # we're deleted momentarily

    @m.output()
    def signal_dataReceived(self, data):
        self._protocol.dataReceived(data)

    @m.output()
    def error_closed(self):
        raise AlreadyClosedError("write/loseConnection not allowed on closed subchannel")

    # primary transitions
    open.upon(remote_data, enter=open, outputs=[signal_dataReceived])
    open.upon(local_data, enter=open, outputs=[send_data])
    open.upon(remote_close, enter=closed, outputs=[signal_loseConnection])
    open.upon(local_close, enter=closing, outputs=[send_close])
    closing.upon(remote_data, enter=closing, outputs=[signal_dataReceived])
    closing.upon(remote_close, enter=closed, outputs=[signal_loseConnection])

    # error cases
    # we won't ever see an OPEN, since L4 will log+ignore those for us
    closing.upon(local_data, enter=closing, outputs=[error_closed])
    closing.upon(local_close, enter=closing, outputs=[error_closed])
    # the CLOSED state won't ever see messages, since we'll be deleted

    # ITransport
    def write(self, data):
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


@implementer(IStreamClientEndpoint)
@attrs
class ControlChannelEndpoint(object):
    _l3d = attrib(validator=instance_of(Deferred))
    def __attrs_post_init__(self):
        self._used = False
    @inlineCallbacks
    def connect(self, f):
        if self._used:
            raise SingleUseEndpointError
        self._used = True
        l3 = yield self._l3d
        t = l3.buildControlChannelTransport()
        f.doStart()
        f.startedConnecting(CONNECTOR) # ??
        p = f.buildProtocol(_SubchannelAddress())
        p.makeConnection(t)
        returnValue(p)

@implementer(IStreamClientEndpoint)
@attrs
class OutboundSubchannelEndpoint(object):
    _l3d = attrib(validator=instance_of(Deferred))

    def __attrs_post_init__(self):
        self._l3 = None

    @inlineCallbacks
    def connect(self, f):
        if self._l3 is None:
            self._l3 = yield self._l3d
        sc = self._l3.openSubchannel()
        # the Subchannel object is an ITransport
        f.doStart()
        f.startedConnecting(CONNECTOR) # ??
        p = f.buildProtocol(_SubchannelAddress())
        p.makeConnection(sc)
        returnValue(p)

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
