
class SingleUseEndpointError(Exception):
    pass

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


@implementer(IAddress)
class _SubchannelAddress(object):
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
