
@attrs
class L3Connection(object):
    """I represent the durable per-Wormhole 'level-3' connection.

    Each dilated Wormhole has exactly one of these, created at the
    moment of dilation, and destroyed along with the Wormhole. At any
    given time, this L3 connection has either zero or one L2
    connections, which is used to deliver data.
    """

    _wormhole = attrib(validator=instance_of(IWormhole))
    _is_leader = attrib(validator=instance_of(bool))
    _inbound_box = attrib(validator=instance_of(SecretBox))
    _outbound_box = attrib(validator=instance_of(SecretBox))

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    def __attrs_post_init__(self):
        self.next_outbound_seqnum = 0
        self.outbound_queue = deque()
        self.next_subchannel_id = 1

    @m.state(initial=True)
    def unconnected(self): pass # pragma: no cover

    @m.state()
    def connecting(self): pass # pragma: no cover

    @m.state()
    def connected(self): pass # pragma: no cover

    @m.state()
    def reconnecting(self): pass # pragma: no cover

    @m.input()
    def l2_connected(self, l2):
        pass
    @m.input()
    def l2_lost(self):
        pass
    @m.input()
    def leader_says_reconnect(self):
        pass

    @m.output()
    def start_l2(self, l2):
        self.l2 = l2
        for (seqnum, msg) in self.outbound_queue:
            l2.sendMessage(msg)


    @m.output()
    def start_connecting(self, l2):
        if 
        pass

    @m.output()
    def dilated(self, l2):
        self._wormhole.dilated(self)

    @m.output()
    def stop_l2(self):
        self.l2 = None

    connecting.upon(l2_connected, enter=connected, outputs=[start_l2, dilated])
    connected.upon(l2_lost, enter=reconnecting, outputs=[stop_l2,
                                                         start_connecting])
    reconnecting.upon(l2_connected, enter=connected, outputs=[start_l2])

    # I also act as the Factory for L2Protocols, and as the higher-level
    # Protocol to which L2Protocol will deliver decrypted messages.
    def buildProtocol(self, addr):
        l2 = L2Protocol(self._inbound_box, self._outbound_box)
        l2.factory = self
        return l2

    def seqnum(self):
        s = self.next_outbound_seqnum
        self.next_outbound_seqnum += 1
        return s

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
