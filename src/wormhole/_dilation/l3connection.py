
@attrs
class L3Connection(object):
    """I represent a generation of level-3 connection.

    Each dilated Wormhole has exactly one of these, created at the
    moment of dilation, and destroyed along with the Wormhole. At any
    given time, this L3 connection has either zero or one L2
    connections, which is used to deliver data.
    """

    _wormhole = attrib(validator=instance_of(IWormhole))
    _is_leader = attrib(validator=instance_of(bool))
    _generation = attrib(validator=instance_of(Generation))

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

    # NEW STUFF HERE

    # from l2
    def bad_frame(self, l2):
        if self._selected_l2 is None:
            # well, we certainly aren't selecting this one
            l2.disconnect()
        else:
            # make it go away. if that was our selected L2, this will start a
            # new generation
            l2.disconnect()

    def good_frame(self, l2, payload):
        if self._selected_l2 is None:
            # we're waiting for selection to complete
            # if we're the leader, this could be a KCM frame from a new L2
            if self._role is LEADER:
                if payload != b"":
                    log.err("weird, Follower's KCM wasn't empty")
                self._add_l2_candidate(l2)
            if self._role is FOLLOWER:
                # as follower, we expect to see one KCM frame from the selected
                # L2, and silence from the rest. So use the L2 for the first
                # good frame we get.
                if payload != b"":
                    log.err("weird, Leader's KCM wasn't empty")
                self._accept_l2(l2)
        else:
            self._l3.got_message(payload)

    def lost_connection(self, l2):
        if l2 is self._selected_l2:
            self._l4.l3_disconnected()

    def pauseProducing(self):
        self._l4.pauseProducing()

    def resumeProducing(self):
        self._l4.resumeProducing()

    def _add_l2_candidate(self, l2):
        self._l2_candidates.add(l2)
        # for now, just accept the first one
        self._accept_l2(l2)

    def _accept_l2(self, l2):
        self._selected_l2 = l2
        self._l3_connected()

    def _l3_connected(self):
        self._l4.l3_connected()

    # from L4

    def encrypt_and_send(self, payload):
        self._l2.encrypt_and_send(payload)

@attrs
class ConnectionSelection(object):
    _generation = attrib(validator=instance_of(Generation))

    

@attrs
class Generation(object):
    _l1 = attrib(validator=instance_of(IWormhole))
    _l4 = attrib(validator=instance_of(L4Connection))
    _gen = attrib(validator=instance_of(int))

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    @m.state(initial=True)
    def idle(self): pass # pragma: no cover
    @m.state()
    def waiting(self): pass # pragma: no cover
    @m.state()
    def active(self): pass # pragma: no cover

    @m.input()
    def start(self):
        pass
    @m.input()
    def got_ok(self):
        pass
    @m.input()
    def lost(self):
        pass

    @m.output()
    def send_start(self):
        if self._l3:
            # make sure all previous connections (established and pending) are
            # stopped
            self._l3.shutdown()
        gen = self._next_generation
        self._next_generation += 1
        self._l1.send_dilate("start-dilation", version="1", generation=gen)

    @m.output()
    def start_connecting(self):
        pass

    idle.upon(start, enter=waiting, outputs=[send_start])
    waiting.upon(got_ok, enter=active, outputs=[start_connecting])
    active.upon(lost, enter=waiting, outputs=[send_start])

    def spawn_the_next_generation(self):
        if self._l3:
            self._l3.shutdown()
        g = Generation(self._l1, self._l4, self._gen+1)
