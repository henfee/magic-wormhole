from ..util import dict_to_bytes, bytes_to_dict

LEADER, FOLLOWER = object(), object()

@attrs
class Dilation(object):
    _wormhole = attrib(validator=instance_of(IWormhole))
    _eventual_queue = attrib()

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    def __attrs_post_init__(self):
        self._l4 = L4(self._eventual_queue)
        self._got_versions_d = Deferred()


    # We're "idle" until all three of:
    # 1: we receive the initial VERSION message and learn our peer's "side"
    #    value (then we compare sides, and the higher one is "leader", and
    #    the lower one is "follower")
    # 2: the peer is capable of dilation
    # 3: the local app calls w.dilate()

    @m.state(initial=True)
    def idle(self): pass # pragma: no cover

    @m.state()
    def leader_connecting(self): pass # pragma: no cover
    @m.state()
    def leader_connected(self): pass # pragma: no cover

    @m.state()
    def follower_connecting(self): pass # pragma: no cover
    @m.state()
    def follower_connected(self): pass # pragma: no cover

    @m.input()
    def start_leader(self): pass # pragma: no cover
    @m.input()
    def start_follower(self): pass # pragma: no cover
    @m.input()
    def rx_DILATE(self): pass # pragma: no cover
    @m.input()
    def rx_HINTS(self): pass # pragma: no cover

    # Both leader and follower are given l2_connected. The leader sees this
    # when the first connection passes negotiation.
    @m.input()
    def l2_connected(self): pass # pragma: no cover
    # leader reacts to l2_lost
    @m.input()
    def l2_lost(self): pass # pragma: no cover
    # follower doesn't react to l2_lost, but waits for a new LETS_DILATE

    def send_dilation_phase(self, **fields):
        dilation_phase = self._next_dilation_phase
        self._next_dilation_phase += 1
        self._S.send("dilate-%d" % dilation_phase, dict_to_bytes(message))

    @m.output()
    def send_dilate(self):
        generation = self._next_generation
        self._next_generation += 1
        self.send_dilation_phase(type="dilate", generation=generation)
        return generation

    @m.output()
    def start_connecting(self, generation):
        self._connector = Connector(generation)

    def send_hints(self, hints): # from Connector
        self.send_dilation_phase(type="hints", hints=hints)

    @m.output()
    def use_hints(self, hints):
        self._connector.use_hints(hints)

    idle.upon(start_leader, enter=leader_connecting,
              outputs=[send_dilate, start_connecting])
    idle.upon(start_follower, enter=follower_connecting,
              outputs=[start_connecting])

    leader_connecting.upon(rx_HINTS, enter=leader_connecting,
                           outputs=[use_hints])
    leader_connecting.upon(l2_connected, enter=leader_connected, outputs=[?])
    # leader shouldn't be getting rx_DILATE, and l2_lost only happens while
    # connected

    leader_connected.upon(rx_HINTS, enter=leader_connected,
                          outputs=[]) # too late, ignore them
    leader_connected.upon(l2_lost, enter=leader_connecting,
                          outputs=[leader_start_connection])
    # shouldn't happen: rx_DILATE, l2_connected

    follower_connecting.upon(rx_HINTS, enter=follower_connecting,
                             outputs=[use_hints])
    follower_connecting.upon(l2_connected, enter=follower_connected, outputs=[?])
    follower_connecting.upon(l2_lost, enter=follower_connecting, outputs=[?])
    follower_connecting.upon(rx_DILATE, enter=follower_connecting, outputs=[?])

    follower_connected.upon(l2_lost, enter=follower_connected, outputs=[?])
    follower_connected.upon(rx_DILATE, enter=follower_connecting, outputs=[?])
    follower_connected.upon(rx_HINTS, enter=follower_connected,
                            outputs=[]) # too late, ignore them
    # shouldn't happen: l2_connected

    # from wormhole

    @inlineCallbacks
    def dilate(self, eventual_queue):
        # called when w.dilate() is invoked

        # first, we wait until we hear the VERSION message, which tells us 1:
        # the PAKE key works, so we can talk, 2: their side, so we know who
        # will lead, and 3: that they can do dilation at all

        (role, dilation_version) = yield self._got_versions_d

        if not dilation_version: # 1 or None
            raise OldPeerCannotDilateError()

        if role is LEADER:
            self.start_leader()
        else:
            self.start_follower()

        ...

        #self._l3 = L3Connection(self._wormhole, self._my_role is LEADER)
        if self._my_role is LEADER:
            gm = GenerationManager(self._wormhole, self._l4)
            gm.start()
        ...
        yield self._l4.when_first_connected()
        peer_addr = _SubchannelAddress()
        control_ep = ControlEndpoint(peer_addr, ??) # needs gluing
        connect_ep = SubchannelConnectorEndpoint(self._l4)
        listen_ep = SubchannelListenerEndpoint(self._l4)
        endpoints = (control_ep, connect_ep, listen_ep)
        returnValue(endpoints)

    # from Boss
    def got_wormhole_versions(self, our_side, their_side,
                              their_wormhole_versions):
        # this always happens before received_dilate
        my_role = LEADER if our_side > their_side else FOLLOWER
        dilation_version = None
        their_dilation_versions = their_wormhole_versions.get("can-dilate", [])
        if 1 in their_dilation_versions:
            dilation_version = 1
        self._got_versions_d.callback( (my_role, dilation_version) )

    def received_dilate(self, plaintext):
        # this receives new in-order DILATE-n payloads, decrypted but not
        # de-JSONed.
        message = bytes_to_dict(plaintext)
        type = message["type"]
        if type == "dilate":
            self.rx_DILATE(message)
        elif type == "connection-hints":
            self.rx_HINTS(message)
        else:
            log.err("received unknown dilation message type: {}".format(message))
            return

    def handle_start_dilation(self, message):
        if not self._generation:
            self._generation = Generation(self._wormhole, self._l4, 0)
        else:
            self._generation = self._generation.spawn_the_next_generation()

    def handle_ok_dilation(self, message):
        self._generation.ok(message)

    def handle_connection_hints(self, message):
        self._generation.handle_connection_hints(message["hints"])

    # from 
