
# These namedtuples are "hint objects". The JSON-serializable dictionaries
# are "hint dicts".

# DirectTCPV1Hint and TorTCPV1Hint mean the following protocol:
# * make a TCP connection (possibly via Tor)
# * send the sender/receiver handshake bytes first
# * expect to see the receiver/sender handshake bytes from the other side
# * the sender writes "go\n", the receiver waits for "go\n"
# * the rest of the connection contains transit data
DirectTCPV1Hint = namedtuple("DirectTCPV1Hint", ["hostname", "port", "priority"])
TorTCPV1Hint = namedtuple("TorTCPV1Hint", ["hostname", "port", "priority"])
# RelayV1Hint contains a tuple of DirectTCPV1Hint and TorTCPV1Hint hints (we
# use a tuple rather than a list so they'll be hashable into a set). For each
# one, make the TCP connection, send the relay handshake, then complete the
# rest of the V1 protocol. Only one hint per relay is useful.
RelayV1Hint = namedtuple("RelayV1Hint", ["hints"])

def describe_hint_obj(hint):
    if isinstance(hint, DirectTCPV1Hint):
        return u"tcp:%s:%d" % (hint.hostname, hint.port)
    elif isinstance(hint, TorTCPV1Hint):
        return u"tor:%s:%d" % (hint.hostname, hint.port)
    else:
        return str(hint)

def parse_hint_argv(hint, stderr=sys.stderr):
    assert isinstance(hint, type(u""))
    # return tuple or None for an unparseable hint
    priority = 0.0
    mo = re.search(r'^([a-zA-Z0-9]+):(.*)$', hint)
    if not mo:
        print("unparseable hint '%s'" % (hint,), file=stderr)
        return None
    hint_type = mo.group(1)
    if hint_type != "tcp":
        print("unknown hint type '%s' in '%s'" % (hint_type, hint), file=stderr)
        return None
    hint_value = mo.group(2)
    pieces = hint_value.split(":")
    if len(pieces) < 2:
        print("unparseable TCP hint (need more colons) '%s'" % (hint,),
              file=stderr)
        return None
    mo = re.search(r'^(\d+)$', pieces[1])
    if not mo:
        print("non-numeric port in TCP hint '%s'" % (hint,), file=stderr)
        return None
    hint_host = pieces[0]
    hint_port = int(pieces[1])
    for more in pieces[2:]:
        if more.startswith("priority="):
            more_pieces = more.split("=")
            try:
                priority = float(more_pieces[1])
            except ValueError:
                print("non-float priority= in TCP hint '%s'" % (hint,),
                      file=stderr)
                return None
    return DirectTCPV1Hint(hint_host, hint_port, priority)

class _ThereCanBeOnlyOne:
    """Accept a list of contender Deferreds, and return a summary Deferred.
    When the first contender fires successfully, cancel the rest and fire the
    summary with the winning contender's result. If all error, errback the
    summary.

    status_cb=?
    """
    def __init__(self, contenders):
        self._remaining = set(contenders)
        self._winner_d = defer.Deferred(self._cancel)
        self._first_success = None
        self._first_failure = None
        self._have_winner = False
        self._fired = False

    def _cancel(self, _):
        for d in list(self._remaining):
            d.cancel()
        # since that will errback everything in _remaining, we'll have hit
        # _maybe_done() and fired self._winner_d by this point

    def run(self):
        for d in list(self._remaining):
            d.addBoth(self._remove, d)
            d.addCallbacks(self._succeeded, self._failed)
            d.addCallback(self._maybe_done)
        return self._winner_d

    def _remove(self, res, d):
        self._remaining.remove(d)
        return res

    def _succeeded(self, res):
        self._have_winner = True
        self._first_success = res
        for d in list(self._remaining):
            d.cancel()

    def _failed(self, f):
        if self._first_failure is None:
            self._first_failure = f

    def _maybe_done(self, _):
        if self._remaining:
            return
        if self._fired:
            return
        self._fired = True
        if self._have_winner:
            self._winner_d.callback(self._first_success)
        else:
            self._winner_d.errback(self._first_failure)

def there_can_be_only_one(contenders):
    return _ThereCanBeOnlyOne(contenders).run()


@attrs
class Connector:
    _generation = attrib(validator=instance_of(int))
    _transit_key = attrib(validator=instance_of(type(b""))) # SecretBox.KEY_SIZE
    _relay_url = attrib(validator=instance_of(str))
    _manager = attrib(validator=instance_of(Manager))

    RELAY_DELAY = 2.0

    def start(self):
        pass
    def use_hints(self, hints):
        pass

    # self._manager.send_hints(hints)

    def __init__(self, transit_relay, no_listen=False, tor=None,
                 reactor=reactor, timing=None):
        self._side = bytes_to_hexstr(os.urandom(8)) # unicode
        if transit_relay:
            if not isinstance(transit_relay, type(u"")):
                raise InternalError
            # TODO: allow multiple hints for a single relay
            relay_hint = parse_hint_argv(transit_relay)
            relay = RelayV1Hint(hints=(relay_hint,))
            self._transit_relays = [relay]
        else:
            self._transit_relays = []
        self._their_direct_hints = [] # hintobjs
        self._our_relay_hints = set(self._transit_relays)
        self._tor = tor
        self._transit_key = None
        self._no_listen = no_listen
        self._waiting_for_transit_key = []
        self._listener = None
        self._winner = None
        self._reactor = reactor
        self._timing = timing or DebugTiming()
        self._timing.add("transit")

    def _build_listener(self):
        if self._no_listen or self._tor:
            return ([], None)
        portnum = allocate_tcp_port()
        addresses = ipaddrs.find_addresses()
        non_loopback_addresses = [a for a in addresses if a != "127.0.0.1"]
        if non_loopback_addresses:
            # some test hosts, including the appveyor VMs, *only* have
            # 127.0.0.1, and the tests will hang badly if we remove it.
            addresses = non_loopback_addresses
        direct_hints = [DirectTCPV1Hint(six.u(addr), portnum, 0.0)
                        for addr in addresses]
        ep = endpoints.serverFromString(reactor, "tcp:%d" % portnum)
        return direct_hints, ep

    def get_connection_abilities(self):
        return [{u"type": u"direct-tcp-v1"},
                {u"type": u"relay-v1"},
                ]

    @inlineCallbacks
    def get_connection_hints(self):
        hints = []
        direct_hints = yield self._get_direct_hints()
        for dh in direct_hints:
            hints.append({u"type": u"direct-tcp-v1",
                          u"priority": dh.priority,
                          u"hostname": dh.hostname,
                          u"port": dh.port, # integer
                          })
        for relay in self._transit_relays:
            rhint = {u"type": u"relay-v1", u"hints": []}
            for rh in relay.hints:
                rhint[u"hints"].append({u"type": u"direct-tcp-v1",
                                        u"priority": rh.priority,
                                        u"hostname": rh.hostname,
                                        u"port": rh.port})
            hints.append(rhint)
        returnValue(hints)

    def _get_direct_hints(self):
        if self._listener:
            return defer.succeed(self._my_direct_hints)
        # there is a slight race here: if someone calls get_direct_hints() a
        # second time, before the listener has actually started listening,
        # then they'll get a Deferred that fires (with the hints) before the
        # listener starts listening. But most applications won't call this
        # multiple times, and the race is between 1: the parent Wormhole
        # protocol getting the connection hints to the other end, and 2: the
        # listener being ready for connections, and I'm confident that the
        # listener will win.
        self._my_direct_hints, self._listener = self._build_listener()

        if self._listener is None: # don't listen
            self._listener_d = None
            return defer.succeed(self._my_direct_hints) # empty

        # Start the server, so it will be running by the time anyone tries to
        # connect to the direct hints we return.
        f = InboundConnectionFactory(self)
        self._listener_f = f # for tests # XX move to __init__ ?
        self._listener_d = f.whenDone()
        d = self._listener.listen(f)
        def _listening(lp):
            # lp is an IListeningPort
            #self._listener_port = lp # for tests
            def _stop_listening(res):
                lp.stopListening()
                return res
            self._listener_d.addBoth(_stop_listening)
            return self._my_direct_hints
        d.addCallback(_listening)
        return d

    def _stop_listening(self):
        # this is for unit tests. The usual control flow (via connect())
        # wires the listener's Deferred into a there_can_be_only_one(), which
        # eats the errback. If we don't ever call connect(), we must catch it
        # ourselves.
        self._listener_d.addErrback(lambda f: None)
        self._listener_d.cancel()

    def _parse_tcp_v1_hint(self, hint): # hint_struct -> hint_obj
        hint_type = hint.get(u"type", u"")
        if hint_type not in [u"direct-tcp-v1", u"tor-tcp-v1"]:
            log.msg("unknown hint type: %r" % (hint,))
            return None
        if not(u"hostname" in hint
               and isinstance(hint[u"hostname"], type(u""))):
            log.msg("invalid hostname in hint: %r" % (hint,))
            return None
        if not(u"port" in hint
               and isinstance(hint[u"port"], six.integer_types)):
            log.msg("invalid port in hint: %r" % (hint,))
            return None
        priority = hint.get(u"priority", 0.0)
        if hint_type == u"direct-tcp-v1":
            return DirectTCPV1Hint(hint[u"hostname"], hint[u"port"], priority)
        else:
            return TorTCPV1Hint(hint[u"hostname"], hint[u"port"], priority)

    def add_connection_hints(self, hints):
        for h in hints: # hint structs
            hint_type = h.get(u"type", u"")
            if hint_type in [u"direct-tcp-v1", u"tor-tcp-v1"]:
                dh = self._parse_tcp_v1_hint(h)
                if dh:
                    self._their_direct_hints.append(dh) # hint_obj
            elif hint_type == u"relay-v1":
                # TODO: each relay-v1 clause describes a different relay,
                # with a set of equally-valid ways to connect to it. Treat
                # them as separate relays, instead of merging them all
                # together like this.
                relay_hints = []
                for rhs in h.get(u"hints", []):
                    h = self._parse_tcp_v1_hint(rhs)
                    if h:
                        relay_hints.append(h)
                if relay_hints:
                    rh = RelayV1Hint(hints=tuple(sorted(relay_hints)))
                    self._our_relay_hints.add(rh)
            else:
                log.msg("unknown hint type: %r" % (h,))

    def _send_this(self):
        assert self._transit_key
        if self.is_sender:
            return build_sender_handshake(self._transit_key)
        else:
            return build_receiver_handshake(self._transit_key)

    def _expect_this(self):
        assert self._transit_key
        if self.is_sender:
            return build_receiver_handshake(self._transit_key)
        else:
            return build_sender_handshake(self._transit_key)# + b"go\n"

    def _sender_record_key(self):
        assert self._transit_key
        if self.is_sender:
            return HKDF(self._transit_key, SecretBox.KEY_SIZE,
                        CTXinfo=b"transit_record_sender_key")
        else:
            return HKDF(self._transit_key, SecretBox.KEY_SIZE,
                        CTXinfo=b"transit_record_receiver_key")

    def _receiver_record_key(self):
        assert self._transit_key
        if self.is_sender:
            return HKDF(self._transit_key, SecretBox.KEY_SIZE,
                        CTXinfo=b"transit_record_receiver_key")
        else:
            return HKDF(self._transit_key, SecretBox.KEY_SIZE,
                        CTXinfo=b"transit_record_sender_key")

    def set_transit_key(self, key):
        assert isinstance(key, type(b"")), type(key)
        # We use pubsub to protect against the race where the sender knows
        # the hints and the key, and connects to the receiver's transit
        # socket before the receiver gets the relay message (and thus the
        # key).
        self._transit_key = key
        waiters = self._waiting_for_transit_key
        del self._waiting_for_transit_key
        for d in waiters:
            # We don't need eventual-send here. It's safer in general, but
            # set_transit_key() is only called once, and _get_transit_key()
            # won't touch the subscribers list once the key is set.
            d.callback(key)

    def _get_transit_key(self):
        if self._transit_key:
            return defer.succeed(self._transit_key)
        d = defer.Deferred()
        self._waiting_for_transit_key.append(d)
        return d

    @inlineCallbacks
    def connect(self):
        with self._timing.add("transit connect"):
            yield self._get_transit_key()
            # we want to have the transit key before starting any outbound
            # connections, so those connections will know what to say when
            # they connect
            winner = yield self._connect()
        returnValue(winner)

    def _connect(self):
        # It might be nice to wire this so that a failure in the direct hints
        # causes the relay hints to be used right away (fast failover). But
        # none of our current use cases would take advantage of that: if we
        # have any viable direct hints, then they're either going to succeed
        # quickly or hang for a long time.
        contenders = []
        if self._listener_d:
            contenders.append(self._listener_d)
        relay_delay = 0

        for hint_obj in self._their_direct_hints:
            # Check the hint type to see if we can support it (e.g. skip
            # onion hints on a non-Tor client). Do not increase relay_delay
            # unless we have at least one viable hint.
            ep = self._endpoint_from_hint_obj(hint_obj)
            if not ep:
                continue
            description = "->%s" % describe_hint_obj(hint_obj)
            if self._tor:
                description = "tor" + description
            d = self._start_connector(ep, description)
            contenders.append(d)
            relay_delay = self.RELAY_DELAY

        # Start trying the relays a few seconds after we start to try the
        # direct hints. The idea is to prefer direct connections, but not be
        # afraid of using a relay when we have direct hints that don't
        # resolve quickly. Many direct hints will be to unused local-network
        # IP addresses, which won't answer, and would take the full TCP
        # timeout (30s or more) to fail.

        prioritized_relays = {}
        for rh in self._our_relay_hints:
            for hint_obj in rh.hints:
                priority = hint_obj.priority
                if priority not in prioritized_relays:
                    prioritized_relays[priority] = set()
                prioritized_relays[priority].add(hint_obj)

        for priority in sorted(prioritized_relays, reverse=True):
            for hint_obj in prioritized_relays[priority]:
                ep = self._endpoint_from_hint_obj(hint_obj)
                if not ep:
                    continue
                description = "->relay:%s" % describe_hint_obj(hint_obj)
                if self._tor:
                    description = "tor" + description
                d = task.deferLater(self._reactor, relay_delay,
                                    self._start_connector, ep, description,
                                    is_relay=True)
                contenders.append(d)
            relay_delay += self.RELAY_DELAY

        if not contenders:
            raise TransitError("No contenders for connection")

        winner = there_can_be_only_one(contenders)
        return self._not_forever(2*TIMEOUT, winner)

    def _not_forever(self, timeout, d):
        """If the timer fires first, cancel the deferred. If the deferred fires
        first, cancel the timer."""
        t = self._reactor.callLater(timeout, d.cancel)
        def _done(res):
            if t.active():
                t.cancel()
            return res
        d.addBoth(_done)
        return d

    def _build_relay_handshake(self):
        return build_sided_relay_handshake(self._transit_key, self._side)

    def _start_connector(self, ep, description, is_relay=False):
        relay_handshake = None
        if is_relay:
            assert self._transit_key
            relay_handshake = self._build_relay_handshake()
        f = OutboundConnectionFactory(self, relay_handshake, description)
        d = ep.connect(f)
        # fires with protocol, or ConnectError
        d.addCallback(lambda p: p.startNegotiation())
        return d

    def _endpoint_from_hint_obj(self, hint):
        if self._tor:
            if isinstance(hint, (DirectTCPV1Hint, TorTCPV1Hint)):
                # this Tor object will throw ValueError for non-public IPv4
                # addresses and any IPv6 address
                try:
                    return self._tor.stream_via(hint.hostname, hint.port)
                except ValueError:
                    return None
            return None
        if isinstance(hint, DirectTCPV1Hint):
            return endpoints.HostnameEndpoint(self._reactor,
                                              hint.hostname, hint.port)
        return None

    def connection_ready(self, p):
        # inbound/outbound Connection protocols call this when they finish
        # negotiation. The first one wins and gets a "go". Any subsequent
        # ones lose and get a "nevermind" before being closed.

        if not self.is_sender:
            return "wait-for-decision"

        if self._winner:
            # we already have a winner, so this one loses
            return "nevermind"
        # this one wins!
        self._winner = p
        return "go"
