from twisted.internet.defer import Deferred, inlineCallbacks, returnValue
from twisted.internet.endpoints import clientFromString, serverFromString

LEADER, FOLLOWER = object(), object()

@inlineCallbacks
def start_dilation(w, reactor):
    res = yield w._get_wormhole_versions_and_sides()
    (our_side, their_side, their_wormhole_versions) = res
    my_role = LEADER if our_side > their_side else FOLLOWER
    if my_role == LEADER:
        # leader launches the fake control connection
        control_ep = serverFromString(reactor, "tcp:4002")
        listen_ep = serverFromString(reactor, "tcp:4003")
        connect_ep = clientFromString(reactor, "tcp:127.0.0.1:4004")
    else:
        control_ep = clientFromString(reactor, "tcp:127.0.0.1:4002")
        listen_ep = serverFromString(reactor, "tcp:4004")
        connect_ep = clientFromString(reactor, "tcp:127.0.0.1:4003")

    endpoints = (control_ep, connect_ep, listen_ep)
    returnValue(endpoints)


