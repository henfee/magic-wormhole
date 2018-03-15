from __future__ import print_function, unicode_literals
import mock
from zope.interface import alsoProvides
from twisted.trial import unittest
from twisted.internet.interfaces import ITransport
from twisted.internet.error import ConnectionDone
from wormhole._interfaces import IDilationManager, IWormhole, ISubChannel
from wormhole._dilation.encode import to_be4, from_be4
from wormhole._dilation.subchannel import (Once, SubChannel,
                                           ControlEndpoint,
                                           SubchannelConnectorEndpoint,
                                           SubchannelListenerEndpoint,
                                           SubchannelListeningPort,
                                           _WormholeAddress, _SubchannelAddress,
                                           AlreadyClosedError,
                                           SingleUseEndpointError)

class Encoding(unittest.TestCase):

    def test_be4(self):
        self.assertEqual(to_be4(0),   b"\x00\x00\x00\x00")
        self.assertEqual(to_be4(1),   b"\x00\x00\x00\x01")
        self.assertEqual(to_be4(256), b"\x00\x00\x01\x00")
        self.assertEqual(to_be4(257), b"\x00\x00\x01\x01")
        with self.assertRaises(ValueError):
            to_be4(-1)
        with self.assertRaises(ValueError):
            to_be4(2**32)

        self.assertEqual(from_be4(b"\x00\x00\x00\x00"), 0)
        self.assertEqual(from_be4(b"\x00\x00\x00\x01"), 1)
        self.assertEqual(from_be4(b"\x00\x00\x01\x00"), 256)
        self.assertEqual(from_be4(b"\x00\x00\x01\x01"), 257)

        with self.assertRaises(TypeError):
            from_be4(0)
        with self.assertRaises(ValueError):
            from_be4(b"\x01\x00\x00\x00\x00")

def mock_manager():
    m = mock.Mock()
    alsoProvides(m, IDilationManager)
    return m

def mock_wormhole():
    m = mock.Mock()
    alsoProvides(m, IWormhole)
    return m

def make_sc(set_protocol=True):
    scid = b"scid"
    hostaddr = _WormholeAddress(mock_wormhole())
    peeraddr = _SubchannelAddress(scid)
    m = mock_manager()
    sc = SubChannel(scid, m, hostaddr, peeraddr)
    p = mock.Mock()
    if set_protocol:
        sc._set_protocol(p)
    return sc, m, scid, hostaddr, peeraddr, p

class SubChannelAPI(unittest.TestCase):
    def test_once(self):
        o = Once(ValueError)
        o()
        with self.assertRaises(ValueError):
            o()

    def test_create(self):
        sc, m, scid, hostaddr, peeraddr, p = make_sc()
        self.assert_(ITransport.providedBy(sc))
        self.assertEqual(m.mock_calls, [])
        self.assertIdentical(sc.getHost(), hostaddr)
        self.assertIdentical(sc.getPeer(), peeraddr)

    def test_write(self):
        sc, m, scid, hostaddr, peeraddr, p = make_sc()

        sc.write(b"data")
        self.assertEqual(m.mock_calls, [mock.call.send_data(scid, b"data")])
        m.mock_calls[:] = []
        sc.writeSequence([b"more", b"data"])
        self.assertEqual(m.mock_calls, [mock.call.send_data(scid, b"moredata")])

    def test_write_when_closing(self):
        sc, m, scid, hostaddr, peeraddr, p = make_sc()

        sc.loseConnection()
        self.assertEqual(m.mock_calls, [mock.call.send_close(scid)])
        m.mock_calls[:] = []

        with self.assertRaises(AlreadyClosedError) as e:
            sc.write(b"data")
        self.assertEqual(str(e.exception),
                         "write not allowed on closed subchannel")

    def test_local_close(self):
        sc, m, scid, hostaddr, peeraddr, p = make_sc()

        sc.loseConnection()
        self.assertEqual(m.mock_calls, [mock.call.send_close(scid)])
        m.mock_calls[:] = []

        # late arriving data is still delivered
        sc.remote_data(b"late")
        self.assertEqual(p.mock_calls, [mock.call.dataReceived(b"late")])
        p.mock_calls[:] = []

        sc.remote_close()
        self.assert_connectionDone(p.mock_calls)

    def test_local_double_close(self):
        sc, m, scid, hostaddr, peeraddr, p = make_sc()

        sc.loseConnection()
        self.assertEqual(m.mock_calls, [mock.call.send_close(scid)])
        m.mock_calls[:] = []

        with self.assertRaises(AlreadyClosedError) as e:
            sc.loseConnection()
        self.assertEqual(str(e.exception),
                         "loseConnection not allowed on closed subchannel")

    def assert_connectionDone(self, mock_calls):
        self.assertEqual(len(mock_calls), 1)
        self.assertEqual(mock_calls[0][0], "connectionLost")
        self.assertEqual(len(mock_calls[0][1]), 1)
        self.assertIsInstance(mock_calls[0][1][0], ConnectionDone)

    def test_remote_close(self):
        sc, m, scid, hostaddr, peeraddr, p = make_sc()
        sc.remote_close()
        self.assertEqual(m.mock_calls, [mock.call.subchannel_closed(scid, sc)])
        self.assert_connectionDone(p.mock_calls)

    def test_data(self):
        sc, m, scid, hostaddr, peeraddr, p = make_sc()
        sc.remote_data(b"data")
        self.assertEqual(p.mock_calls, [mock.call.dataReceived(b"data")])
        p.mock_calls[:] = []
        sc.remote_data(b"not")
        sc.remote_data(b"coalesced")
        self.assertEqual(p.mock_calls, [mock.call.dataReceived(b"not"),
                                        mock.call.dataReceived(b"coalesced"),
                                        ])

    def test_data_before_open(self):
        sc, m, scid, hostaddr, peeraddr, p = make_sc(set_protocol=False)
        sc.remote_data(b"data")
        self.assertEqual(p.mock_calls, [])
        sc._set_protocol(p)
        self.assertEqual(p.mock_calls, [mock.call.dataReceived(b"data")])
        p.mock_calls[:] = []
        sc.remote_data(b"more")
        self.assertEqual(p.mock_calls, [mock.call.dataReceived(b"more")])

    def test_close_before_open(self):
        sc, m, scid, hostaddr, peeraddr, p = make_sc(set_protocol=False)
        sc.remote_close()
        self.assertEqual(p.mock_calls, [])
        sc._set_protocol(p)
        self.assert_connectionDone(p.mock_calls)

    def test_producer(self):
        sc, m, scid, hostaddr, peeraddr, p = make_sc()

        sc.pauseProducing()
        self.assertEqual(m.mock_calls, [mock.call.subchannel_pauseProducing(sc)])
        m.mock_calls[:] = []
        sc.resumeProducing()
        self.assertEqual(m.mock_calls, [mock.call.subchannel_resumeProducing(sc)])
        m.mock_calls[:] = []
        sc.stopProducing()
        self.assertEqual(m.mock_calls, [mock.call.subchannel_stopProducing(sc)])
        m.mock_calls[:] = []

    def test_consumer(self):
        sc, m, scid, hostaddr, peeraddr, p = make_sc()

        # TODO: more, once this is implemented
        sc.registerProducer(None, True)
        sc.unregisterProducer()

class Endpoints(unittest.TestCase):
    def test_control(self):
        scid0 = b"scid0"
        peeraddr = _SubchannelAddress(scid0)
        ep = ControlEndpoint(peeraddr)

        f = mock.Mock()
        p = mock.Mock()
        f.buildProtocol = mock.Mock(return_value=p)
        d = ep.connect(f)
        self.assertNoResult(d)

        t = mock.Mock()
        alsoProvides(t, ISubChannel)
        ep._subchannel_zero_opened(t)
        self.assertIdentical(self.successResultOf(d), p)
        self.assertEqual(f.buildProtocol.mock_calls, [mock.call(peeraddr)])
        self.assertEqual(t.mock_calls, [mock.call._set_protocol(p)])
        self.assertEqual(p.mock_calls, [mock.call.makeConnection(t)])

        d = ep.connect(f)
        self.failureResultOf(d, SingleUseEndpointError)

    def assert_makeConnection(self, mock_calls):
        self.assertEqual(len(mock_calls), 1)
        self.assertEqual(mock_calls[0][0], "makeConnection")
        self.assertEqual(len(mock_calls[0][1]), 1)
        return mock_calls[0][1][0]

    def test_connector(self):
        m = mock_manager()
        m.allocate_subchannel_id = mock.Mock(return_value=b"scid")
        hostaddr = _WormholeAddress(mock_wormhole())
        peeraddr = _SubchannelAddress(b"scid")
        ep = SubchannelConnectorEndpoint(m, hostaddr)

        f = mock.Mock()
        p = mock.Mock()
        t = mock.Mock()
        f.buildProtocol = mock.Mock(return_value=p)
        with mock.patch("wormhole._dilation.subchannel.SubChannel",
                        return_value=t) as sc:
            d = ep.connect(f)
        self.assertIdentical(self.successResultOf(d), p)
        self.assertEqual(f.buildProtocol.mock_calls, [mock.call(peeraddr)])
        self.assertEqual(sc.mock_calls, [mock.call(b"scid", m, hostaddr, peeraddr)])
        self.assertEqual(t.mock_calls, [mock.call._set_protocol(p)])
        self.assertEqual(p.mock_calls, [mock.call.makeConnection(t)])

    def test_listener(self):
        m = mock_manager()
        m.allocate_subchannel_id = mock.Mock(return_value=b"scid")
        hostaddr = _WormholeAddress(mock_wormhole())
        ep = SubchannelListenerEndpoint(m, hostaddr)

        f = mock.Mock()
        p1 = mock.Mock()
        p2 = mock.Mock()
        f.buildProtocol = mock.Mock(side_effect=[p1, p2])

        # OPEN that arrives before we ep.listen() should be queued

        t1 = mock.Mock()
        peeraddr1 = _SubchannelAddress(b"peer1")
        ep._got_open(t1, peeraddr1)

        d = ep.listen(f)
        lp = self.successResultOf(d)
        self.assertIsInstance(lp, SubchannelListeningPort)

        self.assertEqual(lp.getHost(), hostaddr)
        lp.startListening()

        self.assertEqual(t1.mock_calls, [mock.call._set_protocol(p1)])
        self.assertEqual(p1.mock_calls, [mock.call.makeConnection(t1)])

        t2 = mock.Mock()
        peeraddr2 = _SubchannelAddress(b"peer2")
        ep._got_open(t2, peeraddr2)

        self.assertEqual(t2.mock_calls, [mock.call._set_protocol(p2)])
        self.assertEqual(p2.mock_calls, [mock.call.makeConnection(t2)])

        lp.stopListening() # TODO: should this do more?

from .._dilation.connection import (_Framer, Frame, Prologue,
                                    #_Record,
                                    #DilatedConnectionProtocol,
                                    Disconnect)

def make_framer():
    t = mock.Mock()
    alsoProvides(t, ITransport)
    f = _Framer(t, b"outbound_prologue\n", b"inbound_prologue\n")
    return f, t

class Framer(unittest.TestCase):
    def test_bad_prologue_length(self):
        f, t = make_framer()
        self.assertEqual(t.mock_calls, [])

        f.connectionMade()
        self.assertEqual(t.mock_calls, [mock.call.write(b"outbound_prologue\n")])
        t.mock_calls[:] = []
        self.assertEqual([], list(f.add_and_parse(b"inbound_"))) # wait for it
        self.assertEqual(t.mock_calls, [])

        with mock.patch("wormhole._dilation.connection.log.msg") as m:
            with self.assertRaises(Disconnect):
                list(f.add_and_parse(b"not the prologue after all"))
        self.assertEqual(m.mock_calls,
                         [mock.call("bad prologue: {}".format(
                             b"inbound_not the p"))])
        self.assertEqual(t.mock_calls, [])

    def test_bad_prologue_newline(self):
        f, t = make_framer()
        self.assertEqual(t.mock_calls, [])

        f.connectionMade()
        self.assertEqual(t.mock_calls, [mock.call.write(b"outbound_prologue\n")])
        t.mock_calls[:] = []
        self.assertEqual([], list(f.add_and_parse(b"inbound_"))) # wait for it

        self.assertEqual([], list(f.add_and_parse(b"not")))
        with mock.patch("wormhole._dilation.connection.log.msg") as m:
            with self.assertRaises(Disconnect):
                list(f.add_and_parse(b"\n"))
        self.assertEqual(m.mock_calls,
                         [mock.call("bad prologue: {}".format(
                             b"inbound_not\n"))])
        self.assertEqual(t.mock_calls, [])

    def test_good_prologue(self):
        f, t = make_framer()
        self.assertEqual(t.mock_calls, [])

        f.connectionMade()
        self.assertEqual(t.mock_calls, [mock.call.write(b"outbound_prologue\n")])
        t.mock_calls[:] = []
        self.assertEqual([Prologue()],
                         list(f.add_and_parse(b"inbound_prologue\n")))
        self.assertEqual(t.mock_calls, [])

        # now send_frame should work
        f.send_frame(b"frame")
        self.assertEqual(t.mock_calls,
                         [mock.call.write(b"\x00\x00\x00\x05frame")])

    def test_bad_relay(self):
        f, t = make_framer()
        self.assertEqual(t.mock_calls, [])
        f.use_relay(b"relay handshake\n")

        f.connectionMade()
        self.assertEqual(t.mock_calls, [mock.call.write(b"relay handshake\n")])
        t.mock_calls[:] = []
        with mock.patch("wormhole._dilation.connection.log.msg") as m:
            with self.assertRaises(Disconnect):
                list(f.add_and_parse(b"goodbye\n"))
        self.assertEqual(m.mock_calls,
                         [mock.call("bad relay_ok: {}".format(b"goo"))])
        self.assertEqual(t.mock_calls, [])

    def test_good_relay(self):
        f, t = make_framer()
        self.assertEqual(t.mock_calls, [])
        f.use_relay(b"relay handshake\n")
        self.assertEqual(t.mock_calls, [])

        f.connectionMade()
        self.assertEqual(t.mock_calls, [mock.call.write(b"relay handshake\n")])
        t.mock_calls[:] = []

        self.assertEqual([], list(f.add_and_parse(b"ok\n")))
        self.assertEqual(t.mock_calls, [mock.call.write(b"outbound_prologue\n")])

    def test_frame(self):
        f, t = make_framer()
        self.assertEqual(t.mock_calls, [])

        f.connectionMade()
        self.assertEqual(t.mock_calls, [mock.call.write(b"outbound_prologue\n")])
        t.mock_calls[:] = []
        self.assertEqual([Prologue()],
                         list(f.add_and_parse(b"inbound_prologue\n")))
        self.assertEqual(t.mock_calls, [])

        encoded_frame = b"\x00\x00\x00\x05frame"
        self.assertEqual([], list(f.add_and_parse(encoded_frame[:2])))
        self.assertEqual([], list(f.add_and_parse(encoded_frame[2:6])))
        self.assertEqual([Frame(frame=b"frame")],
                         list(f.add_and_parse(encoded_frame[6:])))

from .._dilation.connection import (parse_record,
                                    KCM, Ping, Pong, Open, Data, Close, Ack)
class Parse(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_record(b"\x00"), KCM())
        self.assertEqual(parse_record(b"\x01\x55\x44\x33\x22"),
                         Ping(ping_id=b"\x55\x44\x33\x22"))
        self.assertEqual(parse_record(b"\x02\x55\x44\x33\x22"),
                         Pong(ping_id=b"\x55\x44\x33\x22"))
        self.assertEqual(parse_record(b"\x03scidseqn"),
                         Open(scid=b"scid", seqnum=b"seqn"))
        self.assertEqual(parse_record(b"\x04scidseqndataaa"),
                         Data(scid=b"scid", seqnum=b"seqn", data=b"dataaa"))
        self.assertEqual(parse_record(b"\x05scidseqn"),
                         Close(scid=b"scid", seqnum=b"seqn"))
        self.assertEqual(parse_record(b"\x06seqn"),
                         Ack(resp_seqnum=b"seqn"))
        with mock.patch("wormhole._dilation.connection.log.err") as m:
            with self.assertRaises(ValueError):
                parse_record(b"\x07unknown")
        self.assertEqual(m.mock_calls,
                         [mock.call("received unknown message type: {}".format(
                             b"\x07unknown"))])

