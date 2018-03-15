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
        #peeraddr = _SubchannelAddress(b"scid")
        ep = SubchannelListenerEndpoint(m, hostaddr)

        f = mock.Mock()
        p = mock.Mock()
        f.buildProtocol = mock.Mock(return_value=p)
        d = ep.listen(f)
        lp = self.successResultOf(d)
        self.assertIsInstance(lp, SubchannelListeningPort)

        #with mock.patch("wormhole._dilation.subchannel.SubChannel",
        #                return_value=t) as sc:
        #    pass
