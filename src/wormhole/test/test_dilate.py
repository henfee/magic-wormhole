from __future__ import print_function, unicode_literals
from collections import namedtuple
from itertools import cycle
import mock
from zope.interface import alsoProvides
from twisted.trial import unittest
from twisted.internet.task import Clock, Cooperator
from twisted.internet.interfaces import ITransport, IPullProducer
from twisted.internet.error import ConnectionDone
from noise.exceptions import NoiseInvalidMessage
from ..eventual import EventualQueue
from .._interfaces import (IDilationManager, IDilationConnector,
                           IWormhole, ISubChannel)
from .._dilation.roles import LEADER, FOLLOWER
from .._dilation.encode import to_be4, from_be4
from .._dilation.subchannel import (Once, SubChannel,
                                    ControlEndpoint,
                                    SubchannelConnectorEndpoint,
                                    SubchannelListenerEndpoint,
                                    SubchannelListeningPort,
                                    _WormholeAddress, _SubchannelAddress,
                                    AlreadyClosedError,
                                    SingleUseEndpointError)

from .._dilation.connection import (IFramer, _Framer, Frame, Prologue,
                                    _Record, Handshake,
                                    DilatedConnectionProtocol,
                                    Disconnect)
from .._dilation.connection import (parse_record, encode_record,
                                    KCM, Ping, Pong, Open, Data, Close, Ack)
from .._dilation.inbound import (Inbound, DuplicateOpenError,
                                 DataForMissingSubchannelError,
                                 CloseForMissingSubchannelError)
from .._dilation.outbound import Outbound, PullToPush


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
        self.assertEqual(m.mock_calls, [mock.call.subchannel_closed(sc)])
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

class Parse(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_record(b"\x00"), KCM())
        self.assertEqual(parse_record(b"\x01\x55\x44\x33\x22"),
                         Ping(ping_id=b"\x55\x44\x33\x22"))
        self.assertEqual(parse_record(b"\x02\x55\x44\x33\x22"),
                         Pong(ping_id=b"\x55\x44\x33\x22"))
        self.assertEqual(parse_record(b"\x03\x00\x00\x02\x01\x00\x00\x01\x00"),
                         Open(scid=513, seqnum=256))
        self.assertEqual(parse_record(b"\x04\x00\x00\x02\x02\x00\x00\x01\x01dataaa"),
                         Data(scid=514, seqnum=257, data=b"dataaa"))
        self.assertEqual(parse_record(b"\x05\x00\x00\x02\x03\x00\x00\x01\x02"),
                         Close(scid=515, seqnum=258))
        self.assertEqual(parse_record(b"\x06\x00\x00\x01\x03"),
                         Ack(resp_seqnum=259))
        with mock.patch("wormhole._dilation.connection.log.err") as le:
            with self.assertRaises(ValueError):
                parse_record(b"\x07unknown")
        self.assertEqual(le.mock_calls,
                         [mock.call("received unknown message type: {}".format(
                             b"\x07unknown"))])

    def test_encode(self):
        self.assertEqual(encode_record(KCM()), b"\x00")
        self.assertEqual(encode_record(Ping(ping_id=b"ping")), b"\x01ping")
        self.assertEqual(encode_record(Pong(ping_id=b"pong")), b"\x02pong")
        self.assertEqual(encode_record(Open(scid=65536, seqnum=16)),
                         b"\x03\x00\x01\x00\x00\x00\x00\x00\x10")
        self.assertEqual(encode_record(Data(scid=65537, seqnum=17, data=b"dataaa")),
                         b"\x04\x00\x01\x00\x01\x00\x00\x00\x11dataaa")
        self.assertEqual(encode_record(Close(scid=65538, seqnum=18)),
                         b"\x05\x00\x01\x00\x02\x00\x00\x00\x12")
        self.assertEqual(encode_record(Ack(resp_seqnum=19)),
                         b"\x06\x00\x00\x00\x13")
        with self.assertRaises(TypeError) as ar:
            encode_record("not a record")
        self.assertEqual(str(ar.exception), "not a record")

def make_record():
    f = mock.Mock()
    alsoProvides(f, IFramer)
    n = mock.Mock() # pretends to be a Noise object
    r = _Record(f, n)
    return r, f, n

class Record(unittest.TestCase):
    def test_good2(self):
        f = mock.Mock()
        alsoProvides(f, IFramer)
        f.add_and_parse = mock.Mock(side_effect=[
            [],
            [Prologue()],
            [Frame(frame=b"rx-handshake")],
            [Frame(frame=b"frame1"), Frame(frame=b"frame2")],
            ])
        n = mock.Mock()
        n.write_message = mock.Mock(return_value=b"tx-handshake")
        p1, p2 = object(), object()
        n.decrypt = mock.Mock(side_effect=[p1, p2])
        r = _Record(f, n)
        self.assertEqual(f.mock_calls, [])
        r.connectionMade()
        self.assertEqual(f.mock_calls, [mock.call.connectionMade()])
        f.mock_calls[:] = []
        self.assertEqual(n.mock_calls, [mock.call.start_handshake()])
        n.mock_calls[:] = []

        # Pretend to deliver the prologue in two parts. The text we send in
        # doesn't matter: the side_effect= is what causes the prologue to be
        # recognized by the second call.
        self.assertEqual(list(r.add_and_unframe(b"pro")), [])
        self.assertEqual(f.mock_calls, [mock.call.add_and_parse(b"pro")])
        f.mock_calls[:] = []
        self.assertEqual(n.mock_calls, [])

        # recognizing the prologue causes a handshake frame to be sent
        self.assertEqual(list(r.add_and_unframe(b"logue")), [])
        self.assertEqual(f.mock_calls, [mock.call.add_and_parse(b"logue"),
                                        mock.call.send_frame(b"tx-handshake")])
        f.mock_calls[:] = []
        self.assertEqual(n.mock_calls, [mock.call.write_message()])
        n.mock_calls[:] = []

        # next add_and_unframe is recognized as the Handshake
        self.assertEqual(list(r.add_and_unframe(b"blah")), [Handshake()])
        self.assertEqual(f.mock_calls, [mock.call.add_and_parse(b"blah")])
        f.mock_calls[:] = []
        self.assertEqual(n.mock_calls, [mock.call.read_message(b"rx-handshake")])
        n.mock_calls[:] = []

        # next is a pair of Records
        r1, r2 = object() , object()
        with mock.patch("wormhole._dilation.connection.parse_record",
                        side_effect=[r1,r2]) as pr:
            self.assertEqual(list(r.add_and_unframe(b"blah2")), [r1, r2])
            self.assertEqual(n.mock_calls, [mock.call.decrypt(b"frame1"),
                                            mock.call.decrypt(b"frame2")])
            self.assertEqual(pr.mock_calls, [mock.call(p1), mock.call(p2)])

    def test_bad_handshake(self):
        f = mock.Mock()
        alsoProvides(f, IFramer)
        f.add_and_parse = mock.Mock(return_value=[Prologue(),
                                                  Frame(frame=b"rx-handshake")])
        n = mock.Mock()
        n.write_message = mock.Mock(return_value=b"tx-handshake")
        nvm = NoiseInvalidMessage()
        n.read_message = mock.Mock(side_effect=nvm)
        r = _Record(f, n)
        self.assertEqual(f.mock_calls, [])
        r.connectionMade()
        self.assertEqual(f.mock_calls, [mock.call.connectionMade()])
        f.mock_calls[:] = []
        self.assertEqual(n.mock_calls, [mock.call.start_handshake()])
        n.mock_calls[:] = []

        with mock.patch("wormhole._dilation.connection.log.err") as le:
            with self.assertRaises(Disconnect):
                list(r.add_and_unframe(b"data"))
        self.assertEqual(le.mock_calls,
                         [mock.call(nvm, "bad inbound noise handshake")])

    def test_bad_message(self):
        f = mock.Mock()
        alsoProvides(f, IFramer)
        f.add_and_parse = mock.Mock(return_value=[Prologue(),
                                                  Frame(frame=b"rx-handshake"),
                                                  Frame(frame=b"bad-message")])
        n = mock.Mock()
        n.write_message = mock.Mock(return_value=b"tx-handshake")
        nvm = NoiseInvalidMessage()
        n.decrypt = mock.Mock(side_effect=nvm)
        r = _Record(f, n)
        self.assertEqual(f.mock_calls, [])
        r.connectionMade()
        self.assertEqual(f.mock_calls, [mock.call.connectionMade()])
        f.mock_calls[:] = []
        self.assertEqual(n.mock_calls, [mock.call.start_handshake()])
        n.mock_calls[:] = []

        with mock.patch("wormhole._dilation.connection.log.err") as le:
            with self.assertRaises(Disconnect):
                list(r.add_and_unframe(b"data"))
        self.assertEqual(le.mock_calls,
                         [mock.call(nvm, "bad inbound noise frame")])

    def test_send_record(self):
        f = mock.Mock()
        alsoProvides(f, IFramer)
        n = mock.Mock()
        f1 = object()
        n.encrypt = mock.Mock(return_value=f1)
        r1 = Ping(b"pingid")
        r = _Record(f, n)
        self.assertEqual(f.mock_calls, [])
        m1 = object()
        with mock.patch("wormhole._dilation.connection.encode_record",
                        return_value=m1) as er:
            r.send_record(r1)
        self.assertEqual(er.mock_calls, [mock.call(r1)])
        self.assertEqual(n.mock_calls, [mock.call.start_handshake(),
                                        mock.call.encrypt(m1)])
        self.assertEqual(f.mock_calls, [mock.call.send_frame(f1)])

    def test_good(self):
        # Exercise the success path. The Record instance is given each chunk
        # of data as it arrives on Protocol.dataReceived, and is supposed to
        # return a series of Tokens (maybe none, if the chunk was incomplete,
        # or more than one, if the chunk was larger). Internally, it delivers
        # the chunks to the Framer for unframing (which returns 0 or more
        # frames), manages the Noise decryption object, and parses any
        # decrypted messages into tokens (some of which are consumed
        # internally, others for delivery upstairs).
        #
        # in the normal flow, we get:
        #
        # |   | Inbound   | NoiseAction   | Outbound  | ToUpstairs |
        # |   | -         | -             | -         | -          |
        # | 1 |           |               | prologue  |            |
        # | 2 | prologue  |               |           |            |
        # | 3 |           | write_message | handshake |            |
        # | 4 | handshake | read_message  |           | Handshake  |
        # | 5 |           | encrypt       | KCM       |            |
        # | 6 | KCM       | decrypt       |           | KCM        |
        # | 7 | msg1      | decrypt       |           | msg1       |

        # 1: instantiating the Record instance causes the outbound prologue
        # to be sent

        # 2+3: receipt of the inbound prologue triggers creation of the
        # ephemeral key (the "handshake") by calling noise.write_message()
        # and then writes the handshake to the outbound transport

        # 4: when the peer's handshake is received, it is delivered to
        # noise.read_message(), which generates the shared key (enabling
        # noise.send() and noise.decrypt()). It also delivers the Handshake
        # token upstairs, which might (on the Follower) trigger immediate
        # transmission of the Key Confirmation Message (KCM)

        # 5: the outbound KCM is framed and fed into noise.encrypt(), then
        # sent outbound

        # 6: the peer's KCM is decrypted then delivered upstairs. The
        # Follower treats this as a signal that it should use this connection
        # (and drop all others).

        # 7: the peer's first message is decrypted, parsed, and delivered
        # upstairs. This might be an Open or a Data, depending upon what
        # queued messages were left over from the previous connection

        r, f, n = make_record()
        outbound_handshake = object()
        kcm, msg1 = object(), object()
        f_kcm, f_msg1 = object(), object()
        n.write_message = mock.Mock(return_value=outbound_handshake)
        n.decrypt = mock.Mock(side_effect=[kcm, msg1])
        n.encrypt = mock.Mock(side_effect=[f_kcm, f_msg1])
        f.add_and_parse = mock.Mock(side_effect=[[], # no tokens yet
                                                 [Prologue()],
                                                 [Frame("f_handshake")],
                                                 [Frame("f_kcm"),
                                                  Frame("f_msg1")],
                                                 ])

        self.assertEqual(f.mock_calls, [])
        self.assertEqual(n.mock_calls, [mock.call.start_handshake()])
        n.mock_calls[:] = []

        # 1. The Framer is responsible for sending the prologue, so we don't
        # have to check that here, we just check that the Framer was told
        # about connectionMade properly.
        r.connectionMade()
        self.assertEqual(f.mock_calls, [mock.call.connectionMade()])
        self.assertEqual(n.mock_calls, [])
        f.mock_calls[:] = []

        # 2
        # we dribble the prologue in over two messages, to make sure we can
        # handle a dataReceived that doesn't complete the token

        # remember, add_and_unframe is a generator
        self.assertEqual(list(r.add_and_unframe(b"pro")), [])
        self.assertEqual(f.mock_calls, [mock.call.add_and_parse(b"pro")])
        self.assertEqual(n.mock_calls, [])
        f.mock_calls[:] = []

        self.assertEqual(list(r.add_and_unframe(b"logue")), [])
        # 3: write_message, send outbound handshake
        self.assertEqual(f.mock_calls, [mock.call.add_and_parse(b"logue"),
                                        mock.call.send_frame(outbound_handshake),
                                        ])
        self.assertEqual(n.mock_calls, [mock.call.write_message()])
        f.mock_calls[:] = []
        n.mock_calls[:] = []

        # 4
        # Now deliver the Noise "handshake", the ephemeral public key. This
        # is framed, but not a record, so it shouldn't decrypt or parse
        # anything, but the handshake is delivered to the Noise object, and
        # it does return a Handshake token so we can let the next layer up
        # react (by sending the KCM frame if we're a Follower, or not if
        # we're the Leader)

        self.assertEqual(list(r.add_and_unframe(b"handshake")), [Handshake()])
        self.assertEqual(f.mock_calls, [mock.call.add_and_parse(b"handshake")])
        self.assertEqual(n.mock_calls, [mock.call.read_message("f_handshake")])
        f.mock_calls[:] = []
        n.mock_calls[:] = []


        # 5: at this point we ought to be able to send a messge, the KCM
        with mock.patch("wormhole._dilation.connection.encode_record",
                        side_effect=[b"r-kcm"]) as er:
            r.send_record(kcm)
        self.assertEqual(er.mock_calls, [mock.call(kcm)])
        self.assertEqual(n.mock_calls, [mock.call.encrypt(b"r-kcm")])
        self.assertEqual(f.mock_calls, [mock.call.send_frame(f_kcm)])
        n.mock_calls[:] = []
        f.mock_calls[:] = []

        # 6: Now we deliver two messages stacked up: the KCM (Key
        # Confirmation Message) and the first real message. Concatenating
        # them tests that we can handle more than one token in a single
        # chunk. We need to mock parse_record() because everything past the
        # handshake is decrypted and parsed.

        with mock.patch("wormhole._dilation.connection.parse_record",
                        side_effect=[kcm, msg1]) as pr:
            self.assertEqual(list(r.add_and_unframe(b"kcm,msg1")),
                             [kcm, msg1])
            self.assertEqual(f.mock_calls,
                             [mock.call.add_and_parse(b"kcm,msg1")])
            self.assertEqual(n.mock_calls, [mock.call.decrypt("f_kcm"),
                                            mock.call.decrypt("f_msg1")])
            self.assertEqual(pr.mock_calls, [mock.call(kcm), mock.call(msg1)])
        n.mock_calls[:] = []
        f.mock_calls[:] = []

def make_con(role, use_relay=False):
    clock = Clock()
    eq = EventualQueue(clock)
    connector = mock.Mock()
    alsoProvides(connector, IDilationConnector)
    n = mock.Mock() # pretends to be a Noise object
    n.write_message = mock.Mock(side_effect=[b"handshake"])
    c = DilatedConnectionProtocol(eq, role, connector, n,
                                  b"outbound_prologue\n", b"inbound_prologue\n")
    if use_relay:
        c.use_relay(b"relay_handshake\n")
    t = mock.Mock()
    alsoProvides(t, ITransport)
    return c, n, connector, t, eq

def clear_mock_calls(*args):
    for a in args:
        a.mock_calls[:] = []

class Connection(unittest.TestCase):
    def test_bad_prologue(self):
        c, n, connector, t, eq = make_con(LEADER)
        c.makeConnection(t)
        d = c.when_disconnected()
        self.assertEqual(n.mock_calls, [mock.call.start_handshake()])
        self.assertEqual(connector.mock_calls, [])
        self.assertEqual(t.mock_calls, [mock.call.write(b"outbound_prologue\n")])
        clear_mock_calls(n, connector, t)

        c.dataReceived(b"prologue\n")
        self.assertEqual(n.mock_calls, [])
        self.assertEqual(connector.mock_calls, [])
        self.assertEqual(t.mock_calls, [mock.call.loseConnection()])

        eq.flush_sync()
        self.assertNoResult(d)
        c.connectionLost(b"why")
        eq.flush_sync()
        self.assertIdentical(self.successResultOf(d), c)

    def _test_no_relay(self, role):
        c, n, connector, t, eq = make_con(role)
        t_kcm = KCM()
        t_open = Open(seqnum=1, scid=0x11223344)
        t_ack = Ack(resp_seqnum=2)
        n.decrypt = mock.Mock(side_effect=[
            encode_record(t_kcm),
            encode_record(t_open),
            ])
        exp_kcm = b"\x00\x00\x00\x03kcm"
        n.encrypt = mock.Mock(side_effect=[b"kcm", b"ack1"])
        m = mock.Mock() # Manager

        c.makeConnection(t)
        self.assertEqual(n.mock_calls, [mock.call.start_handshake()])
        self.assertEqual(connector.mock_calls, [])
        self.assertEqual(t.mock_calls, [mock.call.write(b"outbound_prologue\n")])
        clear_mock_calls(n, connector, t, m)

        c.dataReceived(b"inbound_prologue\n")
        self.assertEqual(n.mock_calls, [mock.call.write_message()])
        self.assertEqual(connector.mock_calls, [])
        exp_handshake = b"\x00\x00\x00\x09handshake"
        self.assertEqual(t.mock_calls, [mock.call.write(exp_handshake)])
        clear_mock_calls(n, connector, t, m)

        c.dataReceived(b"\x00\x00\x00\x0Ahandshake2")
        if role is LEADER:
            # we're the leader, so we don't send the KCM right away
            self.assertEqual(n.mock_calls, [
                mock.call.read_message(b"handshake2")])
            self.assertEqual(connector.mock_calls, [])
            self.assertEqual(t.mock_calls, [])
            self.assertEqual(c._manager, None)
        else:
            # we're the follower, so we encrypt and send the KCM immediately
            self.assertEqual(n.mock_calls, [
                mock.call.read_message(b"handshake2"),
                mock.call.encrypt(encode_record(t_kcm)),
                ])
            self.assertEqual(connector.mock_calls, [])
            self.assertEqual(t.mock_calls, [
                mock.call.write(exp_kcm)])
            self.assertEqual(c._manager, None)
        clear_mock_calls(n, connector, t, m)

        c.dataReceived(b"\x00\x00\x00\x03KCM")
        # leader: inbound KCM means we add the candidate
        # follower: inbound KCM means we've been selected.
        # in both cases we notify Connector.add_candidate(), and the Connector
        # decides if/when to call .select()

        self.assertEqual(n.mock_calls, [mock.call.decrypt(b"KCM")])
        self.assertEqual(connector.mock_calls, [mock.call.add_candidate(c)])
        self.assertEqual(t.mock_calls, [])
        clear_mock_calls(n, connector, t, m)

        # now pretend this connection wins (either the Leader decides to use
        # this one among all the candiates, or we're the Follower and the
        # Connector is reacting to add_candidate() by recognizing we're the
        # only candidate there is)
        c.select(m)
        self.assertIdentical(c._manager, m)
        if role is LEADER:
            # TODO: currently Connector.select_and_stop_remaining() is
            # responsible for sending the KCM just before calling c.select()
            # iff we're the LEADER, therefore Connection.select won't send
            # anything. This should be moved to c.select().
            self.assertEqual(n.mock_calls, [])
            self.assertEqual(connector.mock_calls, [])
            self.assertEqual(t.mock_calls, [])
            self.assertEqual(m.mock_calls, [])

            c.send_record(KCM())
            self.assertEqual(n.mock_calls, [
                mock.call.encrypt(encode_record(t_kcm)),
                ])
            self.assertEqual(connector.mock_calls, [])
            self.assertEqual(t.mock_calls, [mock.call.write(exp_kcm)])
            self.assertEqual(m.mock_calls, [])
        else:
            # follower: we already sent the KCM, do nothing
            self.assertEqual(n.mock_calls, [])
            self.assertEqual(connector.mock_calls, [])
            self.assertEqual(t.mock_calls, [])
            self.assertEqual(m.mock_calls, [])
        clear_mock_calls(n, connector, t, m)

        c.dataReceived(b"\x00\x00\x00\x04msg1")
        self.assertEqual(n.mock_calls, [mock.call.decrypt(b"msg1")])
        self.assertEqual(connector.mock_calls, [])
        self.assertEqual(t.mock_calls, [])
        self.assertEqual(m.mock_calls, [mock.call.got_record(t_open)])
        clear_mock_calls(n, connector, t, m)

        c.send_record(t_ack)
        exp_ack = b"\x06\x00\x00\x00\x02"
        self.assertEqual(n.mock_calls, [mock.call.encrypt(exp_ack)])
        self.assertEqual(connector.mock_calls, [])
        self.assertEqual(t.mock_calls, [mock.call.write(b"\x00\x00\x00\x04ack1")])
        self.assertEqual(m.mock_calls, [])
        clear_mock_calls(n, connector, t, m)

        c.disconnect()
        self.assertEqual(n.mock_calls, [])
        self.assertEqual(connector.mock_calls, [])
        self.assertEqual(t.mock_calls, [mock.call.loseConnection()])
        self.assertEqual(m.mock_calls, [])
        clear_mock_calls(n, connector, t, m)

    def test_no_relay_leader(self):
        return self._test_no_relay(LEADER)

    def test_no_relay_follower(self):
        return self._test_no_relay(FOLLOWER)


    def test_relay(self):
        c, n, connector, t, eq = make_con(LEADER, use_relay=True)

        c.makeConnection(t)
        self.assertEqual(n.mock_calls, [mock.call.start_handshake()])
        self.assertEqual(connector.mock_calls, [])
        self.assertEqual(t.mock_calls, [mock.call.write(b"relay_handshake\n")])
        clear_mock_calls(n, connector, t)

        c.dataReceived(b"ok\n")
        self.assertEqual(n.mock_calls, [])
        self.assertEqual(connector.mock_calls, [])
        self.assertEqual(t.mock_calls, [mock.call.write(b"outbound_prologue\n")])
        clear_mock_calls(n, connector, t)

        c.dataReceived(b"inbound_prologue\n")
        self.assertEqual(n.mock_calls, [mock.call.write_message()])
        self.assertEqual(connector.mock_calls, [])
        exp_handshake = b"\x00\x00\x00\x09handshake"
        self.assertEqual(t.mock_calls, [mock.call.write(exp_handshake)])
        clear_mock_calls(n, connector, t)

    def test_relay_jilted(self):
        c, n, connector, t, eq = make_con(LEADER, use_relay=True)
        d = c.when_disconnected()

        c.makeConnection(t)
        self.assertEqual(n.mock_calls, [mock.call.start_handshake()])
        self.assertEqual(connector.mock_calls, [])
        self.assertEqual(t.mock_calls, [mock.call.write(b"relay_handshake\n")])
        clear_mock_calls(n, connector, t)

        c.connectionLost(b"why")
        eq.flush_sync()
        self.assertIdentical(self.successResultOf(d), c)

    def test_relay_bad_response(self):
        c, n, connector, t, eq = make_con(LEADER, use_relay=True)

        c.makeConnection(t)
        self.assertEqual(n.mock_calls, [mock.call.start_handshake()])
        self.assertEqual(connector.mock_calls, [])
        self.assertEqual(t.mock_calls, [mock.call.write(b"relay_handshake\n")])
        clear_mock_calls(n, connector, t)

        c.dataReceived(b"not ok\n")
        self.assertEqual(n.mock_calls, [])
        self.assertEqual(connector.mock_calls, [])
        self.assertEqual(t.mock_calls, [mock.call.loseConnection()])
        clear_mock_calls(n, connector, t)

def make_inbound():
    m = mock.Mock()
    alsoProvides(m, IDilationManager)
    host_addr = object()
    i = Inbound(m, host_addr)
    return i, m, host_addr

class InboundTest(unittest.TestCase):
    def test_seqnum(self):
        i, m, host_addr = make_inbound()
        r1 = Open(scid=513, seqnum=1)
        r2 = Data(scid=513, seqnum=2, data=b"")
        r3 = Close(scid=513, seqnum=3)
        self.assertFalse(i.is_record_old(r1))
        self.assertFalse(i.is_record_old(r2))
        self.assertFalse(i.is_record_old(r3))

        i.update_ack_watermark(r1)
        self.assertTrue(i.is_record_old(r1))
        self.assertFalse(i.is_record_old(r2))
        self.assertFalse(i.is_record_old(r3))

        i.update_ack_watermark(r2)
        self.assertTrue(i.is_record_old(r1))
        self.assertTrue(i.is_record_old(r2))
        self.assertFalse(i.is_record_old(r3))

    def test_open_data_close(self):
        i, m, host_addr = make_inbound()
        scid1 = b"scid"
        scid2 = b"scXX"
        c = mock.Mock()
        lep = mock.Mock()
        i.set_listener_endpoint(lep)
        i.use_connection(c)
        sc1 = mock.Mock()
        peer_addr = object()
        with mock.patch("wormhole._dilation.inbound.SubChannel",
                        side_effect=[sc1]) as sc:
            with mock.patch("wormhole._dilation.inbound._SubchannelAddress",
                            side_effect=[peer_addr]) as sca:
                i.handle_open(scid1)
        self.assertEqual(lep.mock_calls, [mock.call._got_open(sc1, peer_addr)])
        self.assertEqual(sc.mock_calls, [mock.call(scid1, m, host_addr, peer_addr)])
        self.assertEqual(sca.mock_calls, [mock.call(scid1)])
        lep.mock_calls[:] = []

        # a subsequent duplicate OPEN should be ignored
        with mock.patch("wormhole._dilation.inbound.SubChannel",
                        side_effect=[sc1]) as sc:
            with mock.patch("wormhole._dilation.inbound._SubchannelAddress",
                            side_effect=[peer_addr]) as sca:
                i.handle_open(scid1)
        self.assertEqual(lep.mock_calls, [])
        self.assertEqual(sc.mock_calls, [])
        self.assertEqual(sca.mock_calls, [])
        self.flushLoggedErrors(DuplicateOpenError)

        i.handle_data(scid1, b"data")
        self.assertEqual(sc1.mock_calls, [mock.call.remote_data(b"data")])
        sc1.mock_calls[:] = []

        i.handle_data(scid2, b"for non-existent subchannel")
        self.assertEqual(sc1.mock_calls, [])
        self.flushLoggedErrors(DataForMissingSubchannelError)

        i.handle_close(scid1)
        self.assertEqual(sc1.mock_calls, [mock.call.remote_close()])
        sc1.mock_calls[:] = []

        i.handle_close(scid2)
        self.assertEqual(sc1.mock_calls, [])
        self.flushLoggedErrors(CloseForMissingSubchannelError)

        # after the subchannel is closed, the Manager will notify Inbound
        i.subchannel_closed(scid1, sc1)

        i.stop_using_connection()

    def test_control_channel(self):
        i, m, host_addr = make_inbound()
        lep = mock.Mock()
        i.set_listener_endpoint(lep)

        scid0 = b"scid"
        sc0 = mock.Mock()
        i.set_subchannel_zero(scid0, sc0)

        # OPEN on the control channel identifier should be ignored as a
        # duplicate, since the control channel is already registered
        sc1 = mock.Mock()
        peer_addr = object()
        with mock.patch("wormhole._dilation.inbound.SubChannel",
                        side_effect=[sc1]) as sc:
            with mock.patch("wormhole._dilation.inbound._SubchannelAddress",
                            side_effect=[peer_addr]) as sca:
                i.handle_open(scid0)
        self.assertEqual(lep.mock_calls, [])
        self.assertEqual(sc.mock_calls, [])
        self.assertEqual(sca.mock_calls, [])
        self.flushLoggedErrors(DuplicateOpenError)

        # and DATA to it should be delivered correctly
        i.handle_data(scid0, b"data")
        self.assertEqual(sc0.mock_calls, [mock.call.remote_data(b"data")])
        sc0.mock_calls[:] = []

    def test_pause(self):
        i, m, host_addr = make_inbound()
        c = mock.Mock()
        lep = mock.Mock()
        i.set_listener_endpoint(lep)

        # add two subchannels, pause one, then add a connection
        scid1 = b"sci1"
        scid2 = b"sci2"
        sc1 = mock.Mock()
        sc2 = mock.Mock()
        peer_addr = object()
        with mock.patch("wormhole._dilation.inbound.SubChannel",
                        side_effect=[sc1, sc2]):
            with mock.patch("wormhole._dilation.inbound._SubchannelAddress",
                            return_value=peer_addr):
                i.handle_open(scid1)
                i.handle_open(scid2)
        self.assertEqual(c.mock_calls, [])

        i.subchannel_pauseProducing(sc1)
        self.assertEqual(c.mock_calls, [])
        i.subchannel_resumeProducing(sc1)
        self.assertEqual(c.mock_calls, [])
        i.subchannel_pauseProducing(sc1)
        self.assertEqual(c.mock_calls, [])

        i.use_connection(c)
        self.assertEqual(c.mock_calls, [mock.call.pauseProducing()])
        c.mock_calls[:] = []

        i.subchannel_resumeProducing(sc1)
        self.assertEqual(c.mock_calls, [mock.call.resumeProducing()])
        c.mock_calls[:] = []

        # consumers aren't really supposed to do this, but tolerate it
        i.subchannel_resumeProducing(sc1)
        self.assertEqual(c.mock_calls, [])

        i.subchannel_pauseProducing(sc1)
        self.assertEqual(c.mock_calls, [mock.call.pauseProducing()])
        c.mock_calls[:] = []
        i.subchannel_pauseProducing(sc2)
        self.assertEqual(c.mock_calls, []) # was already paused

        # tolerate duplicate pauseProducing
        i.subchannel_pauseProducing(sc2)
        self.assertEqual(c.mock_calls, [])

        # stopProducing is treated like a terminal resumeProducing
        i.subchannel_stopProducing(sc1)
        self.assertEqual(c.mock_calls, [])
        i.subchannel_stopProducing(sc2)
        self.assertEqual(c.mock_calls, [mock.call.resumeProducing()])
        c.mock_calls[:] = []

Pauser = namedtuple("Pauser", ["seqnum"])
NonPauser = namedtuple("NonPauser", ["seqnum"])
Stopper = namedtuple("Stopper", ["sc"])

def make_outbound():
    m = mock.Mock()
    alsoProvides(m, IDilationManager)
    clock = Clock()
    eq = EventualQueue(clock)
    term = mock.Mock(side_effect=lambda: True) # one write per Eventual tick
    term_factory = lambda: term
    coop = Cooperator(terminationPredicateFactory=term_factory,
                      scheduler=eq.eventually)
    o = Outbound(m, coop)
    c = mock.Mock() # Connection
    def maybe_pause(r):
        if isinstance(r, Pauser):
            o.pauseProducing()
        elif isinstance(r, Stopper):
            o.subchannel_unregisterProducer(r.sc)
    c.send_record = mock.Mock(side_effect=maybe_pause)
    o._test_eq = eq
    o._test_term = term
    return o, m, c

class OutboundTest(unittest.TestCase):
    def test_build_record(self):
        o, m, c = make_outbound()
        scid1 = b"scid"
        self.assertEqual(o.build_record(Open, scid1),
                         Open(seqnum=0, scid=b"scid"))
        self.assertEqual(o.build_record(Data, scid1, b"dataaa"),
                         Data(seqnum=1, scid=b"scid", data=b"dataaa"))
        self.assertEqual(o.build_record(Close, scid1),
                         Close(seqnum=2, scid=b"scid"))
        self.assertEqual(o.build_record(Close, scid1),
                         Close(seqnum=3, scid=b"scid"))

    def test_outbound_queue(self):
        o, m, c = make_outbound()
        scid1 = b"scid"
        r1 = o.build_record(Open, scid1)
        r2 = o.build_record(Data, scid1, b"data1")
        r3 = o.build_record(Data, scid1, b"data2")
        o.queue_and_send_record(r1)
        o.queue_and_send_record(r2)
        o.queue_and_send_record(r3)
        self.assertEqual(list(o._outbound_queue), [r1, r2, r3])

        # we would never normally receive an ACK without first getting a
        # connection
        o.handle_ack(r2.seqnum)
        self.assertEqual(list(o._outbound_queue), [r3])

        o.handle_ack(r3.seqnum)
        self.assertEqual(list(o._outbound_queue), [])

        o.handle_ack(r3.seqnum) # ignored
        self.assertEqual(list(o._outbound_queue), [])

        o.handle_ack(r1.seqnum) # ignored
        self.assertEqual(list(o._outbound_queue), [])

    def test_duplicate_registerProducer(self):
        o, m, c = make_outbound()
        sc1 = object()
        p1 = mock.Mock()
        o.subchannel_registerProducer(sc1, p1, True)
        with self.assertRaises(ValueError) as ar:
            o.subchannel_registerProducer(sc1, p1, True)
        s = str(ar.exception)
        self.assertIn("registering producer", s)
        self.assertIn("before previous one", s)
        self.assertIn("was unregistered", s)

    def test_connection_send_queued_unpaused(self):
        o, m, c = make_outbound()
        scid1 = b"scid"
        r1 = o.build_record(Open, scid1)
        r2 = o.build_record(Data, scid1, b"data1")
        r3 = o.build_record(Data, scid1, b"data2")
        o.queue_and_send_record(r1)
        o.queue_and_send_record(r2)
        self.assertEqual(list(o._outbound_queue), [r1, r2])
        self.assertEqual(list(o._queued_unsent), [])

        # as soon as the connection is established, everything is sent
        o.use_connection(c)
        self.assertEqual(c.mock_calls, [mock.call.registerProducer(o, True),
                                        mock.call.send_record(r1),
                                        mock.call.send_record(r2)])
        self.assertEqual(list(o._outbound_queue), [r1, r2])
        self.assertEqual(list(o._queued_unsent), [])
        clear_mock_calls(c)

        o.queue_and_send_record(r3)
        self.assertEqual(list(o._outbound_queue), [r1, r2, r3])
        self.assertEqual(list(o._queued_unsent), [])
        self.assertEqual(c.mock_calls, [mock.call.send_record(r3)])

    def test_connection_send_queued_paused(self):
        o, m, c = make_outbound()
        r1 = Pauser(seqnum=1)
        r2 = Pauser(seqnum=2)
        r3 = Pauser(seqnum=3)
        o.queue_and_send_record(r1)
        o.queue_and_send_record(r2)
        self.assertEqual(list(o._outbound_queue), [r1, r2])
        self.assertEqual(list(o._queued_unsent), [])

        # pausing=True, so our mock Manager will pause the Outbound producer
        # after each write. So only r1 should have been sent before getting
        # paused
        o.use_connection(c)
        self.assertEqual(c.mock_calls, [mock.call.registerProducer(o, True),
                                        mock.call.send_record(r1)])
        self.assertEqual(list(o._outbound_queue), [r1, r2])
        self.assertEqual(list(o._queued_unsent), [r2])
        clear_mock_calls(c)

        # Outbound is responsible for sending all records, so when Manager
        # wants to send a new one, and Outbound is still in the middle of
        # draining the beginning-of-connection queue, the new message gets
        # queued behind the rest (in addition to being queued in
        # _outbound_queue until an ACK retires it).
        o.queue_and_send_record(r3)
        self.assertEqual(list(o._outbound_queue), [r1, r2, r3])
        self.assertEqual(list(o._queued_unsent), [r2, r3])
        self.assertEqual(c.mock_calls, [])

        o.handle_ack(r1.seqnum)
        self.assertEqual(list(o._outbound_queue), [r2, r3])
        self.assertEqual(list(o._queued_unsent), [r2, r3])
        self.assertEqual(c.mock_calls, [])

    def test_premptive_ack(self):
        # one mode I have in mind is for each side to send an immediate ACK,
        # with everything they've ever seen, as the very first message on each
        # new connection. The idea is that you might preempt sending stuff from
        # the _queued_unsent list if it arrives fast enough (in practice this
        # is more likely to be delivered via the DILATE mailbox message, but
        # the effects might be vaguely similar, so it seems worth testing
        # here). A similar situation would be if each side sends ACKs with the
        # highest seqnum they've ever seen, instead of merely ACKing the
        # message which was just received.
        o, m, c = make_outbound()
        r1 = Pauser(seqnum=1)
        r2 = Pauser(seqnum=2)
        r3 = Pauser(seqnum=3)
        o.queue_and_send_record(r1)
        o.queue_and_send_record(r2)
        self.assertEqual(list(o._outbound_queue), [r1, r2])
        self.assertEqual(list(o._queued_unsent), [])

        o.use_connection(c)
        self.assertEqual(c.mock_calls, [mock.call.registerProducer(o, True),
                                        mock.call.send_record(r1)])
        self.assertEqual(list(o._outbound_queue), [r1, r2])
        self.assertEqual(list(o._queued_unsent), [r2])
        clear_mock_calls(c)

        o.queue_and_send_record(r3)
        self.assertEqual(list(o._outbound_queue), [r1, r2, r3])
        self.assertEqual(list(o._queued_unsent), [r2, r3])
        self.assertEqual(c.mock_calls, [])

        o.handle_ack(r2.seqnum)
        self.assertEqual(list(o._outbound_queue), [r3])
        self.assertEqual(list(o._queued_unsent), [r3])
        self.assertEqual(c.mock_calls, [])

    def test_pause(self):
        o, m, c = make_outbound()
        o.use_connection(c)
        self.assertEqual(c.mock_calls, [mock.call.registerProducer(o, True)])
        self.assertEqual(list(o._outbound_queue), [])
        self.assertEqual(list(o._queued_unsent), [])
        clear_mock_calls(c)

        sc1, sc2, sc3 = object(), object(), object()
        p1, p2, p3 = mock.Mock(name="p1"), mock.Mock(name="p2"), mock.Mock(name="p3")

        # we aren't paused yet, since we haven't sent any data
        o.subchannel_registerProducer(sc1, p1, True)
        self.assertEqual(p1.mock_calls, [])

        r1 = Pauser(seqnum=1)
        o.queue_and_send_record(r1)
        # now we should be paused
        self.assertTrue(o._paused)
        self.assertEqual(c.mock_calls, [mock.call.send_record(r1)])
        self.assertEqual(p1.mock_calls, [mock.call.pauseProducing()])
        clear_mock_calls(p1, c)

        # so an IPushProducer will be paused right away
        o.subchannel_registerProducer(sc2, p2, True)
        self.assertEqual(p2.mock_calls, [mock.call.pauseProducing()])
        clear_mock_calls(p2)

        o.subchannel_registerProducer(sc3, p3, True)
        self.assertEqual(p3.mock_calls, [mock.call.pauseProducing()])
        self.assertEqual(o._paused_producers, set([p1, p2, p3]))
        self.assertEqual(list(o._all_producers), [p1, p2, p3])
        clear_mock_calls(p3)

        # one resumeProducing should cause p1 to get a turn, since p2 was added
        # after we were paused and p1 was at the "end" of a one-element list.
        # If it writes anything, it will get paused again immediately.
        r2 = Pauser(seqnum=2)
        p1.resumeProducing.side_effect = lambda: c.send_record(r2)
        o.resumeProducing()
        self.assertEqual(p1.mock_calls, [mock.call.resumeProducing(),
                                         mock.call.pauseProducing(),
                                         ])
        self.assertEqual(p2.mock_calls, [])
        self.assertEqual(p3.mock_calls, [])
        self.assertEqual(c.mock_calls, [mock.call.send_record(r2)])
        clear_mock_calls(p1, p2, p3, c)
        # p2 should now be at the head of the queue
        self.assertEqual(list(o._all_producers), [p2, p3, p1])

        # next turn: p2 has nothing to send, but p3 does. we should see p3
        # called but not p1. The actual sequence of expected calls is:
        # p2.resume, p3.resume, pauseProducing, set(p2.pause, p3.pause)
        r3 = Pauser(seqnum=3)
        p2.resumeProducing.side_effect = lambda: None
        p3.resumeProducing.side_effect = lambda: c.send_record(r3)
        o.resumeProducing()
        self.assertEqual(p1.mock_calls, [])
        self.assertEqual(p2.mock_calls, [mock.call.resumeProducing(),
                                         mock.call.pauseProducing(),
                                         ])
        self.assertEqual(p3.mock_calls, [mock.call.resumeProducing(),
                                         mock.call.pauseProducing(),
                                         ])
        self.assertEqual(c.mock_calls, [mock.call.send_record(r3)])
        clear_mock_calls(p1, p2, p3, c)
        # p1 should now be at the head of the queue
        self.assertEqual(list(o._all_producers), [p1, p2, p3])

        # next turn: p1 has data to send, but not enough to cause a pause. same
        # for p2. p3 causes a pause
        r4 = NonPauser(seqnum=4)
        r5 = NonPauser(seqnum=5)
        r6 = Pauser(seqnum=6)
        p1.resumeProducing.side_effect = lambda: c.send_record(r4)
        p2.resumeProducing.side_effect = lambda: c.send_record(r5)
        p3.resumeProducing.side_effect = lambda: c.send_record(r6)
        o.resumeProducing()
        self.assertEqual(p1.mock_calls, [mock.call.resumeProducing(),
                                         mock.call.pauseProducing(),
                                         ])
        self.assertEqual(p2.mock_calls, [mock.call.resumeProducing(),
                                         mock.call.pauseProducing(),
                                         ])
        self.assertEqual(p3.mock_calls, [mock.call.resumeProducing(),
                                         mock.call.pauseProducing(),
                                         ])
        self.assertEqual(c.mock_calls, [mock.call.send_record(r4),
                                        mock.call.send_record(r5),
                                        mock.call.send_record(r6),
                                        ])
        clear_mock_calls(p1, p2, p3, c)
        # p1 should now be at the head of the queue again
        self.assertEqual(list(o._all_producers), [p1, p2, p3])

        # now we let it catch up. p1 and p2 send non-pausing data, p3 sends
        # nothing.
        r7 = NonPauser(seqnum=4)
        r8 = NonPauser(seqnum=5)
        p1.resumeProducing.side_effect = lambda: c.send_record(r7)
        p2.resumeProducing.side_effect = lambda: c.send_record(r8)
        p3.resumeProducing.side_effect = lambda: None

        o.resumeProducing()
        self.assertEqual(p1.mock_calls, [mock.call.resumeProducing(),
                                         ])
        self.assertEqual(p2.mock_calls, [mock.call.resumeProducing(),
                                         ])
        self.assertEqual(p3.mock_calls, [mock.call.resumeProducing(),
                                         ])
        self.assertEqual(c.mock_calls, [mock.call.send_record(r7),
                                        mock.call.send_record(r8),
                                        ])
        clear_mock_calls(p1, p2, p3, c)
        # p1 should now be at the head of the queue again
        self.assertEqual(list(o._all_producers), [p1, p2, p3])
        self.assertFalse(o._paused)

        # now a producer disconnects itself (spontaneously, not from inside a
        # resumeProducing)
        o.subchannel_unregisterProducer(sc1)
        self.assertEqual(list(o._all_producers), [p2, p3])
        self.assertEqual(p1.mock_calls, [])
        self.assertFalse(o._paused)

        # and another disconnects itself when called
        p2.resumeProducing.side_effect = lambda: None
        p3.resumeProducing.side_effect = lambda: o.subchannel_unregisterProducer(sc3)
        o.pauseProducing()
        o.resumeProducing()
        self.assertEqual(p2.mock_calls, [mock.call.pauseProducing(),
                                         mock.call.resumeProducing()])
        self.assertEqual(p3.mock_calls, [mock.call.pauseProducing(),
                                         mock.call.resumeProducing()])
        clear_mock_calls(p2, p3)
        self.assertEqual(list(o._all_producers), [p2])
        self.assertFalse(o._paused)

    def test_subchannel_closed(self):
        o, m, c = make_outbound()

        sc1 = mock.Mock()
        p1 = mock.Mock(name="p1")
        o.subchannel_registerProducer(sc1, p1, True)
        self.assertEqual(p1.mock_calls, [mock.call.pauseProducing()])
        clear_mock_calls(p1)

        o.subchannel_closed(sc1)
        self.assertEqual(p1.mock_calls, [])
        self.assertEqual(list(o._all_producers), [])

        sc2 = mock.Mock()
        o.subchannel_closed(sc2)

    def test_disconnect(self):
        o, m, c = make_outbound()
        o.use_connection(c)

        sc1 = mock.Mock()
        p1 = mock.Mock(name="p1")
        o.subchannel_registerProducer(sc1, p1, True)
        self.assertEqual(p1.mock_calls, [])
        o.stop_using_connection()
        self.assertEqual(p1.mock_calls, [mock.call.pauseProducing()])

    def OFF_test_push_pull(self):
        # use one IPushProducer and one IPullProducer. They should take turns
        o, m, c = make_outbound()
        o.use_connection(c)
        clear_mock_calls(c)

        sc1, sc2 = object(), object()
        p1, p2 = mock.Mock(name="p1"), mock.Mock(name="p2")
        r1 = Pauser(seqnum=1)
        r2 = NonPauser(seqnum=2)

        # we aren't paused yet, since we haven't sent any data
        o.subchannel_registerProducer(sc1, p1, True) # push
        o.queue_and_send_record(r1)
        # now we're paused
        self.assertTrue(o._paused)
        self.assertEqual(c.mock_calls, [mock.call.send_record(r1)])
        self.assertEqual(p1.mock_calls, [mock.call.pauseProducing()])
        self.assertEqual(p2.mock_calls, [])
        clear_mock_calls(p1, p2, c)

        p1.resumeProducing.side_effect = lambda: c.send_record(r1)
        p2.resumeProducing.side_effect = lambda: c.send_record(r2)
        o.subchannel_registerProducer(sc2, p2, False) # pull: always ready

        # p1 is still first, since p2 was just added (at the end)
        self.assertTrue(o._paused)
        self.assertEqual(c.mock_calls, [])
        self.assertEqual(p1.mock_calls, [])
        self.assertEqual(p2.mock_calls, [])
        self.assertEqual(list(o._all_producers), [p1, p2])
        clear_mock_calls(p1, p2, c)

        # resume should send r1, which should pause everything
        o.resumeProducing()
        self.assertTrue(o._paused)
        self.assertEqual(c.mock_calls, [mock.call.send_record(r1),
                                        ])
        self.assertEqual(p1.mock_calls, [mock.call.resumeProducing(),
                                         mock.call.pauseProducing(),
                                         ])
        self.assertEqual(p2.mock_calls, [])
        self.assertEqual(list(o._all_producers), [p2, p1]) # now p2 is next
        clear_mock_calls(p1, p2, c)

        # next should fire p2, then p1
        o.resumeProducing()
        self.assertTrue(o._paused)
        self.assertEqual(c.mock_calls, [mock.call.send_record(r2),
                                        mock.call.send_record(r1),
                                        ])
        self.assertEqual(p1.mock_calls, [mock.call.resumeProducing(),
                                         mock.call.pauseProducing(),
                                         ])
        self.assertEqual(p2.mock_calls, [mock.call.resumeProducing(),
                                         ])
        self.assertEqual(list(o._all_producers), [p2, p1]) # p2 still at bat
        clear_mock_calls(p1, p2, c)

    def test_pull_producer(self):
        # a single pull producer should write until it is paused, rate-limited
        # by the cooperator (so we'll see back-to-back resumeProducing calls
        # until the Connection is paused, or 10ms have passed, whichever comes
        # first, and if it's stopped by the timer, then the next EventualQueue
        # turn will start it off again)

        o, m, c = make_outbound()
        eq = o._test_eq
        o.use_connection(c)
        clear_mock_calls(c)
        self.assertFalse(o._paused)

        sc1 = mock.Mock()
        p1 = mock.Mock(name="p1")
        alsoProvides(p1, IPullProducer)

        records = [NonPauser(seqnum=1)] * 10
        records.append(Pauser(seqnum=2))
        records.append(Stopper(sc1))
        it = iter(records)
        p1.resumeProducing.side_effect = lambda: c.send_record(next(it))
        o.subchannel_registerProducer(sc1, p1, False)
        eq.flush_sync() # fast forward into the glorious (paused) future

        self.assertTrue(o._paused)
        self.assertEqual(c.mock_calls,
                         [mock.call.send_record(r) for r in records[:-1]])
        self.assertEqual(p1.mock_calls,
                         [mock.call.resumeProducing()]*(len(records)-1))
        clear_mock_calls(c, p1)

        # next resumeProducing should cause it to disconnect
        o.resumeProducing()
        eq.flush_sync()
        self.assertEqual(c.mock_calls, [mock.call.send_record(records[-1])])
        self.assertEqual(p1.mock_calls, [mock.call.resumeProducing()])
        self.assertEqual(len(o._all_producers), 0)
        self.assertFalse(o._paused)

    def test_two_pull_producers(self):
        # we should alternate between them until paused
        p1_records = ([NonPauser(seqnum=i) for i in range(5)] +
                      [Pauser(seqnum=5)] +
                      [NonPauser(seqnum=i) for i in range(6, 10)])
        p2_records = ([NonPauser(seqnum=i) for i in range(10, 19)] +
                      [Pauser(seqnum=19)])
        expected1 = [NonPauser(0), NonPauser(10),
                     NonPauser(1), NonPauser(11),
                     NonPauser(2), NonPauser(12),
                     NonPauser(3), NonPauser(13),
                     NonPauser(4), NonPauser(14),
                     Pauser(5)]
        expected2 = [              NonPauser(15),
                     NonPauser(6), NonPauser(16),
                     NonPauser(7), NonPauser(17),
                     NonPauser(8), NonPauser(18),
                     NonPauser(9), Pauser(19),
                     ]

        o, m, c = make_outbound()
        eq = o._test_eq
        o.use_connection(c)
        clear_mock_calls(c)
        self.assertFalse(o._paused)

        sc1 = mock.Mock()
        p1 = mock.Mock(name="p1")
        alsoProvides(p1, IPullProducer)
        it1 = iter(p1_records)
        p1.resumeProducing.side_effect = lambda: c.send_record(next(it1))
        o.subchannel_registerProducer(sc1, p1, False)

        sc2 = mock.Mock()
        p2 = mock.Mock(name="p2")
        alsoProvides(p2, IPullProducer)
        it2 = iter(p2_records)
        p2.resumeProducing.side_effect = lambda: c.send_record(next(it2))
        o.subchannel_registerProducer(sc2, p2, False)

        eq.flush_sync() # fast forward into the glorious (paused) future

        sends = [mock.call.resumeProducing()]
        self.assertTrue(o._paused)
        self.assertEqual(c.mock_calls,
                         [mock.call.send_record(r) for r in expected1])
        self.assertEqual(p1.mock_calls, 6*sends)
        self.assertEqual(p2.mock_calls, 5*sends)
        clear_mock_calls(c, p1, p2)

        o.resumeProducing()
        eq.flush_sync()
        self.assertTrue(o._paused)
        self.assertEqual(c.mock_calls,
                         [mock.call.send_record(r) for r in expected2])
        self.assertEqual(p1.mock_calls, 4*sends)
        self.assertEqual(p2.mock_calls, 5*sends)
        clear_mock_calls(c, p1, p2)

    def test_send_if_connected(self):
        o, m, c = make_outbound()
        o.send_if_connected(Ack(1)) # not connected yet

        o.use_connection(c)
        o.send_if_connected(KCM())
        self.assertEqual(c.mock_calls, [mock.call.registerProducer(o, True),
                                        mock.call.send_record(KCM())])

    def test_tolerate_duplicate_pause_resume(self):
        o, m, c = make_outbound()
        self.assertTrue(o._paused) # no connection
        o.use_connection(c)
        self.assertFalse(o._paused)
        o.pauseProducing()
        self.assertTrue(o._paused)
        o.pauseProducing()
        self.assertTrue(o._paused)
        o.resumeProducing()
        self.assertFalse(o._paused)
        o.resumeProducing()
        self.assertFalse(o._paused)

    def test_stopProducing(self):
        o, m, c = make_outbound()
        o.use_connection(c)
        self.assertFalse(o._paused)
        o.stopProducing() # connection does this before loss
        self.assertTrue(o._paused)
        o.stop_using_connection()
        self.assertTrue(o._paused)

    def test_resume_error(self):
        o, m, c = make_outbound()
        o.use_connection(c)
        sc1 = mock.Mock()
        p1 = mock.Mock(name="p1")
        alsoProvides(p1, IPullProducer)
        p1.resumeProducing.side_effect = PretendResumptionError
        o.subchannel_registerProducer(sc1, p1, False)
        o._test_eq.flush_sync()
        # the error is supposed to automatically unregister the producer
        self.assertEqual(list(o._all_producers), [])
        self.flushLoggedErrors(PretendResumptionError)


def make_pushpull(pauses):
    p = mock.Mock()
    alsoProvides(p, IPullProducer)
    unregister = mock.Mock()

    clock = Clock()
    eq = EventualQueue(clock)
    term = mock.Mock(side_effect=lambda: True) # one write per Eventual tick
    term_factory = lambda: term
    coop = Cooperator(terminationPredicateFactory=term_factory,
                      scheduler=eq.eventually)
    pp = PullToPush(p, unregister, coop)

    it = cycle(pauses)
    def action(i):
        if isinstance(i, Exception):
            raise i
        elif i:
            pp.pauseProducing()
    p.resumeProducing.side_effect = lambda: action(next(it))
    return p, unregister, pp, eq

class PretendResumptionError(Exception):
    pass
class PretendUnregisterError(Exception):
    pass

class PushPull(unittest.TestCase):
    # test our wrapper utility, which I copied from
    # twisted.internet._producer_helpers since it isn't publically exposed

    def test_start_unpaused(self):
        p, unr, pp, eq = make_pushpull([True]) # pause on each resumeProducing
        # if it starts unpaused, it gets one write before being halted
        pp.startStreaming(False)
        eq.flush_sync()
        self.assertEqual(p.mock_calls, [mock.call.resumeProducing()]*1)
        clear_mock_calls(p)

        # now each time we call resumeProducing, we should see one delivered to
        # the underlying IPullProducer
        pp.resumeProducing()
        eq.flush_sync()
        self.assertEqual(p.mock_calls, [mock.call.resumeProducing()]*1)

        pp.stopStreaming()
        pp.stopStreaming() # should tolerate this

    def test_start_unpaused_two_writes(self):
        p, unr, pp, eq = make_pushpull([False, True]) # pause every other time
        # it should get two writes, since the first didn't pause
        pp.startStreaming(False)
        eq.flush_sync()
        self.assertEqual(p.mock_calls, [mock.call.resumeProducing()]*2)

    def test_start_paused(self):
        p, unr, pp, eq = make_pushpull([True]) # pause on each resumeProducing
        pp.startStreaming(True)
        eq.flush_sync()
        self.assertEqual(p.mock_calls, [])
        pp.stopStreaming()

    def test_stop(self):
        p, unr, pp, eq = make_pushpull([True])
        pp.startStreaming(True)
        pp.stopProducing()
        eq.flush_sync()
        self.assertEqual(p.mock_calls, [mock.call.stopProducing()])

    def test_error(self):
        p, unr, pp, eq = make_pushpull([PretendResumptionError()])
        unr.side_effect = lambda: pp.stopStreaming()
        pp.startStreaming(False)
        eq.flush_sync()
        self.assertEqual(unr.mock_calls, [mock.call()])
        self.flushLoggedErrors(PretendResumptionError)

    def test_error_during_unregister(self):
        p, unr, pp, eq = make_pushpull([PretendResumptionError()])
        unr.side_effect = PretendUnregisterError()
        pp.startStreaming(False)
        eq.flush_sync()
        self.assertEqual(unr.mock_calls, [mock.call()])
        self.flushLoggedErrors(PretendResumptionError, PretendUnregisterError)




        
        # TODO: consider making p1/p2/p3 all elements of a shared Mock, maybe I
        # could capture the inter-call ordering that way
