from __future__ import print_function, unicode_literals
import mock
from zope.interface import alsoProvides
from twisted.trial import unittest
from twisted.internet.task import Clock
from twisted.internet.interfaces import ITransport
from twisted.internet.error import ConnectionDone
from ..eventual import EventualQueue
from wormhole._interfaces import (IDilationManager, IDilationConnector,
                                  IWormhole, ISubChannel)
from wormhole._dilation.roles import LEADER, FOLLOWER
from wormhole._dilation.encode import to_be4, from_be4
from wormhole._dilation.subchannel import (Once, SubChannel,
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
        self.assertEqual(parse_record(b"\x03scidseqn"),
                         Open(scid=b"scid", seqnum=b"seqn"))
        self.assertEqual(parse_record(b"\x04scidseqndataaa"),
                         Data(scid=b"scid", seqnum=b"seqn", data=b"dataaa"))
        self.assertEqual(parse_record(b"\x05scidseqn"),
                         Close(scid=b"scid", seqnum=b"seqn"))
        self.assertEqual(parse_record(b"\x06seqn"),
                         Ack(resp_seqnum=b"seqn"))
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
        self.assertEqual(encode_record(Open(scid=b"scid", seqnum=b"seqn")),
                         b"\x03scidseqn")
        self.assertEqual(encode_record(Data(scid=b"scid", seqnum=b"seqn",
                                            data=b"dataaa")),
                         b"\x04scidseqndataaa")
        self.assertEqual(encode_record(Close(scid=b"scid", seqnum=b"seqn")),
                         b"\x05scidseqn")
        self.assertEqual(encode_record(Ack(resp_seqnum=b"seqn")),
                         b"\x06seqn")
        with self.assertRaises(TypeError) as ar:
            encode_record("not a record")
        self.assertEqual(str(ar.exception), "not a record")

from noise.exceptions import NoiseInvalidMessage

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

def clear_mock_calls(n, connector, t, m=None):
    n.mock_calls[:] = []
    connector.mock_calls[:] = []
    t.mock_calls[:] = []
    if m:
        m.mock_calls[:] = []

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
        t_open = Open(seqnum=b"\x00\x01\x02\x03", scid=b"\x11\x22\x33\x44")
        t_ack = Ack(resp_seqnum=b"\x55\x66\x77\x88")
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
        exp_ack = b"\x06\x55\x66\x77\x88"
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
