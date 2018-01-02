from twisted.trial import unittest
from wormhole._transit import noncebuf

class Encoding(unittest.TestCase):
    def test_noncebuf(self):
        self.assertEqual(noncebuf(0), b"\x00"*24)
        self.assertEqual(noncebuf(1), b"\x01" + b"\x00"*23)
        self.assertEqual(noncebuf(2), b"\x02" + b"\x00"*23)
        self.assertEqual(noncebuf(256), b"\x00\x01" + b"\x00"*22)
        self.assertEqual(noncebuf(257), b"\x01\x01" + b"\x00"*22)
        with self.assertRaises(ValueError):
            noncebuf(-1)
        with self.assertRaises(ValueError):
            noncebuf(2**32)

    def test_le4(self):
        self.assertEqual(le4(0),   b"\x00\x00\x00\x00")
        self.assertEqual(le4(1),   b"\x01\x00\x00\x00")
        self.assertEqual(le4(256), b"\x00\x01\x00\x00")
        self.assertEqual(le4(257), b"\x01\x01\x00\x00")
        with self.assertRaises(ValueError):
            le4(-1)
        with self.assertRaises(ValueError):
            le4(2**32)

    def test_le8(self):
        self.assertEqual(le8(0),       b"\x00\x00\x00\x00\x00\x00\x00\x00")
        self.assertEqual(le8(1),       b"\x01\x00\x00\x00\x00\x00\x00\x00")
        self.assertEqual(le8(256),     b"\x00\x01\x00\x00\x00\x00\x00\x00")
        self.assertEqual(le8(257),     b"\x01\x01\x00\x00\x00\x00\x00\x00")
        self.assertEqual(le8(2**32),   b"\x00\x00\x00\x00\x01\x00\x00\x00")
        self.assertEqual(le8(2**32+1), b"\x01\x00\x00\x00\x01\x00\x00\x00")
        with self.assertRaises(ValueError):
            le8(-1)
        with self.assertRaises(ValueError):
            le8(2**64)

