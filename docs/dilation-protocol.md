
The side with the lexicographically-higher "side" value is named the
"Leader". The other side is named the "Follower". The general wormhole
protocol treats both sides identically, but the distinction matters for the
dilation protocol. Either side can trigger dilation, but the Follower does so
by asking the Leader to start the process, whereas the Leader just starts the
process unilaterally. The Leader has exclusive control over whether a given
connection is considered established or not: if there are multiple potential
connections to use, the Leader decides which one to use, and the Leader gets
to decide when the connection is no longer viable (and triggers the
establishment of a new one).

L1 is the mailbox channel. Both clients remain connected to the mailbox
server, and send DILATE(gen=N) and PLEASE-DILATE() messages through the
mailbox. They also send HINTS(gen=N) messages through the mailbox to find
each other.

L2 is the set of competing connection attempts for a given generation of
connection. Each time the Leader decides to establish a new connection, a new
generation number is used. Hopefully these are direct TCP connections between
the two peers, but they may also include connections through the transit
relay. Each connection must go through a handshake process before it is
considered viable. Viable connections are then submitted to a selection
process (on the Leader side), which chooses exactly one to use, and drops the
others. It may wait an extra few seconds in the hopes of getting a "better"
connection (faster, cheaper, etc), but eventually it will select one.

L3 is the current selected connection. At all times, the wormhole will have
exactly zero or one L3 connection. Each L3 uses a distinct Noise session
(started during the handshake process), using the NNpsk0 pattern, with the
Leader as the first party ("-> psk, e" in the Noise spec), and the Follower
as the second ("<- e, ee").

L4 is the persistent higher-level channel. It is created as soon as the first
L3 connection is selected, and lasts until wormhole is closed entirely. L4
contains OPEN/DATA/CLOSE/ACK messages: OPEN/DATA/CLOSE have a sequence number
(scoped to the L4 connection and the direction of travel), and the ACK
messages reference those sequence numbers. When a message is given to the L4
channel for delivery to the remote side, it is always queued, then
transmitted if there is an L3 connection available. This message remains in
the queue until an ACK is received to release it. If a new L3 connection is
made, all queued messages will be re-sent (in seqnum order).

L5 are subchannels. There is one pre-established subchannel 0 known as the
"control channel", which does not require an OPEN message. All other
subchannels are created by the receipt of an OPEN message with the subchannel
number. DATA frames are delivered to a specific subchannel. When the
subchannel is no longer needed, one side will invoke the ``close()`` API
(``loseConnection()`` in Twisted), which will cause a CLOSE message to be
sent, and the local L5 object will be put into the "closing "state. When the
other side receives the CLOSE, it will send its own CLOSE for the same
subchannel, and fully close its local object (``connectionLost()``). When the
first side receives CLOSE in the "closing" state, it will fully close its
local object too.

All L5 subchannels will be paused (``pauseProducing()``) when the L3
connection is paused or lost. They are resumed when the L3 connection is
resumed or reestablished.

## L2 protocol

Upon ``connectionMade()``, both sides send their handshake message. The
Leader sends "Magic-Wormhole Dilation Handshake v1 Leader\n\n". The Follower
sends "Magic-Wormhole Dilation Handshake v1 Follower\n\n". This should
trigger an immediate error for most non-magic-wormhole listeners (e.g. HTTP
servers that were contacted by accident). If the wrong handshake is received,
the connection will be dropped. For debugging purposes, the node might want
to keep looking at data beyond the first incorrect character and log
everything until the first newline.

Everything beyond that point is a Noise protocol message, which use a 4-byte
big-endian length field, followed by some number of bytes. The Leader sends
the first message, which is a psk-encrypted ephemeral key. The Follower sends
the next message, its own psk-encrypted ephemeral key. The Follower then
sends an empty packet as the "key confirmation message", which will be
encrypted by the shared key.

The Leader sees the KCM and knows the connection is viable. It delivers the
protocol object to the Dilation manager, which will decide which connection
to select. When the L2 connection is selected to be the new L3, it will send
an empty KCM of its own, to let the Follower know the connection being
selected. All other L2 connections (either viable or still in handshake) are
dropped, all other connection attempts are cancelled, and all listening
sockets are shut down.

The Follower will wait for either an empty KCM (at which point the L2
connection is delivered to the Dilation manager as the new L3), a
disconnection, or an invalid message (which causes the connection to be
dropped). Other connections and/or listening sockets are stopped.

## L4 protocol

The L4 protocol manages a durable stream of OPEN/DATA/CLOSE/ACK messages.
Each is enclosed in a Noise frame, so they do not need length fields or other
framing.

Subchannel numbers are 4-byte big-endian integers, and are present in
OPEN/DATA/CLOSE but not ACK. Sequence numbers are 4-byte big-endian integers
and are present in OPEN/DATA/CLOSE. Acknowledged sequence numbers are also
4-byte big-endian integers and are only present in ACK messages: they refer
to the seqnum in a matching OPEN/DATA/CLOSE from the other direction, rather
than indicating anything about the ACK message itself. ACKs are not acked.

All L4 messages are retained until a matching ACK from the other side has
been received. If there is no L3 connection available when the L4 message is
presented for transmission, it will be queued until one becomes available.
Consequently the L4 ``send()`` function always appends the message onto a
double-ended queue, and additionally sends it if an L3 connection is present.
If and when the ACK arrives, the message is removed from the other end. On
any given L3 connection, all messages are sent in-order.

