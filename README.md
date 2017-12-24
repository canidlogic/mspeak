# mspeak

A very simple network communication program.

This program is capable of transmitting a stream of binary data over TCP/IP from one computer to another.

## Security considerations

There are a few important security considerations to be aware of before using this tool, especially if one is thinking of using this over the public Internet:

(1) Data is not encrypted in any way.  It is easy for other people to intercept and spy on communications done through this tool.  To prevent this, consider having a pipeline on the sender side that encrypts the data before sending through mspeak, and then a pipeline on the receiver side that decrypts the data after receiving through mspeak.  This allows the encryption program to be separate from the communication program.  Make sure that the encryption keys are transmitted through a secure channel.  (Don't just send them plain-text over mspeak!)

(2) There is no guarantee that data is not altered en route to the destination.  It is easy to pull a man-in-the-middle attack on communication here and alter messages in any way.  To prevent this, consider having a pipeline as described above from encryption, and add a pipeline stage that runs the data through a cryptographic message digest such as SHA-256.  Then, compare the digest on the received data to the digest on the sent data through a separate, secure channel to make sure nothing was altered.

(3) There is no guarantee that the other party the program is communicating with is the party the program thinks it is communicating with.  Using encryption and message digests as described above, and talking directly with the other party through a secure channel to confirm transmission and matching message digests can help in this regard.

(4) This is not an exhaustive security review of the application.  If security is important, think carefully before using this program, or use a more inherently secure alternative, such as SSH or SCP.

## Operation

In order to transmit data successfully through mspeak, the following conditions must be satisfied:

(1) Each mspeak connection must be between two separate mspeak instances.

(2) One of these instances must be in "read" mode while the other instance must be in "write" mode.

(3) One of these instances must be in "client" mode while the other instance must be in "server" mode.

(4) The "server" instance must be started and listening for a connection before the "client" instance is started.

(5) The "server" instance must be listening on an IP address and port that is valid on the server machine and accessible to the "client" instance.

(6) If the "server" instance is listening on a low-numbered port, then it may need to be started in superuser mode for the operation to be allowed.

Note that the read/write modes are separate from the client/server modes.  Hence, the server may read or write, and the client may write or read.

To use mspeak, invoke with the following syntax:

> mspeak sr 192.168.1.10:32

The "sr" parameter must consist of exactly two characters.  One of these characters must be "s" or "c" indicating server or client mode, and the other character must be "r" or "w" indicating read or write mode.  The two characters can be in any order.

In "server" modes only, an additional character "h" can optionally be added.  This is the "fake HTTP" switch.  This allows mspeak to pretend to be an HTTP server, even though it isn't.  This fake implementation might be good enough to be able to download and upload files through a normal web browser with mspeak on the other end.  The specifics are described below.

In fake HTTP write mode ("swh"), the server will read from the client until two line breaks (defined as LF characters when CR characters are filtered out) in a row are received.  At that point, the mspeak program will write all the information, as usual.  If the written information passed to mspeak begins with HTTP headers, this may allow an HTTP client (such as a normal web browser) to receive a single file from mspeak.  This is useful, for example, to transmit the mspeak source code or program binary to a system that only has a normal web browser, after which the received mspeak can be used for further communication.  Note, however, that mspeak is not actually an HTTP server, so this method isn't guaranteed to work.  For example, it won't correctly handle an HTTP/0.9 request.  See the application "httpbin" for a way to frame binary data within an HTTP response.

The 192.168.1.10:32 in the syntax example above is the IPv4 address (192.168.1.10) and port (32).  Platform-specific translation services are used to convert the given address into an address and port combination to be used for the actual connection.  In "server" mode, the address and port indicate the address and port on the local machine to listen for incoming connections on, while in "client" mode, the address and port indicate the address and port on the remote machine to connect to.

The server will accept exactly one connection from a client.  To stop the server from waiting for a client, use a system-specific break, such as CTRL+C.

The instance that is in "read" mode will output all the data it receives to standard output.  This can be piped into a file, or piped to other programs (see security considerations above).  The instance that is in "write" mode will input data from standard input and send it over the connection.  This can be piped from a file, or piped from other programs (see security considerations above).

In a broad sense, mspeak acts like a link in a pipeline that transmits the pipeline to a remote machine (over a very insecure channel!).

## Build notes

On Windows, ws2_32.lib must be linked in for access to the Windows platform implementation of sockets.  Also, this program must be built in ANSI mode for console use.  (Unicode wouldn't add anything, as no functions with functional Unicode alternatives are used.)  64-bit builds should be supported, despite all the "32" labels everywhere.
