/*
 * mspeak.c
 *
 * A very simple network communication program.
 *
 * This program is capable of transmitting a stream of binary data over
 * TCP/IP from one computer to another.
 *
 * There are a few important security considerations to be aware of
 * before using this tool, especially if one is thinking of using this
 * over the public Internet:
 *
 * (1) Data is not encrypted in any way.  It is easy for other people to
 *     intercept and spy on communications done through this tool.  To
 *     prevent this, consider having a pipeline on the sender side that
 *     encrypts the data before sending through mspeak, and then a
 *     pipeline on the receiver side that decrypts the data after
 *     receiving through mspeak.  This allows the encryption program to
 *     be separate from the communication program.  Make sure that the
 *     encryption keys are transmitted through a secure channel.  (Don't
 *     just send them plain-text over mspeak!)
 *
 * (2) There is no guarantee that data is not altered en route to the
 *     destination.  It is easy to pull a man-in-the-middle attack on
 *     communication here and alter messages in any way.  To prevent
 *     this, consider having a pipeline as described above from
 *     encryption, and add a pipeline stage that runs the data through
 *     a cryptographic message digest such as SHA-256.  Then, compare
 *     the digest on the received data to the digest on the sent data
 *     through a separate, secure channel to make sure nothing was
 *     altered.
 *
 * (3) There is no guarantee that the other party the program is
 *     communicating with is the party the program thinks it is
 *     communicating with.  Using encryption and message digests as
 *     described above, and talking directly with the other party
 *     through a secure channel to confirm transmission and matching
 *     message digests can help in this regard.
 *
 * (4) This is not an exhaustive security review of the application.  If
 *     security is important, think carefully before using this program,
 *     or use a more inherently secure alternative, such as SSH or SCP.
 *
 * In order to transmit data successfully through mspeak, the following
 * conditions must be satisfied:
 *
 * (1) Each mspeak connection must be between two separate mspeak
 *     instances.
 *
 * (2) One of these instances must be in "read" mode while the other
 *     instance must be in "write" mode.
 *
 * (3) One of these instances must be in "client" mode while the other
 *     instance must be in "server" mode.
 *
 * (4) The "server" instance must be started and listening for a
 *     connection before the "client" instance is started.
 *
 * (5) The "server" instance must be listening on an IP address and port
 *     that is valid on the server machine and accessible to the
 *     "client" instance.
 *
 * (6) If the "server" instance is listening on a low-numbered port,
 *     then it may need to be started in superuser mode for the
 *     operation to be allowed.
 *
 * Note that the read/write modes are separate from the client/server
 * modes.  Hence, the server may read or write, and the client may write
 * or read.
 *
 * To use mspeak, invoke with the following syntax:
 *
 *   mspeak sr 192.168.1.10:32
 *
 * The "sr" parameter must consist of exactly two characters.  One of
 * these characters must be "s" or "c" indicating server or client mode,
 * and the other character must be "r" or "w" indicating read or write
 * mode.  The two characters can be in any order.
 *
 * In "server" modes only, an additional character "h" can optionally be
 * added.  This is the "fake HTTP" switch.  This allows mspeak to
 * pretend to be an HTTP server, even though it isn't.  This fake
 * implementation might be good enough to be able to download and upload
 * files through a normal web browser with mspeak on the other end.  The
 * specifics are described below.
 *
 * In fake HTTP write mode ("swh"), the server will read from the client
 * until two line breaks (defined as LF characters when CR characters
 * are filtered out) in a row are received.  At that point, the mspeak
 * program will write all the information, as usual.  If the written
 * information passed to mspeak begins with HTTP headers, this may allow
 * an HTTP client (such as a normal web browser) to receive a single
 * file from mspeak.  This is useful, for example, to transmit the
 * mspeak source code or program binary to a system that only has a
 * normal web browser, after which the received mspeak can be used for
 * further communication.  Note, however, that mspeak is not actually an
 * HTTP server, so this method isn't guaranteed to work.  For example,
 * it won't correctly handle an HTTP/0.9 request.  See the application
 * "httpbin" for a way to frame binary data within an HTTP response.
 *
 * The 192.168.1.10:32 in the syntax example above is the IPv4 address
 * (192.168.1.10) and port (32).  Platform-specific translation services
 * are used to convert the given address into an address and port
 * combination to be used for the actual connection.  In "server" mode,
 * the address and port indicate the address and port on the local
 * machine to listen for incoming connections on, while in "client"
 * mode, the address and port indicate the address and port on the
 * remote machine to connect to.
 *
 * The server will accept exactly one connection from a client.  To stop
 * the server from waiting for a client, use a system-specific break,
 * such as CTRL+C.
 *
 * The instance that is in "read" mode will output all the data it
 * receives to standard output.  This can be piped into a file, or piped
 * to other programs (see security considerations above).  The instance
 * that is in "write" mode will input data from standard input and send
 * it over the connection.  This can be piped from a file, or piped from
 * other programs (see security considerations above).
 *
 * In a broad sense, mspeak acts like a link in a pipeline that
 * transmits the pipeline to a remote machine (over a very insecure
 * channel!).
 *
 * ---------------------------------------------------------------------
 * NOTE:  On Windows, ws2_32.lib must be linked in for access to the
 * Windows platform implementation of sockets.  Also, this program
 * must be built in ANSI mode for console use.  (Unicode wouldn't add
 * anything, as no functions with functional Unicode alternatives are
 * used.)  64-bit builds should be supported, despite all the "32"
 * labels everywhere.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Windows-specific includes
 */
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#endif

/*
 * POSIX-specific includes
 */
#ifndef _WIN32
#include <netdb.h>
#include <sys/socket.h>
#endif

/*
 * If on Windows, verify we're not building for Unicode.
 */
#ifdef _WIN32
#ifdef UNICODE
#error Unicode builds not supported!
#endif
#ifdef _UNICODE
#error Unicode builds not supported!
#endif
#endif

/*
 * Constants
 * =========
 */

/*
 * Size in bytes of the buffer used for I/O across the socket.
 *
 * This is dynamically allocated, so it can be quite large.
 */
#define IOBUFSIZE 4096

/*
 * ASCII constants.
 */
#define ASCII_CR (0x0D)
#define ASCII_LF (0x0A)

/*
 * The maximum size, including terminating null, that a numeric address
 * and port combination may be in characters.
 */
#define MAXAPSIZE 32

/*
 * Local function prototypes
 * =========================
 */

/*
 * Look up a given numeric address string and map it to a socket
 * address.
 *
 * This only supports IPv4 addresses (with port).  If successful, the
 * decoded IPv4 address will be written into pAddr.  If failure, the
 * state of *pAddr is undefined.  Note that sockaddr_in is a type of
 * sockaddr that can be used with socket functions.
 *
 * On POSIX, this uses getaddrinfo with NI_NUMERICHOST used to limit
 * addresses to numeric type.  On Windows, this uses inet_addr to decode
 * the IP address and then manually decodes the port and fills in the
 * address structure.  If multiple possible addresses are returned by
 * getaddrinfo on POSIX, only the first matching address is used.
 *
 * Parameters:
 *
 *   pAddrStr - the string to translate
 *
 *   pAddr - the socket address to receive the decoded address if
 *   successful
 *
 * Return:
 *
 *   non-zero if successful, zero if error
 *
 * Faults:
 *
 *   - If pAddrStr or pAddr is NULL
 *
 * Undefined behavior:
 *
 *   - If the address string is not null terminated
 *
 *   - If on Windows the Windows Sockets DLL hasn't been loaded with
 *     WSAStartup
 */
static int lookup(const char *pAddrStr, struct sockaddr_in *pAddr);

/*
 * Perform the "mspeak" function.
 *
 * The server flag indicates whether to operate in server mode or client
 * mode.  The write flag indicates whether to operate in write mode or
 * read mode.  pAddrStr points to a string specifying an IPv4 address
 * and port.  See the program documentation at the top of this source
 * file for further information.
 *
 * The fh flag indicates that "fake HTTP" mode should be activated, as
 * described in the program documentation at the top of this source
 * file.  It may only be used when the server and write flags are set.
 *
 * Errors will be reported directly using stderr.  Data will be read or
 * written with standard input and standard output when appropriate.
 *
 * Parameters:
 *
 *   server - non-zero if in server mode, zero if in client mode
 *
 *   write - non-zero if in write mode, zero if in read mode
 *
 *   fh - non-zero if in fake HTTP mode, zero if not
 *
 *   pAddrStr - pointer to the IPv4 address/port string
 *
 * Return:
 *
 *   non-zero if success, zero if failure
 *
 * Faults:
 *
 *   - If pAddrStr is NULL
 *
 *   - If fake HTTP mode is specified when in client or reading mode
 *
 * Undefined behavior:
 *
 *   - If the address string is not null terminated
 *
 *   - If on Windows the Windows Sockets DLL hasn't been loaded with
 *     WSAStartup
 */
static int mspeak(int server, int write, int fh, const char *pAddrStr);

/*
 * Local function implementations
 * ==============================
 */

/*
 * lookup function.
 */
static int lookup(const char *pAddrStr, struct sockaddr_in *pAddr) {
  int          status          = 1   ;
  const char * pc              = NULL;
  char *       pw              = NULL;
  char         abuf[MAXAPSIZE]       ;
  char         pbuf[MAXAPSIZE]       ;
#ifdef _WIN32
/* WIN32-specific --------------------------------------------------- */
  unsigned long  ulipaddr = 0;
  unsigned short usport   = 0;
  int            c        = 0;
/* ================================================================== */
#endif
#ifndef _WIN32
/* POSIX-specific --------------------------------------------------- */
  struct addrinfo   hint       ;
  struct addrinfo * pi   = NULL;
/* ================================================================== */
#endif

#ifndef _WIN32
/* POSIX-specific --------------------------------------------------- */

  /* Initialize structures */
  memset(&hint, 0, sizeof(struct addrinfo));

/* ================================================================== */
#endif

  /* Initialize buffers */
  memset(abuf, 0, MAXAPSIZE);
  memset(pbuf, 0, MAXAPSIZE);

  /* Check parameters */
  if ((pAddrStr == NULL) || (pAddr == NULL)) {
    abort();
  }

  /* Make sure passed address doesn't exceed one less than MAXAPSIZE
   * so that it will fit within the buffers */
  if (status) {
    if (strlen(pAddrStr) > (MAXAPSIZE - 1)) {
      status = 0;
    }
  }

  /* Split the address string into numeric address and port components
   * across a colon character -- first get the numeric address */
  if (status) {
    /* Copy everything up to colon or end of string into abuf --
     * this won't overflow because we verified total size
     * previously */
    pw = abuf;
    for(pc = pAddrStr; (*pc != 0) && (*pc != ':'); pc++) {
      *pw = *pc;
      pw++;
    }

    /* Make sure we stopped on a colon character, consuming it if we
     * did and failing otherwise */
    if (*pc == ':') {
      pc++;
    } else {
      status = 0;
    }
  }

  /* Now get the port */
  if (status) {
    pw = pbuf;
    for( ; *pc != 0; pc++) {
      *pw = *pc;
      pw++;
    }
  }

  /* Fail if either field is empty or contains characters apart from
   * the dot (address buffer only) or ASCII decimal digits */
  if (status) {
    /* Check for empty fields */
    if ((abuf[0] == 0) || (pbuf[0] == 0)) {
      status = 0;
    }

    /* Check character ranges */
    if (status) {
      for(pc = abuf; *pc != 0; pc++) {
        if ((*pc != '.') && ((*pc < '0') || (*pc > '9'))) {
          status = 0;
        }
      }
    }

    if (status) {
      for(pc = pbuf; *pc != 0; pc++) {
        if ((*pc < '0') || (*pc > '9')) {
          status = 0;
        }
      }
    }
  }

#ifdef _WIN32
/* WIN32-specific --------------------------------------------------- */

  /* Translate the address buffer into an IP address */
  if (status) {
    ulipaddr = inet_addr(abuf);
    if (ulipaddr == INADDR_NONE) {
      status = 0;
    }
  }

  /* Manually translate the port buffer into a port number */
  if (status) {
    /* Read each character in the port buffer */
    usport = 0;
    for(pc = pbuf; *pc != 0; pc++) {
      /* Multiply port value by 10, watching out for overflow */
      if (usport <= (0xffff / 10)) {
        usport *= (unsigned short) 10;
      } else {
        status = 0;
      }

      /* Translate current character into decimal value */
      if (status) {
        if ((*pc >= '0') && (*pc <= '9')) {
          c = (*pc) - '0';
        } else {
          status = 0;
        }
      }

      /* Add the decimal value into the port */
      if (status) {
        usport += (unsigned short) c;
      }

      /* If there was an error, break */
      if (!status) {
        break;
      }
    }
  }

  /* Change the port number into network byte order */
  if (status) {
    usport = htons(usport);
  }

  /* Manually fill in the address structure */
  if (status) {
    memset(pAddr, 0, sizeof(struct sockaddr_in));
    pAddr->sin_family           = (short) AF_INET ;
    pAddr->sin_port             =         usport  ;
    pAddr->sin_addr.S_un.S_addr =         ulipaddr;
  }

/* ================================================================== */
#endif

#ifndef _WIN32
/* POSIX-specific --------------------------------------------------- */

  /* Set the hint structure */
  if (status) {
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_NUMERICHOST;
    hint.ai_protocol = IPPROTO_TCP;
  }

  /* Attempt to translate the address */
  if (status) {
    if (getaddrinfo(abuf, pbuf, &hint, &pi)) {
      status = 0;
    }
  }

  /* If translation was successful, make sure address length matches
   * passed address structure */
  if (status) {
    if (pi->ai_addrlen != sizeof(struct sockaddr_in)) {
      status = 0;
    }
  }

  /* If we're still good, copy the address to the result and free the
   * lookup structures */
  if (status) {
    memcpy(pAddr, pi->ai_addr, sizeof(struct sockaddr_in));
    freeaddrinfo(pi);
    pi = NULL;
  }

/* ================================================================== */
#endif

  /* Return status */
  return status;
}

/*
 * mspeak function.
 */
static int mspeak(int server, int write, int fh, const char *pAddrStr) {

  int                status =  1            ;
  int                conup  =  0            ;
  struct sockaddr_in sai                    ;
  char *             iobuf  = NULL          ;
  int                rcount =  0            ;
  int                lf_flg =  0            ;
  int                ht_brk =  0            ;
  int                i      =  0            ;
#ifdef _WIN32
  SOCKET             sock   = INVALID_SOCKET;
  SOCKET             sserv  = INVALID_SOCKET;
#else
  int                sock   = -1            ;
  int                sserv  = -1            ;
#endif

  /* Initialize structures */
  memset(&sai, 0, sizeof(struct sockaddr_in));

  /* Check parameters */
  if (pAddrStr == NULL) {
    abort();
  }

  if (fh && ((!server) || (!write))) {
    abort();
  }

  /* First off, we need to translate the address string into a socket
   * address */
  if (status) {
    if (!lookup(pAddrStr, &sai)) {
      fprintf(stderr, "Address is not valid!\n");
      status = 0;
    }
  }

  /* Next, get a socket for communication */
  if (status) {
    sock = socket(AF_INET, SOCK_STREAM, 0);

#ifdef _WIN32
    if (sock == INVALID_SOCKET) {
      status = 0;
    }
#else
    if (sock == -1) {
      status = 0;
    }
#endif

    if (!status) {
      fprintf(stderr, "Could not open a socket!\n");
    }
  }

  /* If we're in server mode, the current socket will just be used to
   * listen and accept a request, and another socket will do the
   * actual communication -- in this case, copy the currently opened
   * socket to sserv and blank out the main socket again */
  if (status && server) {
    sserv = sock;
#ifdef _WIN32
    sock = INVALID_SOCKET;
#else
    sock = -1;
#endif
  }

  /* Furthermore, in server mode, set the SO_REUSEADDR option on the
   * socket to allow reuse of addresses -- this is recommended on
   * p. 580 of Advanced Programming in the UNIX Environment, 2nd ed.,
   * by W. Richard Stevens and Stephen A. Rago, to handle a quirk of
   * TCP */
  if (status && server) {
    i = 1;
    if (setsockopt(
        sserv,
        SOL_SOCKET,
        SO_REUSEADDR,
#ifdef _WIN32
        (const char *) &i,
        (int) sizeof(int)
#else
        &i,
        (socklen_t) sizeof(int)
#endif
      )) {
      fprintf(stderr, "Could not set server socket options!\n");
      status = 0;
    }
  }

  /* We need to connect with the other instance now -- this depends on
   * whether we are in server or client mode */
  if (status && server) {
    /* Server mode -- first we need to bind the server socket */
    if (bind(
        sserv,
        (const struct sockaddr *) &sai,
#ifdef _WIN32
        (int) sizeof(struct sockaddr_in)
#else
        (socklen_t) sizeof(struct sockaddr_in)
#endif
        )) {
      fprintf(stderr,
        "Could not bind server socket to address!\n");
      status = 0;
    }

    /* Next, put the server socket in listening mode */
    if (status) {
      if (listen(sserv, 1)) {
        fprintf(stderr,
          "Could not listen for incoming connections!\n");
        status = 0;
      }
    }

    /* Next, wait for a client connection and open the main socket
     * for that connection */
    if (status) {
      sock = accept(sserv, NULL, NULL);
#ifdef _WIN32
      if (sock == INVALID_SOCKET) {
        status = 0;
      }
#else
      if (sock == -1) {
        status = 0;
      }
#endif

      /* If we're okay here, set the conup flag indicating
       * connection is active; else, report error */
      if (status) {
        conup = 1;
      } else {
        fprintf(stderr,
          "Could not accept the incoming connection!\n");
        status = 0;
      }
    }

    /* Finally, regardless of whether we succeeded or not, close the
     * server socket as we won't be accepting any further
     * connections */
#ifdef _WIN32
    if (closesocket(sserv)) {
      fprintf(stderr, "Warning:  problem closing socket.\n");
    }
    sserv = INVALID_SOCKET;
#else
    if (close(sserv)) {
      fprintf(stderr, "Warning:  problem closing socket.\n");
    }
    sserv = -1;
#endif

  } else if (status && (!server)) {
    /* Client mode -- use connect() on sock */
    if (connect(
        sock,
        (const struct sockaddr *) &sai,
#ifdef _WIN32
        (int) sizeof(struct sockaddr_in)
#else
        (socklen_t) sizeof(struct sockaddr_in)
#endif
        )) {
      fprintf(stderr, "Could not connect to server!\n");
      status = 0;
    }

    /* If succeeded, set flag indicating connection is up */
    if (status) {
      conup = 1;
    }
  }

  /* Allocate the I/O buffer */
  if (status) {
    iobuf = (char *) malloc(IOBUFSIZE);
    if (iobuf == NULL) {
      fprintf(stderr, "Couldn't allocate I/O buffer!\n");
      status = 0;
    }
    if (status) {
      memset(iobuf, 0, IOBUFSIZE);
    }
  }

  /* We've got sock connected and ready for I/O with the other party
   * and our I/O buffer -- our first step is if we are in fake HTTP
   * mode, we have to read with ASCII CR characters filtered out until
   * either two ASCII LF characters in a row are encountered or the
   * input ends (whichever occurs first) */
  if (status && fh) {
    /* First receive operation */
    rcount = (int) recv(sock, iobuf, IOBUFSIZE, 0);

    /* Keep processing until error or end of data */
    while (rcount > 0) {
      /* Process all the newly received data */
      for(i = 0; i < rcount; i++) {
        /* Ignore CR characters */
        if (iobuf[i] == ASCII_CR) {
          continue;
        }

        /* Handling varies depending on if character is LF or
         * not */
        if (iobuf[i] == ASCII_LF) {
          /* LF character -- if lf_flg already set, we got two
           * line breaks in a row, so set ht_brk to indicate
           * fake HTTP reading should stop and break out of
           * this inner loop; else, set lf_flg */
          if (lf_flg) {
            ht_brk = 1;
            break;
          } else {
            lf_flg = 1;
          }

        } else {
          /* Not an LF character -- reset the LF flag */
          lf_flg = 0;
        }
      }

      /* Break out of this loop if we've encountered two line
       * breaks in a row in the inner loop */
      if (ht_brk) {
        break;
      }

      /* Read more data */
      rcount = (int) recv(sock, iobuf, IOBUFSIZE, 0);
    }

    /* Fail if we stopped processing on account of an I/O error */
    if (status) {
      if (rcount < 0) {
        fprintf(stderr,
          "Read error during fake HTTP handling!\n");
        status = 0;
      }
    }
  }

  /* We've now got the connection established and handled fake HTTP
   * mode, if requested -- what's left is to either send stdin through
   * socket (write mode) or receive stdout through socket (read mode),
   * using the I/O buffer as an intermediary */
  if (status && write) {
    /* Write mode -- transfer stdin through socket; begin with the
     * first read from stdin into the I/O buffer */
    rcount = (int) fread(iobuf, 1, IOBUFSIZE, stdin);

    /* Keep reading full buffers from stdin until EOF or error */
    while (rcount == IOBUFSIZE) {

      /* Send the full buffer */
      if (send(sock, iobuf, IOBUFSIZE, 0) != IOBUFSIZE) {
        fprintf(stderr, "Error sending data!\n");
        status = 0;
      }

      /* Break if failure to send */
      if (!status) {
        break;
      }

      /* Read more from stdin */
      rcount = (int) fread(iobuf, 1, IOBUFSIZE, stdin);
    }

    /* If reading stopped due to error, detect that, report it, and
     * fail */
    if (status) {
      if (ferror(stdin)) {
        fprintf(stderr, "Error reading from stdin!\n");
        status = 0;
      }
    }

    /* If we still have remainder data, write that */
    if (status && (rcount > 0)) {
      if (send(sock, iobuf, rcount, 0) != rcount) {
        fprintf(stderr, "Error sending data!\n");
        status = 0;
      }
    }

  } else {
    /* Read mode -- transfer socket through stdout; begin with the
     * first read from socket into the I/O buffer */
    rcount = (int) recv(sock, iobuf, IOBUFSIZE, 0);

    /* Keep reading until no more to receive or error */
    while (rcount > 0) {
      /* Write all the data to stdout */
      if (fwrite(iobuf, 1, rcount, stdout) != rcount) {
        fprintf(stderr, "Error writing to stdout!\n");
        status = 0;
      }

      /* Break if there was an error */
      if (!status) {
        break;
      }

      /* Read more from sock */
      rcount = (int) recv(sock, iobuf, IOBUFSIZE, 0);
    }

    /* If we stopped on account of a socket read error, detect that
     * and report it */
    if (status) {
      if (rcount < 0) {
        fprintf(stderr, "Error receiving data!\n");
        status = 0;
      }
    }
  }

  /* If connection is open, shut it down */
  if (conup) {
    if (shutdown(
        sock,
#ifdef _WIN32
        2 /* both */
#else
        SHUT_RDWR
#endif
        )) {
      fprintf(stderr, "Warning:  socket shutdown failed.\n");
    }
  }

  /* Free the I/O buffer if it is allocated */
  if (iobuf != NULL) {
    free(iobuf);
    iobuf = NULL;
  }

  /* Close the sockets if they are open */
#ifdef _WIN32
  if (sock != INVALID_SOCKET) {
    if (closesocket(sock)) {
      fprintf(stderr, "Warning:  problem closing socket.\n");
    }
  }

  if (sserv != INVALID_SOCKET) {
    if (closesocket(sserv)) {
      fprintf(stderr, "Warning:  problem closing socket.\n");
    }
  }
#else
  if (sock != -1) {
    if (close(sock)) {
      fprintf(stderr, "Warning:  problem closing socket.\n");
    }
  }

  if (sserv != -1) {
    if (close(sserv)) {
      fprintf(stderr, "Warning:  problem closing socket.\n");
    }
  }
#endif

  /* Return status */
  return status;
}

/*
 * Public functions
 * ================
 */

/*
 * Program entrypoint.
 *
 * argc must be the number of arguments, and argv must be an array of
 * pointers to the null-terminated arguments.
 *
 * There must be exactly three arguments.  The first argument is the
 * conventional module name, and then the second and third arguments are
 * two command-line parameters.  The first argument is ignored.  The
 * second argument must be two or three characters, one of which is a
 * case-sensitive match for "s" or "c", the other of which is a
 * case-sensitive match for "r" or "w", and the third (if present) is
 * a case-sensitive match for "h" (order does not matter).  "h" may only
 * be used if "sw" mode is specified, or an error message will be
 * displayed.  The third program argument should be a IPv4 address/port
 * combination that the platform-specific translation function will be
 * able to interpret.
 *
 * See the program documentation at the top of this source file for
 * further information about the meaning of these parameters.
 *
 * If there are not exactly three arguments, an error message is
 * displayed and the function returns failure.  If the second argument
 * can't be parsed, an error message is displayed and the function
 * returns failure.  Otherwise, the function calls through to mspeak
 * with the arguments set as parsed from the command line.
 *
 * If less than two arguments are passed (that is, no extra command line
 * parameters), a short help screen is displayed and the program returns
 * failure.
 *
 * Note that the status return is the opposite of usual -- zero means
 * success, while non-zero means error, as matches console program
 * conventions.
 *
 * On Windows, this function handles WSAStartup and WSACleanup to load
 * and release the Windows Sockets DLL.  Also on Windows only, stdin and
 * stdout are set to binary mode to prevent automatic CR+LF translation.
 *
 * Parameters:
 *
 *   argc - the total number of arguments
 *
 *   argv - the array of pointers to arguments
 *
 * Return:
 *
 *   zero if successful, one if failure
 *
 * Faults:
 *
 *   - If argv is NULL
 *
 *   - If argc is three and the second or third parameter is NULL
 *
 * Undefined behavior:
 *
 *   - If any parameter is not null terminated
 *
 *   - If argv doesn't have at least the number of parameters specified
 *     by argc
 */
int main(int argc, char *argv[]) {
  int status      =  1  ;
  int server      = -1  ; /* -1 means not specified yet */
  int write       = -1  ; /* -1 means not specified yet */
  int fh          = -1  ; /* -1 means not specified yet */
  const char * pc = NULL;
#ifdef _WIN32
/* WIN32-specific --------------------------------------------------- */
  int     sock_init = 0;
  WORD    ver       = 0;
  WSADATA wsadat       ;
/* ================================================================== */
#endif

#ifdef _WIN32
/* WIN32-specific --------------------------------------------------- */

  /* Initialize structures */
  memset(&wsadat, 0, sizeof(WSADATA));

/* ================================================================== */
#endif

  /* Check parameters */
  if (argv == NULL) {
    abort();
  }

  /*
   * Help screen and fail if less than two arguments
   */
  if (argc < 2) {
    fprintf(stderr,
"Syntax: mspeak [flags] [address/port]\n"
"\n"
"Address/port is IPv4, such as 192.168.1.10:32\n"
"\n"
"Flags are:\n"
"\n"
"  r - read mode\n"
"  w - write mode\n"
"  c - client mode\n"
"  s - server mode\n"
"  h - fake HTTP mode\n"
"\n"
"Either r/w must be specified.\n"
"Either c/s must be specified.\n"
"h is optional but only allowed with sw.\n"
"\n"
"Superuser privilege may be required to listen on a\n"
"low-numbered port.\n"
"\n"
"See source file for further information.\n"
    );
    status = 0;
  }

  /* Fail if not exactly three arguments */
  if (status) {
    if (argc != 3) {
      fprintf(stderr, "Expecting two additional arguments!\n");
      status = 0;
    }
  }

  /* Check arguments */
  if (status) {
    if ((argv[1] == NULL) || (argv[2] == NULL)) {
      abort();
    }
  }

  /* Intepret the flags */
  if (status) {
    /* Go through each character */
    for(pc = argv[1]; *pc != 0; pc++) {
      /* Find the right flag */
      if (*pc == 'r') {
        /* Read flag -- set write to zero if not yet set,
         * ignore if already set to read, otherwise error */
        if (write == -1) {
          write = 0;
        } else if (write != 0) {
          fprintf(stderr, "Invalid flag combination!\n");
          status = 0;
        }

      } else if (*pc == 'w') {
        /* Write flag -- set write to one if not yet set,
         * ignore if already set to write, otherwise error */
        if (write == -1) {
          write = 1;
        } else if (write == 0) {
          fprintf(stderr, "Invalid flag combination!\n");
          status = 0;
        }

      } else if (*pc == 'c') {
        /* Client flag -- set server to zero if not yet set,
         * ignore if already set to client, otherwise error */
        if (server == -1) {
          server = 0;
        } else if (server != 0) {
          fprintf(stderr, "Invalid flag combination!\n");
          status = 0;
        }

      } else if (*pc == 's') {
        /* Server flag -- set server to one if not yet set,
         * ignore if already set to server, otherwise error */
        if (server == -1) {
          server = 1;
        } else if (server == 0) {
          fprintf(stderr, "Invalid flag combination!\n");
          status = 0;
        }

      } else if (*pc == 'h') {
        /* Fake HTTP flag -- set fh to one if not yet set,
         * ignore if already set to one, otherwise error */
        if (fh == -1) {
          fh = 1;
        } else if (fh == 0) {
          fprintf(stderr, "Invalid flag combination!\n");
          status = 0;
        }

      } else {
        /* Unrecognized flag */
        fprintf(stderr, "Unrecognized flag!\n");
        status = 0;
      }

      /* Break if there was an error */
      if (!status) {
        break;
      }
    }
  }

  /* If fake HTTP flag wasn't set, set it to a default of zero because
   * it is optional */
  if (status) {
    if (fh == -1) {
      fh = 0;
    }
  }

  /* Error if any of the flags haven't been set either by the
   * parameter or by default value, error */
  if (status) {
    if ((server == -1) || (write == -1) || (fh == -1)) {
      fprintf(stderr, "Required flag is missing!\n");
      status = 0;
    }
  }

  /* Error if fake HTTP is specified when not in server write mode */
  if (status) {
    if (fh) {
      if ((!server) || (!write)) {
        fprintf(stderr,
          "Fake HTTP only allowed in server write mode!\n");
        status = 0;
      }
    }
  }

#ifdef _WIN32
/* WIN32-specific --------------------------------------------------- */

  /* (Windows only) Start the Windows Sockets DLL and set flag if
   * successful, else report error -- warn if there might be a version
   * problem, but otherwise proceed */
  if (status) {
    /* We support winsock version 2.2 */
    ver = MAKEWORD(2, 2);

    /* Try to start up, setting flag if successful */
    if (WSAStartup(ver, &wsadat) == 0) {
      sock_init = 1;
    } else {
      fprintf(stderr, "Couldn't load Windows Sockets!\n");
      status = 0;
    }

    /* Warn if there might be a version problem, but proceed in this
     * case */
    if (status) {
      if ((LOBYTE(wsadat.wVersion) != 2) ||
          (HIBYTE(wsadat.wVersion) != 2)) {
        fprintf(stderr,
"Warning:  possible version issue with Windows Sockets.\n"
        );
      }
    }
  }

  /* (Windows only) Set stdin and stdout to binary mode to disable
   * automatic CR+LF translation */
  if (status) {
    if (_setmode(_fileno(stdin), _O_BINARY) == -1) {
      status = 0;
    }
  }

  if (status) {
    if (_setmode(_fileno(stdout), _O_BINARY) == -1) {
      status = 0;
    }
  }

/* ================================================================== */
#endif

  /* Call through to the main mspeak function */
  if (status) {
    status = mspeak(server, write, fh, argv[2]);
  }

#ifdef _WIN32
/* WIN32-specific --------------------------------------------------- */

  /* (Windows only) Release the Windows Sockets DLL if the flag was
   * set indicating it was loaded earlier -- warn if this doesn't
   * work out successfully */
  if (sock_init) {
    /* Clear initialization flag */
    sock_init = 0;

    /* Unload the DLL */
    if (WSACleanup()) {
      fprintf(stderr,
        "Warning:  problem closing down Windows Sockets.\n");
    }
  }

/* ================================================================== */
#endif

  /* Invert the status to get an appropriate return value */
  if (status) {
    status = 0;
  } else {
    status = 1;
  }

  /* Return the inverted status */
  return status;
}
