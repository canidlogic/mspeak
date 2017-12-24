/*
 * httpbin.c
 *
 * A program to echo a binary disk file to standard output, preceded by
 * HTTP/1.0 headers identifying the data as generic binary data
 * (application/octet-stream) and providing the appropriate
 * Content-Length field.
 *
 * This can be used to pack a binary file into a stream that can be
 * downloaded as a file from a standard web browser.  This can be used
 * with the "mspeak" program in fake HTTP mode to allow for a file
 * download through standard browser HTTP without having a full HTTP
 * server.
 *
 * The syntax is:
 *
 *   httpbin myfile.bin
 *
 * myfile.bin is the path to a file on disk to stream to standard output
 * with the HTTP header prefixed.  To use with mspeak in fake HTTP mode,
 * do something like this:
 *
 *   httpbin myfile.bin | mspeak swh 192.168.1.10:2000
 *
 * Then, connect to the domain from a web browser -- any file path in
 * the domain will work because mspeak doesn't check it, but for ease of
 * use this should match the original file so that the web browser knows
 * what to call the file.  Loading the following address:
 *
 *   http://192.168.1.10:2000/myfile.bin
 *
 * in a web browser when the prior pipeline is running in server mode
 * should cause the web browser to download the file and then the
 * pipeline to finish as soon as the web browser has downloaded the
 * file.
 *
 * Of course, the web browser has to be able to access the provided port
 * of the provided IP address for this to work, and there are some
 * serious security considerations that need to be taken into account.
 * See the program documentation in the "mspeak" source file for further
 * information.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Constant definitions
 * ====================
 */

/*
 * The size of the buffer used to transfer data.
 *
 * This is dynamically allocated, so it can be made large.
 */
#define IOBUFSIZE 4096

/*
 * Local function prototypes
 * =========================
 */

/*
 * Stream the file at the given path to standard output, preceded by
 * HTTP headers.
 *
 * Errors that occur are reported directly to stderr.
 *
 * Parameters:
 *
 *   pPath - pointer to the path to stream
 *
 * Return:
 *
 *   non-zero if successful, zero if failure
 *
 * Faults:
 *
 *   - If pPath is NULL
 *
 * Undefined behavior:
 *
 *   - If the path is not null terminated
 */
static int httpbin(const char *pPath);

/*
 * Local function implementations
 * ==============================
 */

/*
 * httpbin function.
 */
static int httpbin(const char *pPath) {
  int    status = 1   ;
  FILE * pFile  = NULL;
  long   flen   = 0   ;
  char * pBuf   = NULL;
  long   rcount = 0   ;

  /* First of all, open the path for reading */
  if (status) {
    pFile = fopen(pPath, "r");
    if (pFile == NULL) {
      fprintf(stderr, "Couldn't open input file!\n");
      status = 0;
    }
  }

  /* Next, get the file size by going to the end of the file and
   * reading the location -- we're using the classic long method which
   * may fail due to overflow for files that are multiple gigabytes in
   * size, but this program isn't designed for transferring such large
   * files anyway; after performing this operation, rewind back to the
   * beginning */
  if (status) {
    if (fseek(pFile, 0, SEEK_END)) {
      fprintf(stderr, "Error seeking to end of file!\n");
      status = 0;
    }

    if (status) {
      flen = ftell(pFile);
      if (flen < 0) {
        fprintf(stderr, "Error determining file length!\n");
        status = 0;
      }
    }

    if (status) {
      if (fseek(pFile, 0, SEEK_SET)) {
        fprintf(stderr, "Error rewinding the file!\n");
        status = 0;
      }
    }
  }

  /* Next, allocate the I/O buffer */
  if (status) {
    pBuf = (char *) malloc(IOBUFSIZE);
    if (pBuf == NULL) {
      fprintf(stderr, "Couldn't allocate I/O buffer!\n");
      status = 0;
    }
    if (status) {
      memset(pBuf, 0, IOBUFSIZE);
    }
  }

  /* Next, transmit the HTTP header, with the file length filled in,
   * and using CR+LF linebreaks even on platforms where LF-only
   * linebreaks are customary */
  if (status) {
    if (printf(
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %ld\r\n"
        "\r\n",
        flen) < 0) {
      fprintf(stderr, "Error printing HTTP header!\n");
      status = 0;
    }
  }

  /* Finally, echo the entire input file to standard output */
  if (status) {
    /* Transfer full buffers until the rest of the file will fit in
     * a buffer */
    while(flen > IOBUFSIZE) {
      /* Read a full buffer */
      if (fread(pBuf, 1, IOBUFSIZE, pFile) != IOBUFSIZE) {
        fprintf(stderr, "Error reading from file!\n");
        status = 0;
      }

      /* Write a full buffer */
      if (status) {
        if (fwrite(pBuf, 1, IOBUFSIZE, stdout) != IOBUFSIZE) {
          fprintf(stderr, "Error writing to output!\n");
          status = 0;
        }
      }

      /* Break if there was a problem */
      if (!status) {
        break;
      }

      /* Otherwise, reduce remaining file length by IOBUFSIZE */
      flen -= IOBUFSIZE;
    }

    /* The rest fits in a single buffer, so transfer all the rest */
    if (status) {
      /* Read the rest */
      if (fread(pBuf, 1, (size_t) flen, pFile) != (size_t) flen) {
        fprintf(stderr, "Error reading from file!\n");
        status = 0;
      }

      /* Write the rest */
      if (status) {
        if (fwrite(pBuf, 1, (size_t) flen, stdout) !=
            (size_t) flen) {
          fprintf(stderr, "Error writing to output!\n");
          status = 0;
        }
      }
    }
  }

  /* Free the I/O buffer if allocated */
  if (pBuf != NULL) {
    free(pBuf);
  }

  /* Close the input file if it is open */
  if (pFile != NULL) {
    fclose(pFile);
  }

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
 * There must be exactly two arguments.  The first argument is the
 * conventional module name, and the second argument is the command-line
 * parameter.  The first argument is ignored.  The second argument must
 * be a path to the file to stream.
 *
 * If there are not exactly two arguments, an error message is displayed
 * and the function returns failure.  Otherwise, the function calls
 * through to httpbin with the argument from the command line.
 *
 * If less than two arguments are passed (that is, no extra command line
 * parameters), a short help screen is displayed and the program returns
 * failure.
 *
 * Note that the status return is the opposite of usual -- zero means
 * success, while non-zero means error, as matches console program
 * conventions.
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
 *   - If argc is two and the second parameter is NULL
 *
 * Undefined behavior:
 *
 *   - If any parameter is not null terminated
 *
 *   - If argv doesn't have at least the number of parameters specified
 *     by argc
 */
int main(int argc, char *argv[]) {
  int status = 1;

  /* Check parameters */
  if (argv == NULL) {
    abort();
  }

  /*
   * Help screen and fail if less than two arguments
   */
  if (argc < 2) {
    fprintf(stderr,
"Syntax: httpbin [path]\n"
"\n"
"path is the path to the file to stream in an HTTP\n"
"response container.\n"
"\n"
"See source file for further information.\n"
    );
    status = 0;
  }

  /* Fail if not exactly two arguments */
  if (status) {
    if (argc != 2) {
      fprintf(stderr, "Expecting one additional argument!\n");
      status = 0;
    }
  }

  /* Check argument */
  if (status) {
    if (argv[1] == NULL) {
      abort();
    }
  }

  /* Call function */
  if (status) {
    status = httpbin(argv[1]);
  }

  /* Invert status and return it */
  if (status) {
    status = 0;
  } else {
    status = 1;
  }

  return status;
}
