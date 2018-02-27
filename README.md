# PyTFTPd
TFTP server and client in Python 3

## Supported features
* RFC 1350 - TFTP revision 2
*   Octet mode transfer (netascii and mail unsupported)
*   Read request (RRQ) only, no write capability
*   Limited error reporting (e.g. all file reading errors reported as FILE_NOT_FOUND, real reason in message string)
* RFC 2347 - TFTP option Extension
* RFC 2348 - TFTP Blocksize Option
* RFC 7440 - TFTP Windowsize Option

## Usage
### Server
Run tftpd.py [port_to_bind_to] [webroot_dir]

### Client
Run tftp.py [server] [port] [file to download]
Save filename, prefered window and block sizes are set using BLOCK_SIZE, WINDOW_SIZE, OUT_FILENAME constants in tftp.py
Logging verbosity can be changed in tftp_common using DEBUG and INFO flags.
## System requirements
Tested on Python 3.5 on Linux. MS Windows is not supported due to usage of Unix signals.
