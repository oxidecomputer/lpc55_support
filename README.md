# LPC55 support crate

This is a crate for accessing things beyond the LPC55 registers, namely support
for ISP mode programming and structures for the CMPA and CFPA regions. This
crate also contains two binaries for working with the LPC55

## `lpc55_flash`

Designed to read/write memory over ISP

```
USAGE:
    lpc55_flash <port> <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <port>    

SUBCOMMANDS:
    erase-cmpa         Erase the CMPA region (use to boot non-secure binaries again)
    flash-erase-all    Erases all non-secure flash. This MUST be done before writing!
    help               Prints this message or the help of the given subcommand(s)
    ping               Runs a single ping to verify communication with the target
    read-memory        Reads memory from the specified address and saves it at the path
    write-cmpa         Write a file to the CMPA region
    write-memory       Write the file to the specified address
```

The ISP protocol doesn't document errors well. If you get ACK errors or timeouts
the best protocol is to try again. A typical session looks like

```
$ ./lpc55_flash /dev/ttyUSB0 flash-erase-all
$ ./lpc55_flash /dev/ttyUSB0 write-memory 0x0 my_binary.bin
```

## `cfpa_update`

The CFPA region has a version counter that must be incremented with every write.
This is great for security but annoying for debugging and iterating. This
tool enables the certificates for secureboot in the CFPA region and updates
the version counter. By default it will write this back to the device but
optionally it will write the CFPA region to a file to be flashed later.

```
USAGE:
    cfpa-update <port> [outfile]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <port>       UART port
    <outfile>    Optional out file for the CFPA region
```
