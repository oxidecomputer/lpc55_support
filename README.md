# LPC55 support crate

This is a crate for accessing things beyond the LPC55 registers, namely support
for ISP mode programming and structures for the CMPA and CFPA regions. This
crate also contains some binaries for working with the LPC55

## UART Setup

To use these tools with an lpc55xpresso board it must be in ISP mode. The
procedure for doing so is documented in the NXP manual. Once your board is in
ISP mode you'll be able to program various aspects of the device over the UART
with the commands documented below. Depending on how you want to access the
UART, some additional steps may be required.

By default the UART is bridged to the LPC-LINK2 probe. When the board is
powered and the debug link connected, the UART shows up as a USB CDC class
device. On my Linux system the `usb_cdc` driver creates the device node
`/dev/ACM0` for it. This device can be used as the `<port>` parameter to the
commands below.

If you want to use the UART pins (P8) instead you'll need to install a jumper
on P1. This disables the UART bridge. If you don't have a jumper handy you can
use the UART through P8 but only if the `Debug Link` / `P6` USB port isn't
used. Powering the board through one of the other USB ports appears to keep the
debug link from taking over the UART leaving the P8 pins active but YMMV.

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

## `lpc55_sign`

Will update a binary image with NXP crc information or RSA signature.
Currently this only supports a single certificate.

```
USAGE:
    lpc55_sign <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    crc             Generate a non-secure CRC image
    help            Prints this message or the help of the given subcommand(s)
    signed-image    Generate a secure signed image and corresponding CMPA region
```

### Generating a crc image

CRC images are considered non-secure so make sure the CMPA region is either
erased or has secure booting turned off.


```
$ ./lpc55_sign crc my_binary.bin my_crc_binary.bin
```

This can be flashed using your preferred method.

```
$ ./lpc55_flash /dev/ttyUSB0 write-memory 0x0 my_crc_binary.bin
If you didn't already erase the flash this operation will fail!
This operation may take a while
Write complete!
```

### Generating a signed image

Make sure you've run `cfpa_update` at least once to mark certificate 0 as valid:

```
$ ./cfpa_update /dev/ttyUSB0
Writing updated CFPA region back to the device
done!
```

You will need a private key and certificate. NXP expects the certificate
to have a specific serial number for revoking.

```
$ ./lpc55_sign signed-image my_binary.bin my_private_key.pem my_cert.der.crt my_signed_image.bin cmpa.bin
```

The signed binary and CMPA image can be flashed using your preferred method

```
$ ./lpc55_flash /dev/ttyUSB0 write-cmpa cmpa.bin
Write to CMPA done!
$ ./lpc55_flash /dev/ttyUSB0 write-memory 0x0 my_signed_image.bin
If you didn't already erase the flash this operation will fail!
This operation may take a while
Write complete!
```

If you want to go back to working on unsigned images, write 512 bytes of
zeros to the CMPA region or just use the flash shortcut

```
$ ./lpc55_flash /dev/ttyUSB0 erase-cmpa
CMPA region erased!
You can now boot unsigned images
```
