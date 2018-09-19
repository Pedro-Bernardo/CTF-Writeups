# Reversing (The Problem)
The clue was: "Linked lists are great! They let you chain pieces of data together"
The program asks twice for 15 bytes of data, to store on two separate linked list nodes, node 1 and node 2. Then it leaks the second node's address through the "next" pointer in the first node.
Finally, it asks for our initials and then prints a goodbye message using our input.


Running checksec on the binary gives the following result:

![alt text](checksec.png)

This gives us a few clues already:
1. NX is disabled and there are RWX segments, which points to possible shellcode injection
2. Full RELRO means that we can also overwrite the GOT if needed.
3. No stack ca
nary, which points to a possible buffer overflow vulnerability.

Jumping into ida, we can identify a buffer overflow which we can use to overwrite
