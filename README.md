# The Problem
The clue was: "Linked lists are great! They let you chain pieces of data together"
The program asks twice for 15 bytes of data, to store on two separate linked list nodes, and then it leaks the second node's address.


Running checksec on the binary gives the following result:

![alt text](checksec.png)
