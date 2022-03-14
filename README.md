# Security Authentication System
An authentication system like Needham-Schroeder protocol with public - private key cryptosystem

![alt text](https://github.com/eceomurtay/Security-Authentication-System/blob/main/scenario.jpg)

Scenario of Alice tries to communicate with Mail server:

> 1. Alice, P_KDC(“Alice”, Pass, “Mail”, TS1) 🠊 Alice sends KDC her id with a content encrypted with the public key of KDC. The encrypted message includes her id, her password, id of Mail Server and a timestamp. KDC decrypts Alice message with its own private key. Then, in the second message, KDC sends a message and ticket information back to Alice.
> 2. P_A(K_A, “Mail”, TS2), Ticket = P_Mail (“Alice”, “Mail”, TS2, K_A) 🠊 KDC’s message has two parts. First part is encrpyted with public key of Alice and includes session key (K_A), ID of Mail Server and a timestamp. Second part contains a ticket encrypted with public key of Mail Server and includes IDs of Alice and mail Server, same timestamp and session key values. Alice decrypts the first part of message with her own private key and gets the session key and also stores the ticket. 
> 3. Alice, Ticket, K_A(N1) 🠊 Alice sends her id, the ticket, and a nonce value encrypted with the session key to the Mail Server. Mail Server decrypts ticket with its own private key and learns the session key and verifies the correctness of the information in the ticket. Mail Server also decrypts the encrypted N1value with the session key. 
> 4. K_A (N1+1, N2) 🠊 Mail Server sends N1+1 and N2 values encrypted with the session key. Alice decrypts the message from Mail Server with session key and verifies the correctness of N1+1 value. 
> 5. K_A (N2+1) 🠊 If N1+1 value is correct, Alice sends back a message to the Mail server. Message is encrypted with the session key and includes N2+1 value.

## Usage
Execution sequence: KDC 🠊 Alice 🠊 Selected server

Get requested password in Alice (client program) from KDC_Log.txt
