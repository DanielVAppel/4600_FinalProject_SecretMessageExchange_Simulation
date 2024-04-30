# 4600_FinalProject_SecretMessageExchange_Simulation
 Secure communication system between two parties.

Requirements:
The requirements of the system include:
1.) The two parties have each other’s RSA public key. Each of them holds his/her own RSA
private key.
2.) Each party’s message (from a .txt file) is encrypted using AES before sending it to
another party.
3.) The AES key used in 2) is encrypted using the receiver’s RSA public key. The encrypted
AES key is sent together with the encrypted message obtained from 2).
4.) Message authentication code is appended to data transmitted. WIth a user specified protocol of MAC.
5.) The receiver is be able to successfully authenticate, decrypt the message, and read
the original message.
