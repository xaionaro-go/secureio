```go
// Generate (if not exists) and read ED25519 keys 
identity, err := cryptofilter.NewIdentity(`/home/user/.ssh`)

// Read remote identity 
remoteIdentity, err := cryptofilter.NewRemoteIdentity(`/home/user/.somedir/remote.pubkey`)

// Create a connection
conn, _ := net.Dial("udp", "10.0.0.2:1234")

// Create encrypted connection (exchange keys using ECDH and verify remote side by Curve25519 signature).
session := identity.NewSession(remoteIdentity, conn, someLogger)


// Use it!

session.Write(someData)

session.Read(someData)
```
