Encrypted `io.WriteReadCloser`, easy:

```go
// Generate (if not exists) and read ED25519 keys 
identity, err := secureio.NewIdentity(`/home/user/.ssh`)

// Read remote identity 
remoteIdentity, err := secureio.NewRemoteIdentity(`/home/user/.somedir/remote.pubkey`)

// Create a connection
conn, _ := net.Dial("udp", "10.0.0.2:1234")

// Create encrypted connection (exchange keys using ECDH and verify remote side by Curve25519 signature).
session := identity.NewSession(context.Background(), remoteIdentity, conn, someLogger)

// Use it!

// Write to it
session.Write(someData)

// Or/and read from it
session.Read(someData)
```

It's also a multiplexer:

receiver:
```go
session.NewMessenger(secureio.MessageType_dataPacketType3), func(payload []byte) {
    fmt.Println("I received a payload:", payload)
}, func(err error) {
    panic(err)
}
```

sender:
```go
session.WriteMessage(secureio.MessageType_dataPacketType3, payload)
```

possible message types:
```go
MessageType_dataPacketType0
MessageType_dataPacketType1
MessageType_dataPacketType2
MessageType_dataPacketType3
MessageType_dataPacketType4
MessageType_dataPacketType5
MessageType_dataPacketType6
MessageType_dataPacketType7
```
The `MessageType_dataPacketType0` is used for default `Read()`/`Write()`.
