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

## Benchmark

```
BenchmarkSessionWriteRead1-8               85442             14045 ns/op           0.07 MB/s          18 B/op          2 allocs/op
BenchmarkSessionWriteRead16-8              84830             13738 ns/op           1.16 MB/s          19 B/op          2 allocs/op
BenchmarkSessionWriteRead1024-8            64996             18621 ns/op          54.99 MB/s          18 B/op          2 allocs/op
BenchmarkSessionWriteRead32000-8            7401            146470 ns/op         218.48 MB/s          39 B/op          2 allocs/op
```
