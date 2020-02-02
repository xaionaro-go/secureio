# Quick start

Encrypted `io.WriteReadCloser`, easy:

```go
// Generate (if not exists) and read ED25519 keys 
identity, err := secureio.NewIdentity(`/home/user/.ssh`)

// Read remote identity 
remoteIdentity, err := secureio.NewRemoteIdentity(`/home/user/.somedir/remote.pubkey`)

// Create a connection
conn, err := net.Dial("udp", "10.0.0.2:1234")

// Create encrypted connection (exchange keys using ECDH and verify remote side by Curve25519 signature).
session := identity.NewSession(context.Background(), remoteIdentity, conn, someLogger)

// Use it!

// Write to it
_, err := session.Write(someData)

// Or/and read from it
_, err := session.Read(someData)
```

It's also a multiplexer:

receiver:
```go
session.SetHandlerFuncs(secureio.MessageType_dataPacketType3, func(payload []byte) {
    fmt.Println("I received a payload:", payload)
}, func(err error) {
    panic(err)
})
```

sender:
```go
_, err := session.WriteMessage(secureio.MessageType_dataPacketType3, payload)
```

possible message types:
```go
MessageType_dataPacketType0
MessageType_dataPacketType1
MessageType_dataPacketType2
MessageType_dataPacketType3
...
MessageType_dataPacketType15
```
The `MessageType_dataPacketType0` is used for default `Read()`/`Write()`.

## Benchmark

The benchmark was performed with communication via an UNIX-socket.
```
BenchmarkSessionWriteRead1-8                          	   10000	    117149 ns/op	   0.01 MB/s	     521 B/op	      10 allocs/op
BenchmarkSessionWriteRead16-8                         	    9865	    118167 ns/op	   0.14 MB/s	     562 B/op	      10 allocs/op
BenchmarkSessionWriteRead1024-8                       	    9552	    127126 ns/op	   8.06 MB/s	     570 B/op	      10 allocs/op
BenchmarkSessionWriteRead32000-8                      	    7006	    173781 ns/op	 184.14 MB/s	     512 B/op	      10 allocs/op
BenchmarkSessionWriteRead64000-8                      	    5010	    294980 ns/op	 216.96 MB/s	     592 B/op	      11 allocs/op
BenchmarkSessionWriteMessageAsyncRead1-8              	 1975814	       610 ns/op	   1.64 MB/s	       1 B/op	       0 allocs/op
BenchmarkSessionWriteMessageAsyncRead16-8             	 2049045	       587 ns/op	  27.26 MB/s	       2 B/op	       0 allocs/op
BenchmarkSessionWriteMessageAsyncRead1024-8           	  418461	      2659 ns/op	 385.07 MB/s	      17 B/op	       0 allocs/op
BenchmarkSessionWriteMessageAsyncRead32000-8          	   25476	     46798 ns/op	 683.79 MB/s	     210 B/op	       6 allocs/op
BenchmarkSessionWriteMessageAsyncRead64000-8          	   12976	    109250 ns/op	 585.81 MB/s	     492 B/op	      13 allocs/op
```
More realistic case (if we have MTU ~= 1400):
```
BenchmarkSessionWriteMessageAsyncRead1300_max1400-8   	  114258	     10513 ns/op	 123.65 MB/s	     331 B/op	      12 allocs/op
```

# TODO

* don't use `Async` for sync-writes.
* route messenger-related errors to the messenger's handler.
* support of fragmented/merged traffic.
* documentation
* consider `notewakeup` instead of `Cond.Wait`
* consider `getg` instead of counter for LockID.
