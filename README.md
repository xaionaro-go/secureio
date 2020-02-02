[![GoDoc](https://godoc.org/github.com/xaionaro-go/secureio?status.svg)](https://godoc.org/github.com/xaionaro-go/secureio)

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
BenchmarkSessionWriteRead1-8                          	   10000	    118153 ns/op	   0.01 MB/s	     468 B/op	       8 allocs/op
BenchmarkSessionWriteRead16-8                         	   10000	    118019 ns/op	   0.14 MB/s	     455 B/op	       8 allocs/op
BenchmarkSessionWriteRead1024-8                       	    9710	    119238 ns/op	   8.59 MB/s	     441 B/op	       8 allocs/op
BenchmarkSessionWriteRead32000-8                      	    6980	    173441 ns/op	 184.50 MB/s	     488 B/op	       9 allocs/op
BenchmarkSessionWriteRead64000-8                      	    3994	    310038 ns/op	 206.43 MB/s	     629 B/op	       9 allocs/op
BenchmarkSessionWriteMessageAsyncRead1-8              	 2285032	       539 ns/op	   1.86 MB/s	       0 B/op	       0 allocs/op
BenchmarkSessionWriteMessageAsyncRead16-8             	 2109264	       572 ns/op	  27.99 MB/s	       2 B/op	       0 allocs/op
BenchmarkSessionWriteMessageAsyncRead1024-8           	  480385	      2404 ns/op	 425.87 MB/s	      15 B/op	       0 allocs/op
BenchmarkSessionWriteMessageAsyncRead32000-8          	   30163	     39131 ns/op	 817.76 MB/s	     162 B/op	       5 allocs/op
BenchmarkSessionWriteMessageAsyncRead64000-8          	   15435	     77898 ns/op	 821.59 MB/s	     317 B/op	      10 allocs/op
```
More realistic case (if we have MTU ~= 1400):
```
BenchmarkSessionWriteMessageAsyncRead1300_max1400-8   	  117862	     10277 ns/op	 126.49 MB/s	     267 B/op	      10 allocs/op
```

# TODO

* don't use `Async` for sync-writes.
* route messenger-related errors to the messenger's handler.
* support of fragmented/merged traffic.
* documentation
* consider `notewakeup` instead of `Cond.Wait`
* consider `getg` instead of counter for LockID.
