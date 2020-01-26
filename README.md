# TODO

* don't use `Async` for sync-writes.
* encryption-multithreading.
* route messenger-related errors to the messenger's handler.
* support of fragmented/merged traffic.
* documentation
* consider `notewakeup` instead of `Cond.Wait`
* consider `getg` instead of counter for LockID.

# Quick start

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
session.SetHandlerFuncs(secureio.MessageType_dataPacketType3, func(payload []byte) {
    fmt.Println("I received a payload:", payload)
}, func(err error) {
    panic(err)
})
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
...
MessageType_dataPacketType15
```
The `MessageType_dataPacketType0` is used for default `Read()`/`Write()`.

## Benchmark

```
goos: linux
goarch: amd64
pkg: github.com/xaionaro-go/secureio
BenchmarkSessionWriteRead1-8                          	    8493	    135936 ns/op	   0.01 MB/s	    2567 B/op	      37 allocs/op
BenchmarkSessionWriteRead16-8                         	    8838	    134572 ns/op	   0.12 MB/s	    2569 B/op	      37 allocs/op
BenchmarkSessionWriteRead1024-8                       	    8529	    140228 ns/op	   7.30 MB/s	    2108 B/op	      26 allocs/op
BenchmarkSessionWriteRead32000-8                      	    3610	    324730 ns/op	  98.54 MB/s	    2188 B/op	      26 allocs/op
BenchmarkSessionWriteRead64000-8                      	    2336	    511488 ns/op	 125.13 MB/s	    2219 B/op	      26 allocs/op
BenchmarkSessionWriteMessageAsyncRead1-8              	 2872984	       440 ns/op	   2.27 MB/s	       0 B/op	       0 allocs/op
BenchmarkSessionWriteMessageAsyncRead16-8             	 2524777	       462 ns/op	  34.64 MB/s	       1 B/op	       0 allocs/op
BenchmarkSessionWriteMessageAsyncRead1024-8           	  312882	      3614 ns/op	 283.36 MB/s	      36 B/op	       0 allocs/op
BenchmarkSessionWriteMessageAsyncRead32000-8          	   13692	     87178 ns/op	 367.07 MB/s	    1138 B/op	      16 allocs/op
BenchmarkSessionWriteMessageAsyncRead64000-8          	    6830	    170860 ns/op	 374.57 MB/s	    2218 B/op	      33 allocs/op
BenchmarkSessionWriteMessageAsyncRead1300_max1400-8   	   98013	     12267 ns/op	 105.97 MB/s	    1889 B/op	      29 allocs/op
```