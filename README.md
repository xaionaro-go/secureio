[![go report](https://goreportcard.com/badge/github.com/xaionaro-go/secureio)](https://goreportcard.com/report/github.com/xaionaro-go/secureio)
[![GoDoc](https://godoc.org/github.com/xaionaro-go/secureio?status.svg)](https://godoc.org/github.com/xaionaro-go/secureio)
[![Coverage Status](https://coveralls.io/repos/github/xaionaro-go/secureio/badge.svg?branch=master)](https://coveralls.io/github/xaionaro-go/secureio?branch=master)

# Quick start

Prepare keys (on both sides):
```sh
[ -f ~/.ssh/id_ed25519 ] && [ -f ~/.ssh/id_ed25519.pub ] || ssh-keygen -t ed25519
scp ~/.ssh/id_ed25519.pub remote:from_remote_side/
```

Encrypted `io.WriteReadCloser`, easy:

```go
// Generate (if not exists) and read ED25519 keys 
identity, err := secureio.NewIdentity(`/home/user/.ssh`)

// Read remote identity 
remoteIdentity, err := secureio.NewRemoteIdentityFromPublicKey(`/home/user/from_remote_side/id_ed25519.pub`)

// Create a connection
conn, err := net.Dial("udp", "10.0.0.2:1234")

// Create an encrypted connection (and exchange keys using ECDH and verify remote side by ED25519 signature).
session := identity.NewSession(context.Background(), remoteIdentity, conn, nil, nil)

// Use it!

// Write to it
_, err := session.Write(someData)

// Or/and read from it
_, err := session.Read(someData)
```

## It's also a multiplexer

#### Receive

Setup the receiver:
```go
session.SetHandlerFuncs(secureio.MessageTypeDataPacketType3, func(payload []byte) {
    fmt.Println("I received a payload:", payload)
}, func(err error) {
    panic(err)
})
```

#### Send

Send a message synchronously:
```go
_, err := session.WriteMessage(secureio.MessageTypeDataPacketType3, payload)
```

**OR**

Send a message asynchronously:
```go
// Schedule the sending of the payload
sendInfo := session.WriteMessageAsync(secureio.MessageTypeDataPacketType3, payload)

[.. your another stuff here if you want ..]

// Wait until the real sending
<-sendInfo.Done()

// It's not necessary, but helps to reduce the pressure on GC (so to optimize CPU and RAM utilization)
sendInfo.Release()

// Here you get the error if any:
err := sendInfo.Err
```

#### MessageTypes

```go
MessageTypeDataPacketType0
MessageTypeDataPacketType1
MessageTypeDataPacketType2
MessageTypeDataPacketType3
...
MessageTypeDataPacketType15
```
The `MessageTypeDataPacketType0` is used for default `Read()`/`Write()`.
Use any :)

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

As you can see, if you need a high throughput then you need to use
`WriteMessageAsync`. This package is designed to be asynchronous, so
basically `Write` is an stupid and slow wrapper around code of
`WriteMessageAsync`. And if you use `WriteMessageAsync` it also
merges all your messages collected in 50 microseconds into a one,
sends, and then splits them back. It allows to reduce amount of syscalls
and other overheads. So to achieve like 1.86MiB/s on 1-byte messages
you need to send a lot of them asynchronously (from each other), so they
will be merged while sending/receiving through the backend connection.

Also this 800MiB/s is more about the localhost-case. And more realistic network case (if we have MTU ~= 1400) is:
```
BenchmarkSessionWriteMessageAsyncRead1300_max1400-8   	  117862	     10277 ns/op	 126.49 MB/s	     267 B/op	      10 allocs/op
```

# Security design

### Key exchange

Key exchange is performed via ECDH with X25519. [Also if a PSK is set, then
a XOR-value is received as the PSK concatenated with a constant salt-value
and hashed with `sha3.Sum256`. This "XOR-value" XORs the key (received
via ECDH with X25519)](https://github.com/xaionaro-go/secureio/blob/ccd4d864545620b5483c88df91491817e4f0a442/key_exchanger.go#L111).
If PSK is not set then just a key received via ECDH is used
(without any modifications).

The remote side is authenticated by a ED25519 signature (of the
key exchange message).

The resulting value is used as the encryption key for ChaCha20.
This key is called `cipherKey` within the code.

The key received via ECDH is updated [every minute](https://github.com/xaionaro-go/secureio/blob/ccd4d864545620b5483c88df91491817e4f0a442/key_exchanger.go#L18).
So in turn the `cipherKey` is updated every minute as well.

### Encryption

Each packet starts with an unique (for a session) non-encrypted
`PacketID`. The `PacketID` is used as IV/NONCE for ChaCha20 and
`cipherKey` is used as the key.

### Message authentication 

Message authentication is done using Poly1305. As key for Poly1305
used a blake3.Sum256 hash of:
 - [concatenation of `PacketID` and `cipherKey` XOR-ed](https://github.com/xaionaro-go/secureio/blob/ccd4d864545620b5483c88df91491817e4f0a442/message.go#L267) by a [constant value](https://github.com/xaionaro-go/secureio/blob/ccd4d864545620b5483c88df91491817e4f0a442/message.go#L40).

`PacketID` is allowed to grow only. If it was received a packet
with the same `PacketID` (as before) or with a lesser `PackerID` then the packet
is just ignored.

# TODO

* implement `(*sendInfo).SendNow()`
* implement smart lockers
* check keyCreatedAt
* error if key hasn't chagned
* encrypt key-exchange with PSK (if set)
* verify TS difference sanity
* don't use `Async` for sync-writes.
* route messenger-related errors to the messenger's handler.
* support of fragmented/merged traffic.
* documentation
* consider `notewakeup` instead of `Cond.Wait`
* consider `getg` instead of counter for LockID.
