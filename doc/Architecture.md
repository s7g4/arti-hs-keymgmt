# Arti: Architectural notes and outline.

## Guidelines

I'm hoping to have small, optional, separable pieces here.

I'd like as little code as possible to actually read and write to the
network, and as much code as possible to pretend that the network doesn't
exist.  I hope this will make everything easier to test.

## Structure

To try to keep dependency relationships reasonable, and to follow
what I imagine to be best practice, I'm splitting this
implementation into a bunch of little crates within a workspace.
Crates that are tor-specific start with "tor-"; others don't.

I expect that the list of crates will have to be reorganized quite a
lot by the time we're done.

The current crates are:

`caret`: A utility for generating enumerations with helpful trait
implementations

`tor-units`: Utilities for wrapping bounded and/or meaningful numeric types.

`tor-llcrypto`: Wrappers and re-exports of cryptographic code that Tor needs in
various ways.  Other crates should use this crate, and not actually
use any crypto implementation crates directly.  (It's okay to use crates that
define cryptographic traits.)

`tor-rtcompat`: Traits to expose a common interface for asynchronous runtime
code. Currently it supports async-std and tokio.

`tor-rtmock`: Implementations of the traits in `tor-rtcompat` to support
testing.

`tor-bytes`: Byte-by-byte encoder and decoder functions and traits.  We use
this to safely parse cells, certs, and other byte-oriented things.

`tor-cert`: Decoding and checking signatures on Tor's ed25519 certificates.

`tor-protover`: Minimal implementation of the Tor subprotocol versioning
system.  Less complete than the one in Tor's current src/rust, but more
simple.

`tor-socksproto`: Implements the server side of the SOCKS protocol, along
with Tor-specific extensions.

`tor-checkable`: Defines traits and types used to represent things that you
can't use until verifying their signatures and checking their timeliness.

`tor-consdiff`: Implements the client side of Tor's consensus-diff algorithm.

`tor-netdoc`: Parsing for Tor's network documents.  Underdocumented and too
big.

`tor-linkspec`: Traits and types for connecting and extending to Tor relays.

`tor-cell`: Encoding and decoding for Tor cells.

`tor-proto`: Functions to work with handshakes, channels, circuits, streams,
and other aspects of the Tor protocol.  This crate is NOT ALLOWED to have any
dependencies on specific TLS libraries or specific async environments; those
have to happen at a higher level.  (Perhaps this crate should be split into a
cell handling API and a network API.  The division point would fairly
logical.)

`tor-netdir`: Wraps tor-netdoc to expose a "tor network directory" interface.
Doesn't touch the network itself.  Right now it only handles microdesc-based
directories.

`tor-chanmgr`: Creates channels as necessary, returning existing channels
when they already exist.

`tor-circmgr`: Creates circuits as requested, returning existing circuits
when they already exist.

`tor-dirclient`: Downloads directory information over a one-hop circuit.

`tor-dirmgr`: Uses `tor-dirclient` to fetch directory information as needed
to download, cache, and maintain an up-to-date network view. Exposes the
network view as an instance of `tor-netdir::NetDir`.

`tor-config`: Support for loading and managing configuration files.

`tor-client`: A client library that can be used to connect to the Tor network
and make connections.

`arti`:  A simple command-line client program that can run as a SOCKS proxy.

