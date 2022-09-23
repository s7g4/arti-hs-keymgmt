# tor-ptmgr

`tor-ptmgr`: Manage a set of anti-censorship pluggable transports.

## Overview

This crate is part of [Arti](https://gitlab.torproject.org/tpo/core/arti/),
a project to implement [Tor](https://www.torproject.org/) in Rust.

In Tor, a "transport" is a mechanism used to avoid censorship by disguising
the Tor protocol as some other kind of traffic.

A "pluggable transport" is one that is not implemented by default as part of
the Tor protocol, but which can instead be added later on by the packager or
the user.  Pluggable transports are typically provided as external binaries
that implement a SOCKS proxy, along with certain other configuration
protocols.

This crate provides a means to manage a set of configured pluggable
transports

## Limitations

TODO pt-client: Currently, the APIs for this crate make it quite
tor-specific.  Notably, it can only return Channels!  It would be good
instead to adapt it so that it was more generally useful by other projects
that want to use pluggable transports in rust.  For now, I have put the
Tor-channel-specific stuff behind a `tor-channel-factory` feature, but there
are no APIs for using PTs without that feature currently.  That should
change.

TODO pt-client: Nothing in this crate is actually implemented yet.

TODO pt-client: The first version of this crate will probably only conform
to the old Tor pluggable transport protocol, and not to more recent variants
as documented at `pluggabletransports.info`

License: MIT OR Apache-2.0
