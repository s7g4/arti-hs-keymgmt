# arti

A minimal client for connecting to the tor network

This crate is the primary command-line interface for
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
Many other crates in Arti depend on it.

⚠️**WARNING**: Arti is not yet a secure or complete Tor implementation!
If you use it, you should expect that it _will_ harm your privacy.
For now, if you have actual privacy or security needs, please use
the C implementation of Tor instead. ⚠️

More documentation will follow as this program improves.  For now,
just know that it can run as a simple SOCKS proxy over the Tor network.
It will listen on port 9150 by default, but you can override this in
the configuration.

## Command-line arguments

(This is not stable; future versions will break this.)

`-f <filename>` overrides the location to search for a
configuration file to the list of configuration file.  You can use
this multiple times: All files will be loaded and merged.

`-c <key>=<value>` sets a configuration option to be applied after all
configuration files are loaded.

## Configuration

By default, `arti` looks for its configuration files in a
platform-dependent location.  That's `~/.config/arti/arti.toml` on
Unix. (TODO document OSX and Windows.)

The configuration file is TOML.  (We do not guarantee its stability.)
For an example see [`arti_defaults.toml`](./arti_defaults.toml).

## Limitations

There are many missing features.  Among them: there's no onion
service support yet. There's no anti-censorship support.  You
can't be a relay.  There isn't any kind of proxy besides SOCKS.
Resolve-over-SOCKS isn't implemented yet.

See the [README
file](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/README.md)
for a more complete list of missing features.

License: MIT OR Apache-2.0
