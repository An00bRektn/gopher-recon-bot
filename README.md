# Gopher Recon Bot 🔭
> An00bRektn | November 23, 2022

A Golang version of the [Rusty Recon Bot](https://github.com/The-Taggart-Institute/rusty-recon-bot) from HuskyHacks' [Responsible Red Teaming](https://taggartinstitute.org/p/responsible-red-teaming) course. Demonstration of writing some malicious program and creating YARA signatures ahead of time.

## Build
**Prerequisites**: Golang
```shell
$ go build -ldflags="-s -w" $(pwd)/cmd/scout
```

`server.py` is just a simple HTTP server to capture requests with.

## Note
The Rust example from the course uses [Litcrypt](https://docs.rs/litcrypt/latest/litcrypt/) to encrypt specific things at compile-time via a macro. Golang, as I just found out, does not have support for macros, which is why all of the Golang obfuscation libraries out there felt a little overkill for this.

In reality, nothing *really* changes even if I use [gobfuscate](https://github.com/unixpickle/gobfuscate) or some equivalent, and this is just an exercise anyway. 