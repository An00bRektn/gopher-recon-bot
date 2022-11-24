# Gopher Recon Bot 🔭
> An00bRektn | November 23, 2022

A Golang version of the [Rusty Recon Bot](https://github.com/The-Taggart-Institute/rusty-recon-bot) from HuskyHacks' [Responsible Red Teaming](https://taggartinstitute.org/p/responsible-red-teaming) course. Demonstration of writing some malicious program and creating YARA signatures ahead of time.

## Build
**Prerequisites**: Golang, [garble](https://github.com/burrowers/garble)
```shell
$ garble -literals -tiny build $(pwd)/cmd/scout
```

`server.py` is just a simple HTTP server to capture requests with.

## Note
The Rust example from the course uses [Litcrypt](https://docs.rs/litcrypt/latest/litcrypt/) to encrypt specific things at compile-time via a macro. Golang, as I just found out, does not have support for macros, which is why all of the Golang obfuscation libraries out there felt a little overkill for this.

**Update (11/24/2022)**: After remembering that [garble](https://github.com/burrowers/garble) exists, I proceeded to spend 4+ hours trying to figure out how to embed an imprint string inside a binary, while also using the obfuscation tool. Ultimately, I had to use [`embed`](https://pkg.go.dev/embed) to take the string from a file and stick it in the file. If `garble` is updated to obfuscate embeds as well, then RIP.