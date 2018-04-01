## BIP 39 ##

This is a generic implementation of [BIP39][bip39] mnemonics for arbitrary byte
slices. The reason for implementing this is that it looks like the [main Golang
implementation][golang-bip39] doesn't support arbitrary byte lengths (which is
a problem if you want to use the BIP39 wordlist but aren't using it for storing
Bitcoin seeds). This library is tested against the official test vectors.

All of the data in `data/` that is used for the generation of the wordlist and
test vectors can be re-downloaded using `data/fetch.sh`. The data comes
directly from the URLs in BIP39.
