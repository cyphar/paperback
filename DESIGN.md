## Paperback Design ##

The following is a description of the design behind paperback.

### Overview ###

Paperback is designed to store a person's secret data in a manner such that
they can be recovered with a quorum of people coming together for the recovery.

It is a necessary part of this model that this recovery can occur without the
original person present, as one use-case of paperback is to act as a person's
will. If this is not what the person wants, they should encrypt their document
with a secret passphrase before providing it to paperback.

There are two primary documents in paperback, both of which are required in
order to facilitate a recovery event:

 1. The "main document" stores an encrypted copy of the person's secret data.
    It is up to the user whether they wish to only have one copy of this
    document, or many.

 2. "Key shards" are individual documents which store a portion of the secret
    key used to encrypt the "main document" (in a zero-information manner). A
    unique "key shard" is provided to each person who can form the quorum. `N`
    key "shards" are required to recover the secret key for the "main
    document".

For the purpose of this document, the set of people who possess a "key shard"
are called "key-holders". When `N` people come together to perform a recovery
event, that group is called a "quorum" (with each member being called a "quorum
member"). In this document, `K` refers to the **total** number of key shards
(including any key shards created after ).

For the purposes of simplicity, we assume that each key holder only has one key
shard in their possession. Key-holders holding multiple key shards are counted
as multiple people.

### Threat Model ###

We assume that all of the cryptographic primitives used are computationally
hard to break, and are thus trustworthy enough for our use. However, if the
cryptographic primitives used in this design are found to be compromised, we
can migrate to newer ones.

We also assume that the original user made an accurate decision about the
quorum size (that no more than `N-1` people will either be compromised or
collaborate to attack the secret data). However, paperback must be secure even
with up to `N-1` malicious quorum members.

We assume that the quorum is using a real copy of paperback, as otherwise we
cannot guarantee that the software they use will not produce a fake result. And
while it may be possible to prove that the result is fake using the real
paperback software, that presupposes that they have access to the real
paperback.

Paperback must be able to detect if malicious quorum members have produced fake
key shards or fake documents. It must not allow fewer than `N` people to
recover the secret. It also should protect against `N` people creating a fake
document that other (honest) key-holders then cannot detect is a fake document.
However, in order for this detection to work, the honest key-holder must be
confident that their key shard has not been modified or replaced with a forged
copy (by a malicious quorum).

We assume that in a quorum with `n < N` malicious key-holders (who were able at
some point to form a quorum and thus produce forged key shards), at least one
of the honest key-holders in the quorum is confident that their own key shard
has not been replaced with a forgery. This is a necessary assumption for it to

Paperback's detection of  must We assume that
If more than `N`
Even with `n >= N` malicious key-holders being able to form a quorum, we assume
that at least `K-(N-1)` honest key-holders are confident that their key shard
is not a forgery and has not been replaced with a forgery from a malicious
quorum member. Without this assumption, it would be impossible to protect
against anyone replacing the key shard with a key shard for a completely
different document -- completely negating the security of the scheme.
Key-holders should be chosen specifically so that a single adversary cannot
replace more than `N-1` key shards. As above, additional honest key-holders
(which do not have forged key shards) must be able to detect that the final
document is a forgery, but this is not a substitute for a guarantee that such
forgeries will always be detected if an honest key-holder is a member of the
quorum (as this assumption ensures).

### Design ###

The main cryptographic primitives used in this design are:

 * `ZBase32_Encode(b)` encodes the bytes `b` with [z-base32][zbase32].
 * `ZBase32_Decode(s)` decodes the [z-base32][zbase32] string `s`.

 * `CSPRNG(n)` generates `n` bytes of cryptographically-random data.

 * `AEAD_GenKey()` generates a random and secure cryptographic key, usable for
   `AEAD_Enc` and `AEAD_Dec`.
 * `AEAD_Enc(K, nonce, plain, ad)` symmetrically encrypts the plain-text
   `plain` with associated data `ad` with key `K` and nonce `nonce`.
 * `AEAD_Dec(K, nonce, cipher, ad)` symmetrically decrypts the cipher-text
   `cipher` with associated data `ad` with key `K` and nonce `nonce`.

 * `Hash(data)` produces a cryptographic hash of `data`.

 * `Sig_GenPrivKey()` generates a random and secure cryptographic key, usable
   for `Sig_Sign` and `Sig_Verify`.
 * `Sig_GetPubKey(K_priv)` calculates the corresponding public key for the
   private key `K_priv` generated by `Sig_GenPrivKey`.
 * `Sig_Sign(K_priv, data)` signs the bytes `data` using the private key
   `K_priv`.
 * `Sig_Verify(K_pub, data, sig)` verifies that the signature `sig` by the
   public key `K_pub` of the bytes `data` is valid.

 * `Secret_Share(secret, n, k)` generates `k` shards of the secret data
   `secret`, such that `n` quorum members are required to reconstruct the
   secret.
 * `Secret_Recover(shards, n)` recovers the secret sharded into the given
   `shards` with quorum size `n`.
 * `Secret_Expand(shards, n, k2)` generates an additional `k2` shards by
   recovering the necessary information from `shards` with quorum size `n`.
   These shards should be statistically improbable to coincide with any other
   shards previously generated.

`AEAD_Enc` and `AEAD_Dec` are implemented using the [AEAD construction of
`ChaCha20-Poly1350` as defined in RFC 8439][chacha20poly1305]. `Hash` is
[`BLAKE2b`][blake2]. `Sig_GetPubKey`, `Sig_Sign`, and `Sig_Verify` are
implemented using [`Ed25519`][ed25519]. `Secret_Share`, `Secret_Recover`, and
`Secret_Expand` are implemented using [Shamir Secret Sharing][sss].

`AEAD_GenKey` and `Sig_GenPrivKey` are both implemented using the
relevant secure randomness source provided by the operating system. This is
permitted because [`ChaCha20-Poly1305`][chacha20poly1305] and
[`Ed25519`][ed25519] both permit arbitrary random values as private keys. If
the algorithm choice is modified in the future, this assumption will need to be
reconsidered.

[blake2]: https://blake2.net/
[chacha20poly1305]: https://tools.ietf.org/html/rfc7539
[ed25519]: https://ed25519.cr.yp.to/
[sss]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
[zbase32]: http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt

#### Creation ####

Let `secret` be the secret data which the user wants to store. Let `n` be the
size of the quorum the user selected, and `k` be the number of key shards to be
created (assuming `k > n`).

We first generate all of the necessary keys and shards:

```
K_doc = AEAD_GenKey()

K_id_priv = Sig_GenPrivKey()
K_id_pub = Sig_GetPubKey(K_id_priv)

// "Sealed documents" are documents where creating new shards after the initial
// backup (as described in the "Expansion" section below) is prohibited. This
// prohibition is done by not including K_id_priv in the shared secret -- making
// it impossible for new signatures to be created after the initial backup.
secret = K_doc
if !sealed_document
    secret ||= K_id_priv
shards = Secret_Share(secret, n, k)
```

Then the main document is formed (treat it as a JSON object):

```
doc_nonce = CSPRNG(NONCE_SIZE)

Doc[meta] = n
Doc[body] = doc_nonce || AEAD_Enc(K_doc, doc_nonce, secret, Doc[meta] || K_id_pub)
Doc[identity] = K_id_pub || Sig_Sign(K_id_priv, Doc[meta] || Doc[body] || K_id_pub)
Doc[chksum] = Hash(Doc[meta] || Doc[body] || Doc[identity])

// The full document ID is content-defined.
doc_id = Doc[chksum]
// Used for human identification of the document. Will be printed on the main
// document but isn't actually stored in the data (for obvious reasons -- you
// can't store the checksum of the data inside the data).
doc_human_id = ZBase32_Encode(doc_id[:6])
```

Then the key shards are formed (treat them as JSON-like objects). For each
`shard` in `shards`:

```
K_shard = AEAD_GenKey()
shard_nonce = CSPRNG(NONCE_SIZE)

// The x-coordinate of the SSS shard must be unique for each shard -- if two
// shards have the same x co-ordinate they cannot be used together. Thus we can
// use it as a way for human-verifiable uniqueness of shards as well as a loose
// "content-defined" shard ID for human identification.
shard_id = shard.x
// Used for human identification of the key shard.
shard_human_id = ZBase32_Encode(shard_id)

Shard[meta] = Doc[chksum]
Shard[body] = shard_nonce || AEAD_Enc(K_shard, shard_nonce, n || shard, Shard[meta] || K_id_pub)
Shard[identity] = K_id_pub || Sig_Sign(K_id_priv, Shard[meta] || Shard[body] || K_id_pub)
Shard[chksum] = Hash(Shard[meta] || Shard[body] || Shard[identity])

// The key is included, to allow for users to optionally store the key
// separately (or keep it with the key shard to make this level of security a
// no-op).
Shard[key] = K_shard
```

#### Recovery ####

During recovery, we may discover that the document or one or more key shards do
not have consistent values for `K_id_pub` or `Doc[chksum]`. This indicates that
at least one of the documents has been forged, but it is not possible to be
sure which documents have been forged. However it is possible to display to
users (possibly graphically) which documents are consistent with each other,
and thus perhaps allow for a social solution to the conflict. In all such
cases, the recovery operation must abort.

When recovering, first the main document is verified:

```
// Ensure the checksum and signature are valid.
if Doc[chksum] != Hash(Doc[meta] || Doc[body] || Doc[identity])
    abort "Main document checksum mismatch -- bad data."
{doc_id_pub, doc_id_sig} = Doc[identity]
if not Sig_Verify(doc_id_pub, Doc[meta] || Doc[body] || doc_id_pub, doc_id_sig)
    abort "Main document signature mismatch -- forgery detected"

{doc_doc_id, doc_n} = Doc[meta]
```

Then each of the shards are verified. For each `Shard` in the given set:

```
// Ensure the checksum and signature are valid.
if Shard[chksum] != Hash(Shard[meta] || Shard[body] || Shard[identity])
    abort "Shard checksum mismatch -- bad data."
{shard_id_pub, shard_id_sig} = Shard[identity]
if not Sig_Verify(shard_id_pub, Shard[meta] || Shard[body] || shard_id_pub, shard_id_sig)
    abort "Shard signature mismatch -- forgery detected."

{shard_doc_chksum} = Shard[meta]

// All shards and documents must use the same public identity keys.
if shard_id_pub != doc_id_pub
    abort "Inconsistent identities -- forgery detected."

// The shard must agree on the document's checksum.
if shard_doc_chksum != Doc[chksum]
    abort "Document checksum doesn't match shard's copy -- forgery detected."

// Decrypt the shard.
{shard_nonce, shard_ciphertext} = Shard[body]
{shard_n, shard}, error = AEAD_Dec(Shard[key], shard_nonce, shard_ciphertext, Shard[meta] || Shard[id_pub])
if error
    abort "Error encountered during decryption -- possible forgery detected."

// All shards and documents must agree on basic metadata.
if shard_n != doc_n
    abort "Inconsistent metadata -- forgery detected."

// All shards must have a unique shard_id.
shard_id = shard.x
if shard_id == any other shard_id
    abort "Duplicate or fake duplicate shard -- possible forgery detected."

// All good!
shards.append(shard)
```

Once all the shards have been verified against the document, and no errors have
been found, the recovery process can be completed:

```
// Get the secret data.
{K_doc, K_id_priv}, error = Secret_Recover(shards, doc_n)
if error
    abort "Error encountered during secret recovery."

// Effectively, check if the document is sealed.
if K_id_priv is not empty
    // Make sure that that K_id_priv matches. At this point, we've already
    // revealed the secrets but it doesn't hurt to double-check.
    if Sig_GetPubKey(K_id_priv) != Doc[id_pub]
        abort "Inconsistent identities -- forgery detected."

// Decrypt the main document.
{doc_nonce, doc_ciphertext} = Doc[body]
secret, error = AEAD_Dec(K_doc, doc_nonce, doc_ciphertext, Doc[meta] || doc_id_pub)
if error
    abort "Error encountered during decryption -- possible forgery detected."
```

#### Expansion ####

Let `k2` be the additional number of shards needed.

In certain circumstances, it is necessary to able to create new shards.
However, the most trivial way (creating a new paperback backup) means that any
old shares become invalidated. This is problematic because some key-holders may
not be easily reachable to replace their existing key shard.

Thus, paperback supports creating new key shards which are compatible (but
distinct) from any others. In order to perform this operation a quorum is
required, but the main document is not necessary. Note that this operation
allows the quorum to produce a virtually unlimited number of key shards, and
that this feature is an unavoidable mathematical feature of the construction of
Shamir Secret Sharing.

However, users can disable this feature by creating a "sealed document", where
`K_id_priv` is deleted after the initial backup and thus no new shards can be
signed with that key.

The process for verifying the shards is very similar to the recovery scenario,
except that the shard metadata is compared with other shards rather than
against the main document. The same caveat about forgery detection applies here
too. For each `Shard` in the given set:

```
// Ensure the checksum and signature are valid.
if Shard[chksum] != Hash(Shard[meta] || Shard[body] || Shard[identity])
    abort "Shard checksum mismatch -- bad data."
{shard_id_pub, shard_id_sig} = Shard[identity]
if not Sig_Verify(shard_id_pub, Shard[meta] || Shard[body] || shard_id_pub, shard_id_sig)
    abort "Shard signature mismatch -- forgery detected."

{shard_doc_chksum} = Shard[meta]

// All shards must use the same public identity keys.
if shard_id_pub != any other shard_id_pub
    abort "Inconsistent identities -- forgery detected."

// All shards must agree on the document's checksum.
if shard_doc_chksum != any other shard_doc_chksum
    abort "Shards don't agree on document checksum -- forgery detected."

// Decrypt the shard.
{shard_nonce, shard_ciphertext} = Shard[body]
{shard_n, shard}, error = AEAD_Dec(Shard[key], shard_nonce, shard_ciphertext, Shard[meta] || Shard[id_pub])
if error
    abort "Error encountered during decryption -- possible forgery detected."

// All shards must agree on basic metadata.
if shard_n != any other shard_n
    abort "Inconsistent metadata -- forgery detected."

// All shards must have a unique shard_id.
shard_id = shard.x
if shard_id == any other shard_id
    abort "Duplicate or fake duplicate shard -- possible forgery detected."

// All good!
shards.append(shard)
```

Once all the shards have been verified against the document, and no errors have
been found, the recovery process can be completed. `K_id_pub` is the agreed-upon
`shard_id_pub`, and `n` is the agreed-upon `shard_n`.

```
// Get the secret data.
{K_doc, K_id_priv}, error = Secret_Recover(shards, n)
if error
    abort "Error encountered during secret recovery."

// Effectively, check if the document is sealed.
if K_id_priv is not empty
    // Make sure that that K_id_priv matches. At this point, we've already
    // revealed the secrets but it doesn't hurt to double-check.
    if Sig_GetPubKey(K_id_priv) != K_id_pub
        abort "Inconsistent identities -- forgery detected."
else
    abort "Document was created as a sealed backup -- no new shards permitted."


// Decrypt the main document.
{doc_nonce, doc_ciphertext} = Doc[body]
secret, error = AEAD_Dec(K_doc, doc_nonce, doc_ciphertext, Doc[meta] || K_id_pub)
if error
    abort "Error encountered during decryption -- possible forgery detected."
```

Once all the shards have been verified against each other, and no errors have
been found, the expansion process can be completed.

```
{K_doc, K_id_priv} = Secret_Recover(shards, n)
new_shards = Secret_Expand(shards, n, k2)
```

The new key shards are constructed as during creation. `doc_id` is the
agreed-upon `shard_doc_id`. For each `shard` in `new_shards`:

```
K_shard = AEAD_GenKey()
shard_nonce = CSPRNG(NONCE_SIZE)

// The x-coordinate of the SSS shard must be unique for each shard -- if two
// shards have the same x co-ordinate they cannot be used together. Thus we can
// use it as a way for human-verifiable uniqueness of shards as well as a loose
// "content-defined" shard ID for human identification.
shard_id = shard.x
// Used for human identification of the key shard.
shard_human_id = ZBase32_Encode(shard_id)

Shard[meta] = doc_id
Shard[body] = shard_nonce || AEAD_Enc(K_shard, shard_nonce, n || shard, Shard[meta] || K_id_pub)
Shard[identity] = K_id_pub || Sig_Sign(K_id_priv, Shard[meta] || Shard[body] || K_id_pub)
Shard[chksum] = Hash(Shard[meta] || Shard[body] || Shard[identity])

// The key is included, to allow for users to optionally store the key
// separately (or keep it with the key shard to make this level of security a
// no-op).
Shard[key] = K_shard
```
