## paperback ##

A paper-based backup scheme that is secure, easy-to-use, and is distributed in
a way that can be securely recovered without the need to remember a secret
passphrase.

`paperback` creates several PDFs which you can then print out and laminate,
ready for recovery. The key selling-point of `paperback` is that the data is
encrypted, and the key needed to decrypt the data is split into multiple pieces
that can then be shared with semi-trusted people. It also supports (k, n)
redundancy, which means that you can share `n` pieces of your backup
but only need `k` pieces in order to recover it.

"Semi-trusted" in this context means that you must be sure of the following two
statements about the parties you've given pieces to:

1. At any time, at least `k` of the parties you've given pieces to will provide
   you with the data you gave them. This is important to consider, as human
   relationships can change over time, and your friend today may not be your
   friend tomorrow.

2. At any time, no party will maliciously collude with more than `k-1` other
   parties in order to decrypt your backup information (however if you are
   incapacitated, you could organise with the parties to cooperate only in that
   instance).  Shamir called this having a group of "mutually suspicious
   individuals with conflicting interests". Ideally each of the parties will be
   unaware of each other (or how many parties there are), and would only come
   forward based on pre-arranged agreements with you. In practice a person's
   social graph is quite interconnected, so a higher level of trust is
   required.

By using this "sharded key" sheme, you can create an encrypted backup which
uses a passphrase that only can be obtained by the parties you've chosen
providing enough pieces of the key. No individual knows the key (not even you),
and thus no party can be compelled to provide the key without the consent of
`k-1` other parties.

Each party will get a copy of their unique "key shard", and optionally a copy
of the "master document" (though this is not necessary, and in some situations
you might want to store it separately so that even if the parties collude they
cannot use the "master key" as they do not have the "master document"). We
recommend laminating all of the relevant documents, and printing them duplex
(with each page containing the same page on both sides).

Note that due to the cryptography used by this "sharded key" scheme ([Shamir
Secret Sharing][shamir]), each individual piece of the key is completely
useless without enough other key pieces. An attacker with `k-1` key pieces
mathematically has no more information than an attacker with no key pieces.
This is a key part of the security offered by `paperback`.

> *NOTE*: In future, I may add the ability to have a "backdoor" key for the
> master document, but this feature needs to be considered carefully.  By
> having a backdoor key, you can potentially now be compelled to provide the
> key to your backup (though you still have the above benefits in the case
> where you are incapacitated, or reach some pre-arranged agreement).

[shamir]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing

### Overview ###

`paperback`'s design is explained more completely in [the design
document](/DESIGN.md). A short overview is included here, explaining in simple
terms how `paperback` works. `paperback` provides clear instructions on the
output PDFs for non-technical users to use with the interactive prompts in
`paperback restore`.

When you construct a `paperback` backup, the data you want backed up is
encrypted with a randomly-generated passphrase. In order for anyone to be able
to decrypt the data, they need to have access to the randomly-generated
passphrase. Within `paperback` this document is called the "master document",
and is provided in a PDF of its own.

The randomly-generated passphrase above is called the "master key" and is not
stored anywhere. Instead, it is broken into several "key shards" (with `n`
"key shards" generated, and only `k` are required to reconstruct the "master
key"). Each "key shard" is then encrypted with a randomly-generated passphrase
made up of "shard codewords" which then can be stored separately from the "key
shard" -- then the "key shard" (along with its "shard codeword") are stored in
individual PDFs.

**NB** these individual PDFs should be securely destroyed as soon as they are
printed out, and the printouts should not be stored in the same place for
extended periods of time. As discussed above, only `k` shards are required to
reconstruct the master key -- so storing all of the shards in the same place is
the same as storing your master key.

> *NOTE*: This final layer of "shard codeword" encryption is **not** vital to
> the security of your `paperback` backup. Each individual "key shard" provides
> zero information to an attacker about the "master key". This final layer
> serves to provide an optional additional layer of security, where a party
> that is particularly security-conscious could store the "shard codeword"
> separately from the "key shard" and thus if the "key shard" is stolen it is
> rendered *even more* useless without the "shard codeword".

> *NOTE*: In future I plan to add the ability to choose a secret "shard
>         codeword" for "key shards", so that especially paranoid parties can
>         be even more assured of the security of the individual shards.

`paperback` has to encode quite a few pieces of data into a format which will
be stored in a PDF (and then hopefully printed out). Much of this data would be
impractical to type into a computer or scan with text recognition software. In
order to solve this problem, `paperback` will store the data as a series of
[Data Matrix ECC200][datamatrix] barcodes which can be scanned by most
smartphone apps. This format is extremely widely used in a variety of
industries and is defined in [ISO/IEC 16022:2006][iso16022:2006].

In order to avoid a situation where this tool is no longer available at the
time of the recovery, `paperback` also generates a detailed technical appendix
which can also be printed out and stored with the backup. The intention of this
appendix is to future-proof the backup essentially indefinitely, such that a
reasonably technically-talented user can write a tool to reconstruct the data.

[datamatrix]: https://en.wikipedia.org/wiki/Data_Matrix
[iso16022:2006]: https://www.iso.org/standard/44230.html

### Paper Choices and Storage ###

One of the most important things when considering using `paperback` is to keep
in mind that the integrity of the backup is only as good as the paper you print
it on. Most "cheap" copy paper contains some levels of acid (either from
processing or from the lignin in wood pulp), and thus after a few years will
begin to yellow and become brittle. Archival paper is a grade of paper that is
designed to last longer than ordinary copy paper, and has standardised
requirements for acidity levels and so on. The [National Archives of
Australia][naa-standard] have an even more stringent standard for Archival
paper and will certify consumer-level archival paper if it meets their strict
requirements. Though archival paper is quite a bit more expensive than copy
paper, you can consider it a fairly minor cost (as most users won't need more
than 50 sheets). If archival paper is too expensive, try to find alkaline or
acid-free paper (you can ask your state or local library if they have any
recommendations).

In addition, while using **hot** lamination on a piece of paper may make the
document more resistant to spills and everyday damage, [the lamination process
can cause documents to deteriorate faster][anthropology-lamination] due to the
material most lamination pouches are made from (not to mention that the process
is fairly hard to reverse).  Encapsulation is a process similar to lamination,
except that the laminate is usually made of more inert materials like BoPET
(Mylar) and only the edges are sealed with tape or thread (allowing the
document to be removed). Archival-grade polyester sleeves are more expensive
than lamination pouches, though they are not generally prohibitively expensive
(you can find ~AU$1 sleeves online).

The required lifetime of a `paperback` backup is entire up to the user, and so
making the right price-versus-longevity tradeoff is fairly personal. However,
if you would like your backups to last indefinitely, I would recommend looking
at the [National Archives of Australia's website][naa-preserving-paper] which
documents in quite some detail what common mistakes are made when trying to
preserve paper documents.

It is recommended that you explain some of the best practices of storing
backups to the people you've given shard backups to -- as they are the people
who are in charge of keeping your backups safe and intact.

[naa-standard]: http://www.naa.gov.au/information-management/managing-information-and-records/preserving/physical-records-pres/archival-quality-paper-products.aspx
[anthropology-lamination]: http://anthropology.si.edu/conservation/lamination/lamination_guidelines.htm
[naa-preserving-paper]: http://www.naa.gov.au/information-management/managing-information-and-records/preserving/artworks.aspx

### License ###

`paperback` is licensed under the terms of the GNU GPLv3+.

```
paperback: resilient paper backups for the very paranoid
Copyright (C) 2018 Aleksa Sarai <cyphar@cyphar.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
