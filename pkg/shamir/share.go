/*
 * paperback: resilient paper backups for the very paranoid
 * copyright (c) 2018 aleksa sarai <cyphar@cyphar.com>
 *
 * this program is free software: you can redistribute it and/or modify
 * it under the terms of the gnu general public license as published by
 * the free software foundation, either version 3 of the license, or
 * (at your option) any later version.
 *
 * this program is distributed in the hope that it will be useful,
 * but without any warranty; without even the implied warranty of
 * merchantability or fitness for a particular purpose.  see the
 * gnu general public license for more details.
 *
 * you should have received a copy of the gnu general public license
 * along with this program.  if not, see <https://www.gnu.org/licenses/>.
 */

package shamir

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

// signaturePrefix is the scheme prefix we add to all public keys when
// serialised.
const signaturePrefix = "ed25519-"

// keyIdent represents an ed25519 public key's "identity" as a string. It also
// includes a prefix for future compatibility.
func keyIdent(key ed25519.PublicKey) string {
	return signaturePrefix + base64.StdEncoding.EncodeToString(key)
}

// ShareMeta stores all of the share-independent metadata which is embedded in
// each share. This is used as a convenience struct to verify that all shares
// in a set actually refer to the same secret.
type ShareMeta struct {
	// Size is the size of the secret.
	Size uint
	// BlockSize is the block size.
	BlockSize uint
	// P is the prime defining the finite field.
	P *big.Int
	// K is the number of shares needed (degree+1).
	K uint
	// PublicKey is the public portion of the key used for signing. The
	// serialised format for this is designed to be extensible, but only
	// ed25519 is supported at the moment.
	PublicKey ed25519.PublicKey
}

// SharePayload contains all of the share information which is signed.
type SharePayload struct {
	// Meta is the share-independent metadata.
	Meta ShareMeta
	// X is the x-value used to generate the share. This value is used for all
	// of the sub-parts of Ys.
	X *big.Int
	// Ys are the y-values computed using the share polynomial for each block
	// (as defined by Meta.BS).
	Ys []*big.Int
}

// wireSharePayload is the wire format for *payload* portion of the share
// structure. The reason why we separate this from the entire Share structure
// is so that it can be signed without needing to touch JSON manually. Note
// that this representation *only* works because Go's JSON library produces
// consistent results. We have to define our own serialisation format because
// *big.Int's serialisation is incredibly wasteful, and it's much nicer to
// store the bytes base64-encoded.
type wireSharePayload struct {
	Meta struct {
		S  uint   `json:"s"`
		BS uint   `json:"bs"`
		P  string `json:"p"`
		K  uint   `json:"k"`
		PK string `json:"pubkey"`
	} `json:"meta"`
	X  string   `json:"x"`
	Ys []string `json:"ys"`
}

// wireShare converts a SharePayload to the wire format structure for the
// payload. This is lossless.
func (s SharePayload) wireSharePayload() wireSharePayload {
	var ws wireSharePayload
	ws.Meta.S = s.Meta.Size
	ws.Meta.BS = s.Meta.BlockSize
	ws.Meta.K = s.Meta.K
	ws.Meta.P = encodeBigInt(s.Meta.P)
	ws.Meta.PK = keyIdent(s.Meta.PublicKey)
	ws.X = encodeBigInt(s.X)
	for _, y := range s.Ys {
		ws.Ys = append(ws.Ys, encodeBigInt(y))
	}
	return ws
}

// share converts a wireShare to the exported Share structure. This is
// lossless.
func (ws wireSharePayload) sharePayload() (SharePayload, error) {
	var s SharePayload
	var err error

	s.Meta.Size = ws.Meta.S
	s.Meta.BlockSize = ws.Meta.BS
	s.Meta.K = ws.Meta.K
	s.Meta.P, err = decodeBigInt(ws.Meta.P)
	if err != nil {
		return s, errors.Wrap(err, "decode Meta.P")
	}

	// Sort out the public key.
	if !strings.HasPrefix(ws.Meta.PK, signaturePrefix) {
		return s, errors.Errorf("unknown signature scheme type %v", ws.Meta.PK)
	}
	pkString := strings.TrimPrefix(ws.Meta.PK, signaturePrefix)
	s.Meta.PublicKey, err = base64.StdEncoding.DecodeString(pkString)
	if err != nil {
		return s, errors.Wrap(err, "decode Meta.PK string")
	}
	if len(s.Meta.PublicKey) != ed25519.PublicKeySize {
		return s, errors.New("decode meta.PK: public key is incorrect length")
	}

	s.X, err = decodeBigInt(ws.X)
	if err != nil {
		return s, errors.Wrap(err, "decode X")
	}
	for _, y := range ws.Ys {
		val, err := decodeBigInt(y)
		if err != nil {
			return s, errors.Wrap(err, "decode Y")
		}
		s.Ys = append(s.Ys, val)
	}
	return s, nil
}

// MarshalJSON returns the JSON encoding of the share.
func (s SharePayload) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.wireSharePayload())
}

// UnmarshalJSON fills the share with the given data.
func (s *SharePayload) UnmarshalJSON(data []byte) error {
	var ws wireSharePayload
	if err := json.Unmarshal(data, &ws); err != nil {
		return errors.Wrap(err, "unmarshal share payload")
	}
	newS, err := ws.sharePayload()
	if err != nil {
		return errors.Wrap(err, "convert to share payload")
	}
	*s = newS
	return nil
}

// Sign will take a given SharePayload, sign it, and then produce a
// ShareSignature which can be embedded with the payload. Note that if the
// provided private key and the public key in the metadata don't match, and
// error is returned.
func (sp SharePayload) Sign(key ed25519.PrivateKey) (ShareSignature, error) {
	var sig ShareSignature
	// Ensure embedded public key and the key used for signing are the same.
	if !reflect.DeepEqual(sp.Meta.PublicKey, key.Public()) {
		return sig, errors.New("[internal error] embedded public key doesn't match signing key")
	}
	// Get the wire representation and sign it.
	msg, err := json.Marshal(sp)
	if err != nil {
		return sig, errors.Wrap(err, "marshal payload")
	}
	sig = ed25519.Sign(key, msg)
	return sig, nil
}

// Verify will take a given SharePayload and verify that the provided
// ShareSignature actually works. The public key is taken from the metadata of
// the SharePayload. Returns true if the verification succeeded.
func (sp SharePayload) Verify(sig ShareSignature) (bool, error) {
	// Ensure embedded public key is actually valid.
	if len(sp.Meta.PublicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("[internal error] share payload verify: embedded public key is invalid")
	}
	// Get the wire representation and verify it works.
	msg, err := json.Marshal(sp)
	if err != nil {
		return false, errors.Wrap(err, "marshal payload")
	}
	pass := ed25519.Verify(sp.Meta.PublicKey, msg, sig)
	return pass, nil
}

// ShareSignature contains the data for a share's signature.
type ShareSignature []byte

// MarshalJSON just converts the set of bytes to their base64 representation
// and puts them in a JSON string.
func (ss *ShareSignature) MarshalJSON() ([]byte, error) {
	str := base64.StdEncoding.EncodeToString(*ss)
	return json.Marshal(str)
}

// UnmarshalJSON converts a signature back to its original byte representation.
func (ss *ShareSignature) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return errors.Wrap(err, "unmarshal signature")
	}
	bytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return errors.Wrap(err, "decode signature bytes")
	}
	*ss = bytes
	return nil
}

// Share represents a single share of a given secret. It stores all of the
// necessary metadata to reconstruct the secret from the share and, when
// serialised to JSON, is self-documenting enough (assuming one has access to
// the literature) to be reconstructed without the need for this library. The
// share itself is signed in a manner that is also self-documenting.
type Share struct {
	// Safe is the payload which is signed.
	Safe SharePayload `json:"safe"`
	// Signature is the signature that is used to verify the payload.
	Signature ShareSignature `json:"sig"`
}

// ShareGrouping represents a grouping of shares where
type ShareGrouping struct {
	GroupIdx int
	Bad      bool
}

// GroupShares takes a slice of shares and generates a "grouping list" of said
// shares. This grouping list can be used to identify which shares are
// compatible with each other. In addition, if signature verification fails on
// any share (or the share is malformed in some fundamental way), the "bad"
// member in the struct will be true. The value of "GroupIdx" is not special or
// meaningful other than that all other grouped shares share the same GroupIdx.
func GroupShares(shares []Share) []ShareGrouping {
	var groupIdx int
	groupMapping := map[string]int{}
	groupings := make([]ShareGrouping, len(shares))
	for i, share := range shares {
		// Figure out the group from the previously generated mappings.
		ident := keyIdent(share.Safe.Meta.PublicKey)
		mapIdx, ok := groupMapping[ident]
		if !ok {
			groupIdx++
			mapIdx = groupIdx
		}
		groupMapping[ident] = mapIdx

		// Verify.
		good, err := share.Safe.Verify(share.Signature)
		if err != nil {
			good = false
		}

		// Add the grouping information.
		groupings[i] = ShareGrouping{
			GroupIdx: mapIdx,
			Bad:      !good,
		}
	}
	return groupings
}
