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
	"encoding/json"
	"math/big"
	"reflect"
)

// ShareMeta stores all of the share-independent metadata which is embedded in
// each share. This is used as a convenience struct to verify that all shares
// in a set actually refer to the same secret.
type ShareMeta struct {
	// S is the size of the secret.
	S uint
	// BS is the block size.
	BS uint
	// P is the prime defining the finite field.
	P *big.Int
	// K is the number of shares needed (degree+1).
	K uint
}

// Equal returns whether other is equal to the given ShareMeta.
func (m ShareMeta) Equal(other ShareMeta) bool {
	return reflect.DeepEqual(m, other)
}

// Share represents a single share of a given secret. It stores all of the
// necessary metadata to reconstruct the secret from the share and, when
// serialised to JSON, is self-documenting enough (assuming one has access to
// the literature) to be reconstructed without the need for this library.
type Share struct {
	// Meta is the share-independent metadata.
	Meta ShareMeta
	// X is the x-value used to generate the share. This value is used for all
	// of the sub-parts of Ys.
	X *big.Int
	// Ys are the y-values computed using the share polynomial for each block
	// (as defined by Meta.BS).
	Ys []*big.Int
}

// Equal returns whether other is equal to the given Share.
func (m Share) Equal(other Share) bool {
	return reflect.DeepEqual(m, other)
}

// Make sure that Share can be serialised and deserialised.
var _ json.Marshaler = Share{}
var _ json.Unmarshaler = &Share{}

// wireShare is the wire format for the share structure (it uses JSON as the
// serialisation format). This is necessary because *big.Int's serialisation is
// incredibly wasteful, and it's much nicer to store the bytes base64-encoded.
type wireShare struct {
	Meta struct {
		S  uint   `json:"s"`
		BS uint   `json:"bs"`
		P  string `json:"p"`
		K  uint   `json:"k"`
	} `json:"meta"`
	X  string   `json:"x"`
	Ys []string `json:"ys"`
}

// toWireShare converts a Share to the wire format structure. This is lossless.
func (s Share) toWireShare() wireShare {
	var ws wireShare
	ws.Meta.S = s.Meta.S
	ws.Meta.BS = s.Meta.BS
	ws.Meta.K = s.Meta.K
	ws.Meta.P = encodeBigInt(s.Meta.P)
	ws.X = encodeBigInt(s.X)
	for _, y := range s.Ys {
		ws.Ys = append(ws.Ys, encodeBigInt(y))
	}
	return ws
}

// toShare converts a wireShare to the exported Share structure. This is
// lossless.
func (ws wireShare) toShare() (Share, error) {
	var s Share
	var err error

	s.Meta.S = ws.Meta.S
	s.Meta.BS = ws.Meta.BS
	s.Meta.K = ws.Meta.K
	s.Meta.P, err = decodeBigInt(ws.Meta.P)
	if err != nil {
		return Share{}, err
	}
	s.X, err = decodeBigInt(ws.X)
	if err != nil {
		return Share{}, err
	}
	for _, y := range ws.Ys {
		val, err := decodeBigInt(y)
		if err != nil {
			return Share{}, err
		}
		s.Ys = append(s.Ys, val)
	}
	return s, nil
}

// MarshalJSON returns the JSON encoding of the share.
func (s Share) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.toWireShare())
}

// UnmarshalJSON fills the share with the given data.
func (s *Share) UnmarshalJSON(data []byte) error {
	var ws wireShare
	if err := json.Unmarshal(data, &ws); err != nil {
		return err
	}
	newS, err := ws.toShare()
	if err != nil {
		return err
	}
	*s = newS
	return nil
}
