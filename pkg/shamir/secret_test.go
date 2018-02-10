/*
 * paperback: resilient paper backups for the very paranoid
 * Copyright (C) 2018 Aleksa Sarai <cyphar@cyphar.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package shamir

import (
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"

	"golang.org/x/crypto/ed25519"
)

// TestSecretWireFormatting makes sure that random (internal) secrets can
// round-trip through JSON.
func TestSecretWireFormatting(t *testing.T) {
	for _, secret := range secretVectors {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		internalBytes, err := json.Marshal(secretFormat{
			Version: schemaVersion,
			Key:     privateKey,
			Data:    secret,
		})
		if err != nil {
			t.Errorf("failed to marshal: %v", err)
			continue
		}
		var internalSecret secretFormat
		if err := json.Unmarshal(internalBytes, &internalSecret); err != nil {
			t.Errorf("failed to unmarshal: %v", err)
			continue
		}

		// Make sure each share is identical to the original.
		if !reflect.DeepEqual(secret, internalSecret.Data) {
			t.Errorf("round-trip doesn't produce idential secret: expected %v got %v", secret, internalSecret.Data)
		}
	}
}
