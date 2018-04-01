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

package schema

import (
	"bytes"

	"github.com/cyphar/paperback/pkg/crypto"
)

// Master is the type of the plaintext document. The encrypted variant can be
// created using Encrypt(). This is just an alias for []byte but is used for
// type-safety.
type Master []byte

// EncryptedMaster is the type of the armored and OpenPGP encrypted blob that
// is published as the master document payload. It can be decrypted using
// Decrypt. This is just an alias for []byte but is used for type-safety.
type EncryptedMaster []byte

// Encrypt takes the given master and then returns the encrypted version. This
// is the recommended way of handling encryption of master documents as this
// way it will remain consistent.
func (m Master) Encrypt(passphrase []byte) (EncryptedMaster, error) {
	masterBuffer := bytes.NewBuffer(m)
	return crypto.Encrypt(masterBuffer, passphrase)
}

// Decrypt takes the given encrypted master and then returns the decrypted
// version. This is the recommended way of handling decryption of master
// documents as this way it will remain consistent.
func (em EncryptedMaster) Decrypt(passphrase []byte) (Master, error) {
	encryptedMasterBuffer := bytes.NewBuffer(em)
	return crypto.Decrypt(encryptedMasterBuffer, passphrase)
}
