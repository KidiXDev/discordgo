//go:build libdave && cgo
// +build libdave,cgo

package dave

// #include <dave/dave.h>
import "C"

import "errors"

// Sentinel errors returned by the decryptor/encryptor. Wrap with fmt.Errorf
// via %w at call sites that want to add context.
var (
	ErrEncryptFailed       = errors.New("dave: encryption failed")
	ErrEncryptMissingKey   = errors.New("dave: encryptor missing key ratchet")
	ErrEncryptMissingCrypt = errors.New("dave: encryptor missing cryptographic context")
	ErrEncryptTooManyTries = errors.New("dave: encryptor exceeded retry limit")

	ErrDecryptFailed       = errors.New("dave: decryption failed")
	ErrDecryptMissingKey   = errors.New("dave: decryptor missing key ratchet")
	ErrDecryptInvalidNonce = errors.New("dave: decryptor saw invalid nonce")
	ErrDecryptMissingCrypt = errors.New("dave: decryptor missing cryptographic context")
)

func encryptResultErr(code C.DAVEEncryptorResultCode) error {
	switch code {
	case C.DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS:
		return nil
	case C.DAVE_ENCRYPTOR_RESULT_CODE_ENCRYPTION_FAILURE:
		return ErrEncryptFailed
	case C.DAVE_ENCRYPTOR_RESULT_CODE_MISSING_KEY_RATCHET:
		return ErrEncryptMissingKey
	case C.DAVE_ENCRYPTOR_RESULT_CODE_MISSING_CRYPTOR:
		return ErrEncryptMissingCrypt
	case C.DAVE_ENCRYPTOR_RESULT_CODE_TOO_MANY_ATTEMPTS:
		return ErrEncryptTooManyTries
	}
	return ErrEncryptFailed
}

func decryptResultErr(code C.DAVEDecryptorResultCode) error {
	switch code {
	case C.DAVE_DECRYPTOR_RESULT_CODE_SUCCESS:
		return nil
	case C.DAVE_DECRYPTOR_RESULT_CODE_DECRYPTION_FAILURE:
		return ErrDecryptFailed
	case C.DAVE_DECRYPTOR_RESULT_CODE_MISSING_KEY_RATCHET:
		return ErrDecryptMissingKey
	case C.DAVE_DECRYPTOR_RESULT_CODE_INVALID_NONCE:
		return ErrDecryptInvalidNonce
	case C.DAVE_DECRYPTOR_RESULT_CODE_MISSING_CRYPTOR:
		return ErrDecryptMissingCrypt
	}
	return ErrDecryptFailed
}
