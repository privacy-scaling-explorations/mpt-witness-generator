package witness

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
)

// finalizeProof equips proof with intermediate state roots, first level info, counter, address RLC,
// modification tag (whether it is storage / nonce / balance change).
func finalizeProof(ind int, newProof [][]byte, addrh []byte, sRoot, cRoot, startRoot, finalRoot common.Hash, mType ModType) [][]byte {
	firstLevelBoundary := branchRows
	if newProof[0][len(newProof[0])-1] == AccountLeafKeySRow {
		// This happens when account leaf is without branch / extension node.
		firstLevelBoundary = accountLeafRows
	}

	isStorageMod := byte(0)
	isNonceMod := byte(0)
	isBalanceMod := byte(0)
	isCodeHashMod := byte(0)
	isAccountDeleteMod := byte(0)
	isNonExistingAccount := byte(0)
	isNonExistingStorage := byte(0)
	if mType == StorageMod {
		isStorageMod = 1
	} else if mType == NonceMod {
		isNonceMod = 1
	} else if mType == BalanceMod {
		isBalanceMod = 1
	} else if mType == CodeHashMod {
		isCodeHashMod = 1
	} else if mType == CreateAccount {
		isNonceMod = 1 // TODO: setting as nonce mod for now, this depends on the lookup
	} else if mType == DeleteAccount {
		isAccountDeleteMod = 1
	} else if mType == NonExistingAccount {
		isNonExistingAccount = 1
	} else if mType == NonExistingStorage {
		isNonExistingStorage = 1
	}

	counter := make([]byte, counterLen)
	binary.BigEndian.PutUint32(counter[0:4], uint32(ind))

	proof := [][]byte{}
	for j := 0; j < len(newProof); j++ {
		notFirstLevel := byte(1)
		if j < firstLevelBoundary {
			notFirstLevel = 0
		}
		r := finalizeProofEl(newProof[j], sRoot.Bytes(), cRoot.Bytes(), addrh, counter, notFirstLevel, 
			isStorageMod, isNonceMod, isBalanceMod, isCodeHashMod, isAccountDeleteMod, isNonExistingAccount,
			isNonExistingStorage)
		proof = append(proof, r)
	}
	insertPublicRoot(newProof, startRoot.Bytes(), finalRoot.Bytes())

	return proof
}

// finalizeProofEl equips proof element with intermediate state roots, first level info, counter, address RLC,
// modification tag (whether it is storage / nonce / balance change).
func finalizeProofEl(proofEl, sRoot, cRoot, address, counter []byte, notFirstLevel, isStorageMod, isNonceMod, isBalanceMod, isCodeHashMod, isAccountDeleteMod, isNonExistingAccount, isNonExistingStorage byte) []byte {
	// The last byte (-1) in a row determines the type of the row.
	// Byte -2 determines whether it's the first level or not.
	// Bytes before that store intermediate final and end roots.
	l := len(proofEl)
	extendLen := 64 + 32 + 32 + counterLen + 1 + 7
	extended := make([]byte, l + extendLen) // make space for 32 + 32 + 32 + 1 (s hash, c hash, public_root, notFirstLevel)
	copy(extended, proofEl)
	extended[l+extendLen-1] = extended[l-1] // put selector to the last place
	for i := 0; i < len(sRoot); i++ {
		extended[l-1+i] = sRoot[i]
	}
	for i := 0; i < len(cRoot); i++ {
		extended[l-1+len(sRoot)+i] = cRoot[i]
	}
	for i := 0; i < len(address); i++ {
		extended[l-1+len(sRoot) + len(cRoot) + i] = address[i]
	}
	for i := 0; i < len(counter); i++ {
		extended[l-1+len(sRoot) + len(cRoot) + len(address) + i] = counter[i]
	}
	// public root set later

	extended[l+extendLen-2] = notFirstLevel
	extended[l+extendLen-3] = isStorageMod
	extended[l+extendLen-4] = isNonceMod
	extended[l+extendLen-5] = isBalanceMod
	extended[l+extendLen-6] = isCodeHashMod
	extended[l+extendLen-7] = isAccountDeleteMod
	extended[l+extendLen-8] = isNonExistingAccount
	extended[l+extendLen-9] = isNonExistingStorage

	return extended
}

// insertPublicRoot adds start and final root to the proof.
func insertPublicRoot(proof [][]byte, startRoot, finalRoot []byte) {
	for i := 0; i < len(proof); i++ {
		l := len(proof[i])
		if i == 0 {
			for j := 0; j < 32; j++ {
				proof[i][l - 32 - 6 + j] = startRoot[j]
			}
		} else {
			for j := 0; j < 32; j++ {
				proof[i][l - 32 - 6 + j] = finalRoot[j]
			}
		}
	}
}

