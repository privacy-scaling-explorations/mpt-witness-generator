package witness

import (
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// TODO: replace with prepareAccountLeafNode
func prepareAccountLeaf(leafS, leafC []byte, key []byte, nonExistingAccountProof, noLeaf bool) ([][]byte, [][]byte) {
	var leafRows [][]byte
	var leafForHashing [][]byte
	// When generating a proof that account doesn't exist, the length of both proofs is the same (doesn't reach
	// this code).
	keyRowS, keyRowC, nonExistingAccountRow, nonceBalanceRowS, nonceBalanceRowC, storageCodeHashRowS, storageCodeHashRowC :=
		prepareAccountLeafRows(leafS, leafC, key, nonExistingAccountProof, noLeaf)
	leafRows = append(leafRows, keyRowS)
	leafRows = append(leafRows, keyRowC)
	leafRows = append(leafRows, nonExistingAccountRow) // not really needed
	leafRows = append(leafRows, nonceBalanceRowS)
	leafRows = append(leafRows, nonceBalanceRowC)
	leafRows = append(leafRows, storageCodeHashRowS)
	leafRows = append(leafRows, storageCodeHashRowC)

	leafS = append(leafS, 5)
	leafC = append(leafC, 5)
	leafForHashing = append(leafForHashing, leafS)
	leafForHashing = append(leafForHashing, leafC)

	return leafRows, leafForHashing
}

func prepareStorageLeaf(leafS []byte, key []byte, nonExistingAccountProof bool) ([][]byte, [][]byte) {
	var leafForHashing [][]byte
	leafRows, leafForHashingS := prepareStorageLeafRows(leafS, 2, false)
	leafForHashing = append(leafForHashing, leafForHashingS)

	return leafRows, leafForHashing
}

// TODO: remove with prepareStorageLeafNode
func prepareStorageLeafRows(row []byte, typ byte, valueIsZero bool) ([][]byte, []byte) {
	// Avoid directly changing the row as it might introduce some bugs later on.
	leaf1 := make([]byte, rowLen)
	leaf2 := make([]byte, rowLen)
	typ2 := byte(13)
	if typ == 3 {
		typ2 = 14
	}
	if len(row) < 32 { // the node doesn't get hashed in this case
		// 192 + 32 = 224
		if row[1] < 128 {
			// last level: [194,32,1]
			// or
			// only one nibble in a leaf (as soon as the leaf has two nibbles, row[1] will have 128 + length)
			// [194,48,1] - this one contains nibble 0 = 48 - 48
			leaf1[0] = row[0]
			leaf1[1] = row[1]
			copy(leaf2, row[2:])
		} else {
			// [196,130,32,0,1]
			keyLen := row[1] - 128
			copy(leaf1, row[:keyLen+2])
			copy(leaf2, row[keyLen+2:])
		}
		leaf1 = append(leaf1, typ)
		leaf2 = append(leaf2, typ2)

		leafForHashing := make([]byte, len(row))
		leafForHashing = append(leafForHashing, 5) // not needed in this case
		return [][]byte{leaf1, leaf2}, leafForHashing
	}	
	if row[0] == 248 {
		// [248,67,160,59,138,106,70,105,186,37,13,38,205,122,69,158,202,157,33,95,131,7,227,58,235,229,3,121,188,90,54,23,236,52,68,161,160,...
		keyLen := row[2] - 128
		copy(leaf1, row[:keyLen+3])
		// there are two RLP meta data bytes which are put in s_rlp1 and s_rlp2,
		// value starts in s_advices[0]
		if !valueIsZero {
			copy(leaf2, row[keyLen+3:]) // RLP data in s_rlp1 and s_rlp2, value starts in s_advices[0]
		}
	} else {
		if row[1] < 128 {
			// last level:
			// [227,32,161,160,187,239,170,18,88,1,56,188,38,60,149,117,120,38,223,78,36,235,129,201,170,170,170,170,170,170,170,170,170,170,170,170]
			// one nibble:
			// [227,48,161,160,187,239,170,18,88,1,56,188,38,60,149,117,120,38,223,78,36,235,129,201,170,170,170,170,170,170,170,170,170,170,170,170]
			leaf1[0] = row[0]
			leaf1[1] = row[1]
			copy(leaf2, row[2:])
		} else {
			// [226,160,59,138,106,70,105,186,37,13,38[227,32,161,160,187,239,170,18,88,1,56,188,38,60,149,117,120,38,223,78,36,235,129,201,170,170,170,170,170,170,170,170,170,170,170,170]
			keyLen := row[1] - 128
			copy(leaf1, row[:keyLen+2])
			if !valueIsZero {
				copy(leaf2, row[keyLen+2:]) // value starts in s_rlp1
			}
		}
	}
	leaf1 = append(leaf1, typ)
	leaf2 = append(leaf2, typ2)

	leafForHashing := make([]byte, len(row))
	copy(leafForHashing, row)
	leafForHashing = append(leafForHashing, 5)

	return [][]byte{leaf1, leaf2}, leafForHashing
}

func prepareEmptyNonExistingStorageRow() []byte {	
	// nonExistingStorageRow is used only for proof that nothing is stored at a particular storage key
	nonExistingStorageRow := make([]byte, valueLen)

	return nonExistingStorageRow
}

func prepareNonExistingStorageRow(leafC, keyNibbles []byte, noLeaf bool) ([]byte, []byte) {	
	// nonExistingStorageRow is used only for proof that nothing is stored at a particular storage key
	nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
	
	var wrongRlpBytes []byte
	wrongRlpBytes = append(wrongRlpBytes, leafC[0])
	start := 2
	if leafC[0] == 248 {
		start = 3
		wrongRlpBytes = append(wrongRlpBytes, leafC[1])
	}
	keyLenC := int(leafC[start-1]) - 128
	keyRowC := make([]byte, valueLen)
	for i := 0; i < keyLenC; i++ {
		keyRowC[i] = leafC[start - 1 + i]
	}

	offset := 0	
	nibblesNum := (keyLenC - 1) * 2

	nonExistingStorageRow[0] = leafC[start - 1]
	if keyRowC[1] != 32 { // odd number of nibbles
		nibblesNum = nibblesNum + 1
		nonExistingStorageRow[1] = keyNibbles[64 - nibblesNum] + 48 
		offset = 1
	} else {
		nonExistingStorageRow[1] = 32
	}
	// Get the last nibblesNum of address:
	remainingNibbles := keyNibbles[64 - nibblesNum:64] // exclude the last one as it is not a nibble
	for i := 0; i < keyLenC-1; i++ {
		nonExistingStorageRow[2+i] = remainingNibbles[2*i + offset] * 16 + remainingNibbles[2*i+1 + offset]
	}

	return wrongRlpBytes, nonExistingStorageRow
}

// getNonceBalanceRow takes GetProof account leaf and prepares a row that contains nonce and balance.
// TODO: replace with getNonceBalanceValue
func getNonceBalanceRow(leaf []byte, keyLen int) ([]byte, int) {
	nonceStart := 3 + keyLen + 1 + 1 + 1 + 1

	var nonceRlpLen byte
	var balanceStart int
	var nonce []byte

	// If the first nonce byte is > 128, it means it presents (nonce_len - 128),
	// if the first nonce byte is <= 128, the actual nonce value is < 128 and is exactly this first byte
	// (however, when nonce = 0, the actual value that is stored is 128)
	if leaf[nonceStart] <= 128 {
		// only one nonce byte
		nonceRlpLen = 1
		nonce = leaf[nonceStart : nonceStart+int(nonceRlpLen)]
		balanceStart = nonceStart + int(nonceRlpLen)
	} else {
		nonceRlpLen = leaf[nonceStart] - 128
		nonce = leaf[nonceStart : nonceStart+int(nonceRlpLen)+1]
		balanceStart = nonceStart + int(nonceRlpLen) + 1
	}

	var balanceRlpLen byte
	var storageStart int
	if leaf[balanceStart] <= 128 {
		// only one balance byte
		balanceRlpLen = 1
		storageStart = balanceStart + int(balanceRlpLen)
	} else {
		balanceRlpLen = leaf[balanceStart] - 128
		storageStart = balanceStart + int(balanceRlpLen) + 1
	}

	nonceBalanceRow := make([]byte, rowLen)
	for i := 0; i < len(nonce); i++ {
		nonceBalanceRow[branchNodeRLPLen+i] = nonce[i]
	}
	nonceBalanceRow[0] = leaf[3+keyLen]
	nonceBalanceRow[1] = leaf[3+keyLen+1]
	nonceBalanceRow[branch2start] = leaf[3+keyLen+1+1]
	nonceBalanceRow[branch2start+1] = leaf[3+keyLen+1+1+1]
	var balance []byte
	if balanceRlpLen == 1 {
		balance = leaf[balanceStart : balanceStart+int(balanceRlpLen)]
	} else {
		balance = leaf[balanceStart : balanceStart+int(balanceRlpLen)+1]
	}
	for i := 0; i < len(balance); i++ {
		nonceBalanceRow[branch2start+2+i] = balance[i] // c_advices
	}

	return nonceBalanceRow, storageStart
}

func getNonceBalanceValue(leaf []byte, keyLen int) ([]byte, []byte, int) {
	nonceStart := 3 + keyLen + 1 + 1 + 1 + 1

	var nonceRlpLen byte
	var balanceStart int
	var nonce []byte

	// If the first nonce byte is > 128, it means it presents (nonce_len - 128),
	// if the first nonce byte is <= 128, the actual nonce value is < 128 and is exactly this first byte
	// (however, when nonce = 0, the actual value that is stored is 128)
	if leaf[nonceStart] <= 128 {
		// only one nonce byte
		nonceRlpLen = 1
		nonce = leaf[nonceStart : nonceStart+int(nonceRlpLen)]
		balanceStart = nonceStart + int(nonceRlpLen)
	} else {
		nonceRlpLen = leaf[nonceStart] - 128
		nonce = leaf[nonceStart : nonceStart+int(nonceRlpLen)+1]
		balanceStart = nonceStart + int(nonceRlpLen) + 1
	}

	var balanceRlpLen byte
	var storageStart int
	if leaf[balanceStart] <= 128 {
		// only one balance byte
		balanceRlpLen = 1
		storageStart = balanceStart + int(balanceRlpLen)
	} else {
		balanceRlpLen = leaf[balanceStart] - 128
		storageStart = balanceStart + int(balanceRlpLen) + 1
	}

	nonceVal := make([]byte, valueLen)
	balanceVal := make([]byte, valueLen)
	for i := 0; i < len(nonce); i++ {
		nonceVal[i] = nonce[i]
	}
	var balance []byte
	if balanceRlpLen == 1 {
		balance = leaf[balanceStart : balanceStart+int(balanceRlpLen)]
	} else {
		balance = leaf[balanceStart : balanceStart+int(balanceRlpLen)+1]
	}
	for i := 0; i < len(balance); i++ {
		balanceVal[i] = balance[i]
	}

	return nonceVal, balanceVal, storageStart
}

// getStorageRootCodeHashRow takes GetProof account leaf and prepares a row that contains storage root and hash root.
// TODO: replace with getStorageRootCodeHashValue
func getStorageRootCodeHashRow(leaf []byte, storageStart int) []byte {
	storageCodeHashRow := make([]byte, rowLen)
	storageRlpLen := leaf[storageStart] - 128
	if storageRlpLen != 32 {
		panic("Account leaf RLP 3")
	}
	storage := leaf[storageStart : storageStart+32+1]
	for i := 0; i < 33; i++ {
		storageCodeHashRow[i] = storage[i]
	}
	codeHashStart := storageStart + int(storageRlpLen) + 1
	codeHashRlpLen := leaf[codeHashStart] - 128
	if codeHashRlpLen != 32 {
		panic("Account leaf RLP 4")
	}
	codeHash := leaf[codeHashStart : codeHashStart+32+1]
	for i := 0; i < 33; i++ {
		storageCodeHashRow[branch2start+i] = codeHash[i]
	}

	return storageCodeHashRow
}

func getStorageRootCodeHashValue(leaf []byte, storageStart int) ([]byte, []byte) {
	storageRootValue := make([]byte, valueLen)
	codeHashValue := make([]byte, valueLen)
	storageRlpLen := leaf[storageStart] - 128
	if storageRlpLen != 32 {
		panic("Account leaf RLP 3")
	}
	storage := leaf[storageStart : storageStart+32+1]
	for i := 0; i < 33; i++ {
		storageRootValue[i] = storage[i]
	}
	codeHashStart := storageStart + int(storageRlpLen) + 1
	codeHashRlpLen := leaf[codeHashStart] - 128
	if codeHashRlpLen != 32 {
		panic("Account leaf RLP 4")
	}
	codeHash := leaf[codeHashStart : codeHashStart+32+1]
	for i := 0; i < 33; i++ {
		codeHashValue[i] = codeHash[i]
	}

	return storageRootValue, codeHashValue
}

func prepareAccountLeafRows(leafS, leafC, addressNibbles []byte, nonExistingAccountProof, noLeaf bool) ([]byte, []byte, []byte, []byte, []byte, []byte, []byte) {	
	// wrongLeaf has a meaning only for non existing account proof. For this proof, there are two cases:
	// 1. A leaf is returned that is not at the required address (wrong leaf).
	// 2. A branch is returned as the last element of getProof and
	//    there is nil object at address position. Placeholder account leaf is added in this case.
	keyLenS := int(leafS[2]) - 128
	keyLenC := int(leafC[2]) - 128
	keyRowS := make([]byte, rowLen)
	keyRowC := make([]byte, rowLen)
	for i := 0; i < 3+keyLenS; i++ {
		keyRowS[i] = leafS[i]
	}
	for i := 0; i < 3+keyLenC; i++ {
		keyRowC[i] = leafC[i]
	}

	// For non existing account proof, keyRowS (=keyRowC in this case) stores the key of
	// the wrong leaf. We store the key of the required leaf (which doesn't exist)
	// in nonExistingAccountRow.

	// nonExistingAccountRow is used only for proof that account doesn't exist
	nonExistingAccountRow := make([]byte, rowLen)
	nonExistingAccountRow = append(nonExistingAccountRow, 18)
	
	offset := 0	
	nibblesNum := (keyLenC - 1) * 2
	nonExistingAccountRow[0] = leafC[0]
	nonExistingAccountRow[1] = leafC[1]
	nonExistingAccountRow[2] = leafC[2] // length
	if keyRowC[3] != 32 { // odd number of nibbles
		nibblesNum = nibblesNum + 1
		nonExistingAccountRow[3] = addressNibbles[64 - nibblesNum] + 48
		offset = 1
	} else {
		nonExistingAccountRow[3] = 32
	}
	// Get the last nibblesNum of address:
	remainingNibbles := addressNibbles[64 - nibblesNum:64] // exclude the last one as it is not a nibble
	for i := 0; i < keyLenC-1; i++ {
		nonExistingAccountRow[4+i] = remainingNibbles[2*i + offset] * 16 + remainingNibbles[2*i+1 + offset]
	}

	nonceBalanceRowS := make([]byte, rowLen)
	nonceBalanceRowC := make([]byte, rowLen)
	storageCodeHashRowS := make([]byte, rowLen)
	storageCodeHashRowC := make([]byte, rowLen)

	if !noLeaf {
		rlpStringSecondPartLenS := leafS[3+keyLenS] - 183
		if rlpStringSecondPartLenS != 1 {
			panic("Account leaf RLP at this position should be 1 (S)")
		}
		rlpStringSecondPartLenC := leafC[3+keyLenC] - 183
		if rlpStringSecondPartLenC != 1 {
			panic("Account leaf RLP at this position should be 1 (C)")
		}
		rlpStringLenS := leafS[3+keyLenS+1]
		rlpStringLenC := leafC[3+keyLenC+1]

		// [248,112,157,59,158,160,175,159,65,212,107,23,98,208,38,205,150,63,244,2,185,236,246,95,240,224,191,229,27,102,202,231,184,80,248,78
		// In this example RLP, there are first 36 bytes of a leaf.
		// 157 means there are 29 bytes for key (157 - 128).
		// Positions 32-35: 184, 80, 248, 78.
		// 184 - 183 = 1 means length of the second part of a string.
		// 80 means length of a string.
		// 248 - 247 = 1 means length of the second part of a list.
		// 78 means length of a list.

		rlpListSecondPartLenS := leafS[3+keyLenS+1+1] - 247
		if rlpListSecondPartLenS != 1 {
			panic("Account leaf RLP 1 (S)")
		}
		rlpListSecondPartLenC := leafC[3+keyLenC+1+1] - 247
		if rlpListSecondPartLenC != 1 {
			panic("Account leaf RLP 1 (C)")
		}

		rlpListLenS := leafS[3+keyLenS+1+1+1]
		if rlpStringLenS != rlpListLenS+2 {
			panic("Account leaf RLP 2 (S)")
		}

		rlpListLenC := leafC[3+keyLenC+1+1+1]
		if rlpStringLenC != rlpListLenC+2 {
			panic("Account leaf RLP 2 (C)")
		}

		storageStartS := 0
		storageStartC := 0
		nonceBalanceRowS, storageStartS = getNonceBalanceRow(leafS, keyLenS)
		nonceBalanceRowC, storageStartC = getNonceBalanceRow(leafC, keyLenC)

		storageCodeHashRowS = getStorageRootCodeHashRow(leafS, storageStartS)
		storageCodeHashRowC = getStorageRootCodeHashRow(leafC, storageStartC)
	} 

	keyRowS = append(keyRowS, 6)
	keyRowC = append(keyRowC, 4)
	nonceBalanceRowS = append(nonceBalanceRowS, 7)
	nonceBalanceRowC = append(nonceBalanceRowC, 8)
	storageCodeHashRowS = append(storageCodeHashRowS, 9)
	storageCodeHashRowC = append(storageCodeHashRowC, 11)

	return keyRowS, keyRowC, nonExistingAccountRow, nonceBalanceRowS, nonceBalanceRowC, storageCodeHashRowS, storageCodeHashRowC
}

func prepareAccountLeafNode(addr common.Address, leafS, leafC, neighbourNode, addressNibbles []byte, nonExistingAccountProof, noLeaf bool) Node {	
	// For non existing account proof there are two cases:
	// 1. A leaf is returned that is not at the required address (wrong leaf).
	// 2. A branch is returned as the last element of getProof and
	//    there is nil object at address position. Placeholder account leaf is added in this case.
	values := make([][]byte, 12)

	keyLenS := int(leafS[2]) - 128
	keyLenC := int(leafC[2]) - 128
	keyRowS := make([]byte, valueLen)
	keyRowC := make([]byte, valueLen)

	for i := 2; i < 3+keyLenS; i++ {
		keyRowS[i-2] = leafS[i]
	}
	for i := 2; i < 3+keyLenC; i++ {
		keyRowC[i-2] = leafC[i]
	}

	var listRlpBytes [2][]byte
	listRlpBytes[0] = make([]byte, 2)
	listRlpBytes[1] = make([]byte, 2)
	for i := 0; i < 2; i++ {
		listRlpBytes[0][i] = leafS[i]
	}
	for i := 0; i < 2; i++ {
		listRlpBytes[1][i] = leafC[i]
	}

	var valueRlpBytes [2][]byte
	valueRlpBytes[0] = make([]byte, 2)
	valueRlpBytes[1] = make([]byte, 2)

	var valueListRlpBytes [2][]byte
	valueListRlpBytes[0] = make([]byte, 2)
	valueListRlpBytes[1] = make([]byte, 2)

	driftedRlpBytes := []byte{0}
	keyDrifted := make([]byte, valueLen)
	if neighbourNode != nil {
		keyDrifted, _, driftedRlpBytes, _ = prepareStorageLeafInfo(neighbourNode, false, false)
	}

	wrongValue := make([]byte, valueLen)
	wrongRlpBytes := make([]byte, 2)

	// For non existing account proof, keyRowS (=keyRowC in this case) stores the key of
	// the wrong leaf. We store the key of the required leaf (which doesn't exist)
	// in nonExistingAccountRow.

	// wrongValue is used only for proof that account doesn't exist
	
	offset := 0	
	nibblesNum := (keyLenC - 1) * 2
	wrongRlpBytes[0] = leafC[0]
	wrongRlpBytes[1] = leafC[1]
	wrongValue[0] = leafC[2] // length
	if leafC[3] != 32 { // odd number of nibbles
		nibblesNum = nibblesNum + 1
		wrongValue[1] = addressNibbles[64 - nibblesNum] + 48
		offset = 1
	} else {
		wrongValue[1] = 32
	}
	// Get the last nibblesNum of address:
	remainingNibbles := addressNibbles[64 - nibblesNum:64] // exclude the last one as it is not a nibble
	for i := 0; i < keyLenC-1; i++ {
		wrongValue[2+i] = remainingNibbles[2*i + offset] * 16 + remainingNibbles[2*i+1 + offset]
	}

	nonceValueS := make([]byte, valueLen)
	balanceValueS := make([]byte, valueLen)
	nonceValueC := make([]byte, valueLen)
	balanceValueC := make([]byte, valueLen)

	storageRootValueS := make([]byte, valueLen)
	codeHashValueS := make([]byte, valueLen)
	storageRootValueC := make([]byte, valueLen)
	codeHashValueC := make([]byte, valueLen)

	if !noLeaf {
		rlpStringSecondPartLenS := leafS[3+keyLenS] - 183
		if rlpStringSecondPartLenS != 1 {
			panic("Account leaf RLP at this position should be 1 (S)")
		}
		rlpStringSecondPartLenC := leafC[3+keyLenC] - 183
		if rlpStringSecondPartLenC != 1 {
			panic("Account leaf RLP at this position should be 1 (C)")
		}
		rlpStringLenS := leafS[3+keyLenS+1]
		rlpStringLenC := leafC[3+keyLenC+1]

		// [248,112,157,59,158,160,175,159,65,212,107,23,98,208,38,205,150,63,244,2,185,236,246,95,240,224,191,229,27,102,202,231,184,80,248,78
		// In this example RLP, there are first 36 bytes of a leaf.
		// 157 means there are 29 bytes for key (157 - 128).
		// Positions 32-35: 184, 80, 248, 78.
		// 184 - 183 = 1 means length of the second part of a string.
		// 80 means length of a string.
		// 248 - 247 = 1 means length of the second part of a list.
		// 78 means length of a list.

		rlpListSecondPartLenS := leafS[3+keyLenS+1+1] - 247
		if rlpListSecondPartLenS != 1 {
			panic("Account leaf RLP 1 (S)")
		}
		rlpListSecondPartLenC := leafC[3+keyLenC+1+1] - 247
		if rlpListSecondPartLenC != 1 {
			panic("Account leaf RLP 1 (C)")
		}

		rlpListLenS := leafS[3+keyLenS+1+1+1]
		if rlpStringLenS != rlpListLenS+2 {
			panic("Account leaf RLP 2 (S)")
		}

		rlpListLenC := leafC[3+keyLenC+1+1+1]
		if rlpStringLenC != rlpListLenC+2 {
			panic("Account leaf RLP 2 (C)")
		}

		storageStartS := 0
		storageStartC := 0
		nonceValueS, balanceValueS, storageStartS = getNonceBalanceValue(leafS, keyLenS)
		nonceValueC, balanceValueC, storageStartC = getNonceBalanceValue(leafC, keyLenC)

		valueRlpBytes[0][0] = leafS[3+keyLenS]
		valueRlpBytes[0][1] = leafS[3+keyLenS+1]

		valueRlpBytes[1][0] = leafC[3+keyLenC]
		valueRlpBytes[1][1] = leafC[3+keyLenC+1]

		valueListRlpBytes[0][0] = leafS[3+keyLenS+1+1]
		valueListRlpBytes[0][1] = leafS[3+keyLenS+1+1+1]

		valueListRlpBytes[1][0] = leafC[3+keyLenC+1+1]
		valueListRlpBytes[1][1] = leafC[3+keyLenC+1+1+1]

		storageRootValueS, codeHashValueS = getStorageRootCodeHashValue(leafS, storageStartS)
		storageRootValueC, codeHashValueC = getStorageRootCodeHashValue(leafC, storageStartC)
	} 

	values[AccountKeyS] = keyRowS
	values[AccountKeyC] = keyRowC
	values[AccountNonceS] = nonceValueS
	values[AccountBalanceS] = balanceValueS
	values[AccountStorageS] = storageRootValueS
	values[AccountCodehashS] = codeHashValueS
	values[AccountNonceC] = nonceValueC
	values[AccountBalanceC] = balanceValueC
	values[AccountStorageC] = storageRootValueC
	values[AccountCodehashC] = codeHashValueC
	values[AccountDrifted] = keyDrifted
	values[AccountWrong] = wrongValue

	leaf := AccountNode {
		Address: crypto.Keccak256(addr.Bytes()),
		ListRlpBytes: listRlpBytes,
		ValueRlpBytes: valueRlpBytes,
		ValueListRlpBytes: valueListRlpBytes,
		DriftedRlpBytes: driftedRlpBytes,
		WrongRlpBytes: wrongRlpBytes,
	}
	keccakData := [][]byte{leafS, leafC}
	if neighbourNode != nil {
		keccakData = append(keccakData, neighbourNode)
	}
	node := Node {
		Account: &leaf,
		Values: values,
		KeccakData: keccakData,
	}

	return node
}

func prepareDriftedLeafPlaceholder(isAccount bool) [][]byte {
	driftedLeaf := make([]byte, rowLen)
	driftedLeaf[0] = 248

	return [][]byte{driftedLeaf}
}

// prepareLeafAndPlaceholderNode prepares a leaf node and its placeholder counterpart
// (used when one of the proofs does not have a leaf).
func prepareLeafAndPlaceholderNode(addr common.Address, proof1, proof2 [][]byte, key []byte, nonExistingAccountProof, isAccountProof bool) Node {
	len1 := len(proof1)
	len2 := len(proof2)

	// We don't have a leaf in the shorter proof, but we will add it there
	// as a placeholder.
	if isAccountProof {
		var leafS []byte
		var leafC []byte
		if len1 > len2 {
			leafS = proof1[len1-1]
			leafC = proof1[len1-1] // placeholder
		} else {
			leafC = proof2[len2-1]
			leafS = proof2[len2-1] // placeholder
		}

		// When generating a proof that account doesn't exist, the length of both proofs is the same (doesn't reach
		// this code).
		return prepareAccountLeafNode(addr, leafS, leafC, nil, key, nonExistingAccountProof, false)
	} else {
		var leaf []byte
		isSPlaceholder := false
		isCPlaceholder := false

		if len1 > len2 {
			leaf = proof1[len1-1]
			isCPlaceholder = true
		} else {
			leaf = proof2[len2-1]
			isSPlaceholder = true
		}

		return prepareStorageLeafNode(leaf, leaf, nil, key, false, isSPlaceholder, isCPlaceholder)
	}
}

// addStorageLeafAfterBranchPlaceholder adds storage leaf rows after branch that is a placeholder.
// It also handles the case when there is a modified extension node.
func addStorageLeafAfterBranchPlaceholder(rows *[][]byte, proof1, proof2, leafRows [][]byte, neighbourNode, key []byte, nonExistingAccountProof, isModifiedExtNode, isExtension bool, numberOfNibbles int, toBeHashed *[][]byte) {
	len1 := len(proof1)
	len2 := len(proof2)

	if len1 > len2 {
		if !isModifiedExtNode {
			*rows = append(*rows, leafRows...)
			var leafForHashingC []byte
			leafRows, leafForHashingC = prepareStorageLeafRows(proof2[len2-1], 3, false)
			*rows = append(*rows, leafRows...)
			*toBeHashed = append(*toBeHashed, leafForHashingC)
		} else {
			// We do not have leaf in one of the proofs when extension node is inserted.
			// We can use the same leaf for S and C because we have the same extension
			// node and branch in the rows above (inserted extension node rows are below
			// leaf rows). We just need to make sure the row selectors are the right one.
			*rows = append(*rows, leafRows...)

			l := len(leafRows[0])
			leafKey := make([]byte, l)
			copy(leafKey, leafRows[0])
			leafKey[l - 1] = 3
			*rows = append(*rows, leafKey)

			l = len(leafRows[1])
			leafVal := make([]byte, l)
			copy(leafVal, leafRows[1])
			leafVal[l - 1] = 14
			*rows = append(*rows, leafVal)
		}	
	} else {	
		if !isModifiedExtNode {
			*rows = append(*rows, leafRows...)
			var leafForHashingC []byte
			leafRows, leafForHashingC = prepareStorageLeafRows(proof2[len2-1], 3, false)
			*rows = append(*rows, leafRows...)
			*toBeHashed = append(*toBeHashed, leafForHashingC)
		} else {
			var leafForHashingC []byte
			leafRows, leafForHashingC = prepareStorageLeafRows(proof2[len2-1], 3, false)
			// We do not have leaf in one of the proofs when extension node is inserted.
			// We can use the same leaf for S and C because we have the same extension
			// node and branch in the rows above (inserted extension node rows are below
			// leaf rows). We just need to make sure the row selectors are the right one.

			l := len(leafRows[0])
			leafKey := make([]byte, l)
			copy(leafKey, leafRows[0])
			leafKey[l - 1] = 2
			*rows = append(*rows, leafKey)

			l = len(leafRows[1])
			leafVal := make([]byte, l)
			copy(leafVal, leafRows[1])
			leafVal[l - 1] = 13
			*rows = append(*rows, leafVal)

			*rows = append(*rows, leafRows...)
			*toBeHashed = append(*toBeHashed, leafForHashingC)
		}
	}

	// The branch contains hash of the neighbouring leaf, to be able
	// to check it, we add node RLP to toBeHashed
	addForHashing(neighbourNode, toBeHashed)

	// Neighbouring leaf - the leaf that used to be one level above,
	// but it was "drifted down" when additional branch was added.
	// Only key is needed because we already have the value (it doesn't change)
	// in the parallel proof.
	if !isModifiedExtNode {
		sLeafRows, _ := prepareStorageLeafRows(neighbourNode, 15, false)
		*rows = append(*rows, sLeafRows[0])
	} else {
		pRows := prepareDriftedLeafPlaceholder(false)
		*rows = append(*rows, pRows...)	
	}
	
	// For non existing proof, S and C proofs are the same
	nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
	*rows = append(*rows, nonExistingStorageRow)
}

// addAccountLeafAfterBranchPlaceholder adds account leaf rows after branch that is a placeholder.
// It also handles the case when there is a modified extension node.
func addAccountLeafAfterBranchPlaceholder(rows *[][]byte, proof1, proof2, leafRows [][]byte, neighbourNode, key []byte, nonExistingAccountProof, isModifiedExtNode, isExtension bool, numberOfNibbles int, toBeHashed *[][]byte) {
	*rows = append(*rows, leafRows...)

	// The branch contains hash of the neighbouring leaf, to be able
	// to check it, we add node RLP to toBeHashed
	addForHashing(neighbourNode, toBeHashed)

	// Neighbouring leaf - the leaf that used to be one level above,
	// but it was "drifted down" when additional branch was added.
	// Only key is needed because we already have the value (it doesn't change)
	// in the parallel proof.
	if !isModifiedExtNode {
		h := append(neighbourNode, 5)
		*toBeHashed = append(*toBeHashed, h)

		keyRowS, _, _, _, _, _, _ :=
			prepareAccountLeafRows(neighbourNode, neighbourNode, key, nonExistingAccountProof, false)
		keyRowS = append(keyRowS, 10)
		*rows = append(*rows, keyRowS)
	} else {
		pRows := prepareDriftedLeafPlaceholder(true)
		*rows = append(*rows, pRows...)	
	}
}

// getLeafKeyLen returns the leaf key length given the key index (how many key nibbles have
// been used in the branches / extension nodes above the leaf).
func getLeafKeyLen(keyIndex int) int {
	return int(math.Floor(float64(64-keyIndex) / float64(2))) + 1
}

// setStorageLeafKeyRLP sets the RLP byte that encodes key length of the storage leaf
// to correspond to the number of keys used in the branches / extension nodes above the placeholder leaf.
func setStorageLeafKeyRLP(leaf *[]byte, key []byte, keyIndex int) {
	isEven := keyIndex % 2 == 0 
	remainingNibbles := key[keyIndex:]
	keyLen := getLeafKeyLen(keyIndex)
	(*leaf)[1] = byte(keyLen) + 128
	if isEven {
		(*leaf)[2] = 32
	} else {
		(*leaf)[2] = remainingNibbles[0] + 48
	}
}

// prepareStorageLeafPlaceholderRows prepares storage leaf placeholder rows for the cases when
// both proofs only have branches / extension nodes and no leaves (for example non existing leaf proof).
func prepareStorageLeafPlaceholderRows(key []byte, keyIndex int, nonExistingStorageProof bool) [][]byte {
	var rows [][]byte

	leaf := make([]byte, rowLen)
	setStorageLeafKeyRLP(&leaf, key, keyIndex)
	keyLen := getLeafKeyLen(keyIndex)
	leaf[0] = 192 + 1 + byte(keyLen) + 1

	leafRows, _ := prepareStorageLeafRows(leaf, 2, false)
	rows = append(rows, leafRows...)
	leafRows, _ = prepareStorageLeafRows(leaf, 3, false)
	rows = append(rows, leafRows...)

	pRows := prepareDriftedLeafPlaceholder(false)
	rows = append(rows, pRows...)	

	if nonExistingStorageProof {
		leaf := prepareEmptyNonExistingStorageRow()
		setStorageLeafKeyRLP(&leaf, key, keyIndex)
		// leaf[0] is not set here, because it is used for a flag whether it is a wrong leaf or not

		rows = append(rows, leaf)	
	} else {
		nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
		rows = append(rows, nonExistingStorageRow)	
	}

	return rows
}

// prepareAccountLeafPlaceholderRows prepares account leaf placeholder rows for the cases when
// both proofs only have branches / extension nodes and no leaves (for example non existing leaf proof).
func prepareAccountLeafPlaceholderRows(key []byte, keyIndex int, nonExistingAccountProof bool) [][]byte {
	isEven := keyIndex % 2 == 0 
	keyLen := int(math.Floor(float64(64-keyIndex) / float64(2))) + 1
	remainingNibbles := key[keyIndex:]
	offset := 0
	leaf := make([]byte, rowLen)
	leaf[0] = 248
	leaf[2] = byte(keyLen) + 128
	leaf[3 + keyLen] = 184
	leaf[3 + keyLen + 1 + 1] = 248
	leaf[3 + keyLen + 1 + 1 + 1] = leaf[3 + keyLen + 1] - 2
	if isEven {
		leaf[3] = 32
	} else {
		leaf[3] = remainingNibbles[0] + 48
		offset = 1
	}
	for i := 0; i < keyLen - 1; i++ {
		leaf[4+i] = remainingNibbles[2*i + offset] * 16 + remainingNibbles[2*i + 1 + offset]
	}
	
	leafRows, _ := prepareAccountLeaf(leaf, leaf, key, nonExistingAccountProof, true)

	leafRows[0][1] = byte(keyLen) + 73
	leafRows[1][1] = byte(keyLen) + 73
	leafRows[3][0] = 184
	leafRows[3][1] = 70
	leafRows[3][2] = 128
	leafRows[3][branch2start] = 248
	leafRows[3][branch2start + 1] = 68
	leafRows[3][branch2start + 2] = 128

	leafRows[4][0] = 184
	leafRows[4][1] = 70
	leafRows[4][2] = 128
	leafRows[4][branch2start] = 248
	leafRows[4][branch2start + 1] = 68
	leafRows[4][branch2start + 2] = 128
	
	leafRows[5][0] = 160
	leafRows[5][branch2start] = 160
	leafRows[6][0] = 160
	leafRows[6][branch2start] = 160

	pRows := prepareDriftedLeafPlaceholder(true)
	leafRows = append(leafRows, pRows...)

	return leafRows
}

func prepareStorageLeafInfo(row []byte, valueIsZero, isPlaceholder bool) ([]byte, []byte, []byte, []byte) {
	var keyRlp []byte
	var valueRlp []byte

	var keyRlpLen byte
	var valueRlpLen byte

	key := make([]byte, valueLen)
	value := make([]byte, valueLen)
	// TODO: merge cases
	if len(row) < 32 { // the node doesn't get hashed in this case
		// 192 + 32 = 224
		if row[1] < 128 {
			// last level: [194,32,1]
			// or
			// only one nibble in a leaf (as soon as the leaf has two nibbles, row[1] will have 128 + length)
			// [194,48,1] - this one contains nibble 0 = 48 - 48
			keyRlpLen = 1
			keyLen := byte(1)
			keyRlp = row[:keyRlpLen]
			copy(key, row[keyRlpLen:keyLen+1])
			valueRlpLen = 1
			// If placeholder, we leave the value to be 0.
			if !isPlaceholder {
				valueRlp = row[keyLen+1:keyLen+1+valueRlpLen]
				if !valueIsZero {
					copy(value, row[keyLen+1+valueRlpLen:])
				}
			} else {
				valueRlp = []byte{0}
			}
		} else {
			// [196,130,32,0,1]
			/*
			keyLen := row[1] - 128
			copy(key, row[:keyLen+2])
			copy(value, row[keyLen+2:])
			*/
			keyRlpLen = 1
			keyLen := row[1] - 128
			keyRlp = row[:keyRlpLen]
			copy(key, row[keyRlpLen:keyLen+2])
			valueRlpLen = 1
			// If placeholder, we leave the value to be 0.
			if !isPlaceholder {
				valueRlp = row[keyLen+2:keyLen+2+valueRlpLen]
				if !valueIsZero {
					copy(value, row[keyLen+2+valueRlpLen:]) // value starts in s_rlp1
				}
			} else {
				valueRlp = []byte{0}
			}
		}	
	} else if row[0] == 248 {
		// [248,67,160,59,138,106,70,105,186,37,13,38,205,122,69,158,202,157,33,95,131,7,227,58,235,229,3,121,188,90,54,23,236,52,68,161,160,...
		keyRlpLen = 2
		keyLen := row[2] - 128
		keyRlp = row[:keyRlpLen]	
		copy(key, row[keyRlpLen:keyLen+3])
		valueRlpLen = 1
		valueRlp = row[keyLen+3:keyLen+3+valueRlpLen]
		// there are two RLP meta data bytes which are put in s_rlp1 and s_rlp2,
		// value starts in s_advices[0]
		if !valueIsZero {
			copy(value, row[keyLen+3+valueRlpLen:]) // RLP data in s_rlp1 and s_rlp2, value starts in s_advices[0]
		}
	} else {
		if row[1] < 128 {
			// last level:
			// [227,32,161,160,187,239,170,18,88,1,56,188,38,60,149,117,120,38,223,78,36,235,129,201,170,170,170,170,170,170,170,170,170,170,170,170]
			// one nibble:
			// [227,48,161,160,187,239,170,18,88,1,56,188,38,60,149,117,120,38,223,78,36,235,129,201,170,170,170,170,170,170,170,170,170,170,170,170]
			key[0] = row[0]
			key[1] = row[1]
			valueRlpLen = 1
			// If placeholder, we leave the value to be 0.
			if !isPlaceholder {
				valueRlp = row[2:2+valueRlpLen]
				copy(value, row[2+valueRlpLen:])
			} else {
				valueRlp = []byte{0}
			}	
		} else {
			// [226,160,59,138,106,70,105,186,37,13,38[227,32,161,160,187,239,170,18,88,1,56,188,38,60,149,117,120,38,223,78,36,235,129,201,170,170,170,170,170,170,170,170,170,170,170,170]
			keyRlpLen = 1
			keyLen := row[1] - 128
			keyRlp = row[:keyRlpLen]
			copy(key, row[keyRlpLen:keyLen+2])
			valueRlpLen = 1
			// If placeholder, we leave the value to be 0.
			if !isPlaceholder {
				valueRlp = row[keyLen+2:keyLen+2+valueRlpLen]
				if !valueIsZero {
					copy(value, row[keyLen+2+valueRlpLen:]) // value starts in s_rlp1
				}
			} else {
				valueRlp = []byte{0}
			}
		}
	}

	return key, value, keyRlp, valueRlp
}

func prepareStorageLeafNode(leafS, leafC, neighbourNode []byte, key []byte, nonExistingStorageProof, isSPlaceholder, isCPlaceholder bool) Node {
	var rows [][]byte

	keyS, valueS, listRlpBytes1, valueRlpBytes1 := prepareStorageLeafInfo(leafS, false, isSPlaceholder)

	rows = append(rows, keyS)
	rows = append(rows, valueS)

	keyC, valueC, listRlpBytes2, valueRlpBytes2 := prepareStorageLeafInfo(leafC, false, isCPlaceholder)

	rows = append(rows, keyC)	
	rows = append(rows, valueC)	

	var listRlpBytes [2][]byte
	listRlpBytes[0] = listRlpBytes1
	listRlpBytes[1] = listRlpBytes2

	var valueRlpBytes [2][]byte
	valueRlpBytes[0] = valueRlpBytes1
	valueRlpBytes[1] = valueRlpBytes2

	driftedRlpBytes := []byte{0}
	keyDrifted := make([]byte, valueLen)
	if neighbourNode != nil {
		keyDrifted, _, driftedRlpBytes, _ = prepareStorageLeafInfo(neighbourNode, false, false)
	}
	rows = append(rows, keyDrifted)

	var nonExistingStorageRow []byte
	var wrongRlpBytes []byte
	if nonExistingStorageProof {
		noLeaf := false
		wrongRlpBytes, nonExistingStorageRow = prepareNonExistingStorageRow(leafC, key, noLeaf)
	} else {
		nonExistingStorageRow = prepareEmptyNonExistingStorageRow()
	}
	rows = append(rows, nonExistingStorageRow)	

	leaf := StorageNode {
		ListRlpBytes: listRlpBytes,
		DriftedRlpBytes: driftedRlpBytes,
		WrongRlpBytes: wrongRlpBytes,
		ValueRlpBytes: valueRlpBytes,
	}
	keccakData := [][]byte{leafS, leafC}
	if neighbourNode != nil {
		keccakData = append(keccakData, neighbourNode)
	}
	node := Node {
		Values: rows,
		Storage: &leaf,
		KeccakData: keccakData,
	}

	return node
}