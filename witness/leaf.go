package witness

// TODO: use everywhere where prepareAccountLeafRows is called

func prepareLeaf(proof1, proof2 [][]byte, key []byte, isAccountProof, nonExistingAccountProof bool) ([][]byte, [][]byte) {
	len1 := len(proof1)
	len2 := len(proof2)

	var leafRows [][]byte
	var leafForHashing [][]byte
	if isAccountProof {
		leafS := proof1[len1-1]
		leafC := proof2[len2-1]

		// When generating a proof that account doesn't exist, the length of both proofs is the same (doesn't reach
		// this code).
		keyRowS, keyRowC, nonExistingAccountRow, nonceBalanceRowS, nonceBalanceRowC, storageCodeHashRowS, storageCodeHashRowC :=
			prepareAccountLeafRows(leafS, leafC, key, nonExistingAccountProof, false)
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
	} else {
		var leafForHashingS []byte
		leafRows, leafForHashingS = prepareStorageLeafRows(proof1[len1-1], 2, false)
		leafForHashing = append(leafForHashing, leafForHashingS)
	}

	return leafRows, leafForHashing
}

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
	nonExistingStorageRow := make([]byte, rowLen)
	nonExistingStorageRow = append(nonExistingStorageRow, 19)

	return nonExistingStorageRow
}

func prepareNonExistingStorageRow(leafC, keyNibbles []byte, noLeaf bool) []byte {	
	// nonExistingStorageRow is used only for proof that nothing is stored at a particular storage key
	nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
	
	start := 2
	if leafC[0] == 248 {
		start = 3
	}
	keyLenC := int(leafC[start-1]) - 128
	keyRowC := make([]byte, rowLen)
	for i := 0; i < start+keyLenC; i++ {
		keyRowC[i] = leafC[i]
	}

	offset := 0	
	nibblesNum := (keyLenC - 1) * 2
	nonExistingStorageRow[start-1] = leafC[start-1] // length
	if keyRowC[start] != 32 { // odd number of nibbles
		nibblesNum = nibblesNum + 1
		nonExistingStorageRow[start] = keyNibbles[64 - nibblesNum] + 48 
		offset = 1
	} else {
		nonExistingStorageRow[start] = 32
	}
	// Get the last nibblesNum of address:
	remainingNibbles := keyNibbles[64 - nibblesNum:64] // exclude the last one as it is not a nibble
	for i := 0; i < keyLenC-1; i++ {
		nonExistingStorageRow[start+1+i] = remainingNibbles[2*i + offset] * 16 + remainingNibbles[2*i+1 + offset]
	}

	if !noLeaf {
		nonExistingStorageRow[0] = 1 // whether it is wrong leaf
	}

	return nonExistingStorageRow
}

func getNonceBalanceRow(leaf, nonce []byte, keyLen, balanceStart int, balanceRlpLen byte) []byte {
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

	return nonceBalanceRow
}

func getStorageCodeHashRow(leaf []byte, storageStart int) []byte {
	storageCodeHashRow := make([]byte, rowLen)
	storageRlpLen := leaf[storageStart] - 128
	if storageRlpLen != 32 {
		panic("Account leaf RLP 3")
	}
	storage := leaf[storageStart : storageStart+32+1]
	for i := 0; i < 33; i++ {
		storageCodeHashRow[branchNodeRLPLen-1+i] = storage[i]
	}
	codeHashStart := storageStart + int(storageRlpLen) + 1
	codeHashRlpLen := leaf[codeHashStart] - 128
	if codeHashRlpLen != 32 {
		panic("Account leaf RLP 4")
	}
	codeHash := leaf[codeHashStart : codeHashStart+32+1]
	for i := 0; i < 33; i++ {
		storageCodeHashRow[branch2start+1+i] = codeHash[i] // start from c_rlp2
	}

	return storageCodeHashRow
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

	// for non-existing account proof we have leafS = leafC
	if nonExistingAccountProof && !noLeaf {
		nonExistingAccountRow[0] = 1 // whether it is wrong leaf
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

		nonceStartS := 3 + keyLenS + 1 + 1 + 1 + 1
		nonceStartC := 3 + keyLenC + 1 + 1 + 1 + 1

		var nonceRlpLenS byte
		var nonceRlpLenC byte
		var balanceStartS int
		var balanceStartC int
		var nonceS []byte
		var nonceC []byte
		// If the first nonce byte is > 128, it means it presents (nonce_len - 128),
		// if the first nonce byte is <= 128, the actual nonce value is < 128 and is exactly this first byte
		// (however, when nonce = 0, the actual value that is stored is 128)
		if leafS[nonceStartS] <= 128 {
			// only one nonce byte
			nonceRlpLenS = 1
			nonceS = leafS[nonceStartS : nonceStartS+int(nonceRlpLenS)]
			balanceStartS = nonceStartS + int(nonceRlpLenS)
		} else {
			nonceRlpLenS = leafS[nonceStartS] - 128
			nonceS = leafS[nonceStartS : nonceStartS+int(nonceRlpLenS)+1]
			balanceStartS = nonceStartS + int(nonceRlpLenS) + 1
		}
		if leafC[nonceStartC] <= 128 {
			// only one nonce byte
			nonceRlpLenC = 1
			nonceC = leafC[nonceStartC : nonceStartC+int(nonceRlpLenC)]
			balanceStartC = nonceStartC + int(nonceRlpLenC)
		} else {
			nonceRlpLenC = leafC[nonceStartC] - 128
			nonceC = leafC[nonceStartC : nonceStartC+int(nonceRlpLenC)+1]
			balanceStartC = nonceStartC + int(nonceRlpLenC) + 1
		}

		var balanceRlpLenS byte
		var balanceRlpLenC byte
		var storageStartS int
		var storageStartC int
		if leafS[balanceStartS] <= 128 {
			// only one balance byte
			balanceRlpLenS = 1
			storageStartS = balanceStartS + int(balanceRlpLenS)
		} else {
			balanceRlpLenS = leafS[balanceStartS] - 128
			storageStartS = balanceStartS + int(balanceRlpLenS) + 1
		}
		if leafC[balanceStartC] <= 128 {
			// only one balance byte
			balanceRlpLenC = 1
			storageStartC = balanceStartC + int(balanceRlpLenC)
		} else {
			balanceRlpLenC = leafC[balanceStartC] - 128
			storageStartC = balanceStartC + int(balanceRlpLenC) + 1
		}

		nonceBalanceRowS = getNonceBalanceRow(leafS, nonceS, keyLenS, balanceStartS, balanceRlpLenS)
		nonceBalanceRowC = getNonceBalanceRow(leafC, nonceC, keyLenC, balanceStartC, balanceRlpLenC)

		storageCodeHashRowS = getStorageCodeHashRow(leafS, storageStartS)
		storageCodeHashRowC = getStorageCodeHashRow(leafC, storageStartC)
	} 

	keyRowS = append(keyRowS, 6)
	keyRowC = append(keyRowC, 4)
	nonceBalanceRowS = append(nonceBalanceRowS, 7)
	nonceBalanceRowC = append(nonceBalanceRowC, 8)
	storageCodeHashRowS = append(storageCodeHashRowS, 9)
	storageCodeHashRowC = append(storageCodeHashRowC, 11)

	return keyRowS, keyRowC, nonExistingAccountRow, nonceBalanceRowS, nonceBalanceRowC, storageCodeHashRowS, storageCodeHashRowC
}