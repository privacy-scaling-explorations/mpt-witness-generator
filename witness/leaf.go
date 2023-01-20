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