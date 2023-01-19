package witness

import (
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/miha-stopar/mpt/state"
	"github.com/miha-stopar/mpt/trie"
)

// prepareBranchWitness takes the rows that are to be filled with branch data and it takes
// a branch as returned by GetProof. There are 19 rows for a branch and prepareBranchWitness
// fills the rows from index 1 to index 16 (index 0 is init, index 17 and 18 are for extension
// node when it applies). The parameter branchStart depends on whether it is S or C branch -
// S occupies the first 34 columns, C occupies the next 34 columns.
// The branch children are positioned each in its own row.
func prepareBranchWitness(rows [][]byte, branch []byte, branchStart int, branchRLPOffset int) {
	rowInd := 1 // start with 1 because rows[0] contains some RLP data
	colInd := branchNodeRLPLen

	i := 0
	insideInd := -1
	for {
		if (branchRLPOffset + i == len(branch) - 1) { // -1 because of the last 128 (branch value)
			break
		}
		b := branch[branchRLPOffset+i]
		if insideInd == -1 && b == 128 {
			rows[rowInd][branchStart + branchNodeRLPLen] = b
			rowInd++
		} else if insideInd == -1 && b != 128 {
			if b == 160 {
				insideInd = 32
				colInd = branchNodeRLPLen - 1
			} else {
				// non-hashed node
				insideInd = int(b) - 192
				colInd = branchNodeRLPLen
			}
			rows[rowInd][branchStart + colInd] = b
		} else {
			colInd++
			rows[rowInd][branchStart + colInd] = b
			if insideInd == 1 {
				insideInd = -1
				rowInd++
				colInd = 0
			} else {
				insideInd--
			}
		}	

		i++
	}	
}

// prepareTwoBranches takes two branches (named S and C) as returned by GetProof and returns
// 19 rows. The first row is branch init row which contains information of how long is each
// of the two branches, at which child the change occurs, whether the branch is a placeholder.
// The following 16 rows present branch children: S branch occupies the first 34 columns,
// C branch occupies the next 34 columns. The last two rows present the extension node (when
// a branch is in an extension node, otherwise all 0s).
//
// Example:
// [1 0 1 0 248 241 0 248 241 0 1 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
// [0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
// [0 160 164 92 78 34 81 137 173 236 78 208 145 118 128 60 46 5 176 8 229 165 42 222 110 4 252 228 93 243 26 160 241 85 0 160 95 174 59 239 229 74 221 53 227 115 207 137 94 29 119 126 56 209 55 198 212 179 38 213 219 36 111 62 46 43 176 168 1]
// [0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
// [0 160 60 157 212 182 167 69 206 32 151 2 14 23 149 67 58 187 84 249 195 159 106 68 203 199 199 65 194 33 215 102 71 138 0 160 60 157 212 182 167 69 206 32 151 2 14 23 149 67 58 187 84 249 195 159 106 68 203 199 199 65 194 33 215 102 71 138 1]
// [0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
// [0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
// [0 160 21 230 18 20 253 84 192 151 178 53 157 0 9 105 229 121 222 71 120 109 159 109 9 218 254 1 50 139 117 216 194 252 0 160 21 230 18 20 253 84 192 151 178 53 157 0 9 105 229 121 222 71 120 109 159 109 9 218 254 1 50 139 117 216 194 252 1]
// [0 160 229 29 220 149 183 173 68 40 11 103 39 76 251 20 162 242 21 49 103 245 160 99 143 218 74 196 2 61 51 34 105 123 0 160 229 29 220 149 183 173 68 40 11 103 39 76 251 20 162 242 21 49 103 245 160 99 143 218 74 196 2 61 51 34 105 123 1]
// [0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
// [0 160 0 140 67 252 58 164 68 143 34 163 138 133 54 27 218 38 80 20 142 115 221 100 73 161 165 75 83 53 8 58 236 1 0 160 0 140 67 252 58 164 68 143 34 163 138 133 54 27 218 38 80 20 142 115 221 100 73 161 165 75 83 53 8 58 236 1 1]
// [0 160 149 169 206 0 129 86 168 48 42 127 100 73 109 90 171 56 216 28 132 44 167 14 46 189 224 213 37 0 234 165 140 236 0 160 149 169 206 0 129 86 168 48 42 127 100 73 109 90 171 56 216 28 132 44 167 14 46 189 224 213 37 0 234 165 140 236 1]
// [0 160 42 63 45 28 165 209 201 220 231 99 153 208 48 174 250 66 196 18 123 250 55 107 64 178 159 49 190 84 159 179 138 235 0 160 42 63 45 28 165 209 201 220 231 99 153 208 48 174 250 66 196 18 123 250 55 107 64 178 159 49 190 84 159 179 138 235 1]
// [0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
// [0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
// [0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
// [0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
// [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 16]
// [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 17]
func prepareTwoBranches(branch1, branch2 []byte, key, branchC16, branchC1 byte, isBranchSPlaceholder, isBranchCPlaceholder bool) [][]byte {
	rows := make([][]byte, 17)
	rows[0] = make([]byte, rowLen)

	// Branch (length 21 = 213 - 192) with one byte of RLP meta data
	// [213,128,194,32,1,128,194,32,1,128,128,128,128,128,128,128,128,128,128,128,128,128]

	// Branch (length 83) with two bytes of RLP meta data
	// [248,81,128,128,...

	// Branch (length 340) with three bytes of RLP meta data
	// [249,1,81,128,16,...

	if branch1[0] < 192 + 32 {
		rows[0][isBranchSNonHashedPos] = 1
	} else {
		rows[0][isBranchSNonHashedPos] = 0
	}
	if branch2[0] < 192 + 32 {
		rows[0][isBranchCNonHashedPos] = 1
	} else {
		rows[0][isBranchCNonHashedPos] = 0
	}

	// branch init:
	// bytes 0 and 1: whether branch S has 2 or 3 RLP meta data bytes
	// bytes 2 and 3: whether branch C has 2 or 3 RLP meta data bytes
	// bytes 4 and 5: branch S RLP meta data bytes
	// byte 6: branch S RLP meta data byte (if there are 3 RLP meta data bytes in branch S)
	// bytes 7 and 8: branch C RLP meta data bytes
	// byte 9: branch C RLP meta data byte (if there are 3 RLP meta data bytes in branch C)

	branch1RLPOffset := 2
	rows[0][0] = 1 // 1 0 means two RLP bytes
	rows[0][1] = 0
	if branch1[0] == 249 {
		branch1RLPOffset = 3
		rows[0][0] = 0 // 0 1 means three RLP bytes
		rows[0][1] = 1
	} else if branch1[0] < 248 {
		branch1RLPOffset = 1
		rows[0][0] = 1 // 1 1 means one RLP byte
		rows[0][1] = 1
	}

	branch2RLPOffset := 2
	rows[0][2] = 1 // 1 0 means two RLP bytes
	rows[0][3] = 0
	if branch2[0] == 249 {
		branch2RLPOffset = 3
		rows[0][2] = 0 // 0 1 means three RLP bytes
		rows[0][3] = 1
	} else if branch2[0] < 248 {
		branch2RLPOffset = 1
		rows[0][2] = 1 // 1 1 means one RLP byte
		rows[0][3] = 1
	}

	// Let's put in the 0-th row some RLP data (the length of the whole branch RLP)
	rows[0][4] = branch1[0]
	rows[0][7] = branch2[0]

	if branch1RLPOffset >= 2 {
		rows[0][5] = branch1[1]
	}

	if branch2RLPOffset >= 2 {
		rows[0][8] = branch2[1]
	}

	if branch1RLPOffset == 3 {
		rows[0][6] = branch1[2]
	}

	if branch2RLPOffset == 3 {
		rows[0][9] = branch2[2]
	}

	rows[0][keyPos] = key

	if isBranchSPlaceholder {
		rows[0][isBranchSPlaceholderPos] = 1
	}
	if isBranchCPlaceholder {
		rows[0][isBranchCPlaceholderPos] = 1
	}

	rows[0][isBranchC16Pos] = branchC16
	rows[0][isBranchC1Pos] = branchC1

	for i := 1; i < 17; i++ {
		rows[i] = make([]byte, rowLen)
		// assign row type
		if i == 0 {
			rows[i][rowLen-1] = BranchInitRow
		} else {
			rows[i][rowLen-1] = BranchChildRow
		}
	}

	// Fill rows 1 - 16 (columns 0 - 33) with S branch:
	prepareBranchWitness(rows, branch1, 0, branch1RLPOffset)
	// Fill rows 1 - 16 (columns 34 - 67) with C branch:
	prepareBranchWitness(rows, branch2, 2+32, branch2RLPOffset)

	return rows
}

// prepareParallelBranches takes two branches (named S and C) as returned by GetProof and returns
// the MPT circuit witness of two branches in 19 rows.
// Note that the MPT circuit branch witness is equipped with some additional
// information in the first witness row (named branch init row):
//  - modifiedIndex tells us at which position in the branch the change occurred;
//  - branchC16/branchC1 tells us how many address (if account proof) or key (if storage proof) nibbles
//    have been used up to this branch;
//  - isCPlaceholder tells us whether the C branch is a placeholder.
//
// An example of branch (with two children) returned by GetProof:
// [213,128,194,32,1,128,194,32,1,128,128,128,128,128,128,128,128,128,128,128,128,128]
func prepareParallelBranches(branch1, branch2 []byte, modifiedIndex byte, isCPlaceholder bool, branchC16, branchC1 byte, insertedExtension bool) ([][]byte, []byte) {
	isBranchSPlaceholder := false
	isBranchCPlaceholder := false
	if isCPlaceholder {
		isBranchCPlaceholder = true
	} else {
		isBranchSPlaceholder = true
	}

	bRows := prepareTwoBranches(branch1, branch2, modifiedIndex, branchC16, branchC1, isBranchSPlaceholder, isBranchCPlaceholder)

	branchToBeHashed := branch1
	if !isCPlaceholder {
		branchToBeHashed = branch2
	}

	return bRows, branchToBeHashed
}

// getDriftedPosition returns the position in branch to which the leaf drifted because another
// leaf has been added to the same slot. This information is stored into a branch init row.
func getDriftedPosition(leafKeyRow []byte, numberOfNibbles int) byte {
	var nibbles []byte
	if leafKeyRow[0] != 248 {
		keyLen := int(leafKeyRow[1] - 128)
		if (leafKeyRow[2] != 32) && (leafKeyRow[2] != 0) { // second term is for extension node
			if leafKeyRow[2] < 32 { // extension node
				nibbles = append(nibbles, leafKeyRow[2] - 16)
			} else { // leaf
				nibbles = append(nibbles, leafKeyRow[2] - 48)
			}
		}
		for i := 0; i < keyLen - 1; i++ { // -1 because the first byte doesn't have any nibbles
			b := leafKeyRow[3 + i]
			n1 := b / 16
			n2 := b - n1 * 16
			nibbles = append(nibbles, n1)
			nibbles = append(nibbles, n2)
		}
	} else {
		keyLen := int(leafKeyRow[2] - 128)
		if (leafKeyRow[3] != 32) && (leafKeyRow[3] != 0) { // second term is for extension node
			if leafKeyRow[3] < 32 { // extension node
				nibbles = append(nibbles, leafKeyRow[3] - 16)
			} else { // leaf
				nibbles = append(nibbles, leafKeyRow[3] - 48)
			}
		}
		for i := 0; i < keyLen - 1; i++ { // -1 because the first byte doesn't have any nibbles
			b := leafKeyRow[4 + i]
			n1 := b / 16
			n2 := b - n1 * 16
			nibbles = append(nibbles, n1)
			nibbles = append(nibbles, n2)
		}
	}

	return nibbles[numberOfNibbles]
}

func addPlaceholder(statedb *state.StateDB, addr common.Address, rows *[][]byte, proof1, proof2,
		extNibblesS, extNibblesC [][]byte,
		key, neighbourNode []byte,
		keyIndex, extensionNodeInd int,
		additionalBranch, isAccountProof, nonExistingAccountProof,
		isShorterProofLastLeaf bool, branchC16, branchC1 byte, toBeHashed *[][]byte) {
	len1 := len(proof1)
	len2 := len(proof2)
	if additionalBranch {
		numberOfNibbles := 0
		var extRows [][]byte
		isExtension := (len1 == len2 + 2) || (len2 == len1 + 2)
		if !isExtension {
			extRows = prepareEmptyExtensionRows(false, false)
			if branchC16 == 1 {
				branchC16 = 0
				branchC1 = 1
			} else {
				branchC16 = 1
				branchC1 = 0
			}
		} else {
			var numNibbles byte
			var extensionRowS []byte
			var extensionRowC []byte
			if len1 > len2 {
				numNibbles, extensionRowS, extensionRowC =
					prepareExtensionRows(extNibblesS, extensionNodeInd, proof1[len1 - 3], proof1[len1 - 3], false, false)
			} else {
				numNibbles, extensionRowS, extensionRowC =
					prepareExtensionRows(extNibblesC, extensionNodeInd, proof2[len2 - 3], proof2[len2 - 3], false, false)
			}
			numberOfNibbles = int(numNibbles)
			extRows = append(extRows, extensionRowS)
			extRows = append(extRows, extensionRowC)

			// adding extension node for hashing:
			if len1 > len2 {
				addForHashing(proof1[len1-3], toBeHashed)
			} else {
				addForHashing(proof2[len2-3], toBeHashed)
			}

			if numberOfNibbles % 2 == 0 {
				if branchC16 == 1 {
					branchC16 = 0
					branchC1 = 1
				} else {
					branchC16 = 1
					branchC1 = 0
				}
			}
		}

		/*
		For special cases when a new extension node is inserted.

		Imagine you have an extension node at n1 n2 n3 n4 (where each of these is a nibble).
		Let's say this extension node has the following nibbles as the extension: n5 n6 n7.
		So at position n1 n2 n3 n4 n5 n6 n7 there is some branch.
		Now we want to add a leaf at position n1 n2 n3 n4 n5 m1 where m1 != n6.
		The adding algorithm walks through the trie, but it bumps into an extension node where
		it should put this leaf. So a new extension node is added at position n1 n2 n3 n4 which only
		has one nibble: n5. So at n1 n2 n3 n4 n5 we have a branch now. In this brach, at position m we
		have a leaf, while at position n6 we have another extension node with one extension nibble: n7.
		At this position (n7) we have the branch from the original extension node.

		When an extension node is inserted because of the added key, C proof will contain this new
		extension node and the underlying branch. However, S proof will stop at the old extension node. 
		This old extension node is not part of the C proof, but we need to ensure that it is in the C trie.
		We need to take into accout that in the C trie the old extension node has a shortened extension.

		The problem is where to store the old extension node. Note that in the above code the new
		extension node and the underlying branch rows are prepared. For example, when len2 > len1 we
		take extension node from proof2[len2 - 3] and branch from proof2[len2 - 2]. In this case,
		the old extension node in proof1[len1 - 1] has been ignored. For this reason we store it
		in the rows before we add a leaf.
		*/
		var longExtNode []byte
		if len1 > len2 {
			longExtNode = proof2[len2 - 1]
		} else {
			longExtNode = proof1[len1 - 1]
		}

		isItBranch := isBranch(longExtNode)
		// Note that isModifiedExtNode happens also when we have a branch instead of shortExtNode
		isModifiedExtNode := !isItBranch && !isShorterProofLastLeaf

		if len1 > len2 {
			bRows, branchToBeHashed := prepareParallelBranches(proof1[len1-2], proof1[len1-2], key[keyIndex + numberOfNibbles], true, branchC16, branchC1, isModifiedExtNode)
			*rows = append(*rows, bRows...)
			addForHashing(branchToBeHashed, toBeHashed)
		} else {
			bRows, branchToBeHashed := prepareParallelBranches(proof2[len2-2], proof2[len2-2], key[keyIndex + numberOfNibbles], false, branchC16, branchC1, isModifiedExtNode)
			*rows = append(*rows, bRows...)
			addForHashing(branchToBeHashed, toBeHashed)
		}
		*rows = append(*rows, extRows...)

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

		if len1 > len2 {
			*toBeHashed = append(*toBeHashed, leafForHashing...)
			// All account leaf rows already generated above, for storage leaf only S is generated above.
			if isAccountProof {
				// TODO: isInsertedExtNode
				*rows = append(*rows, leafRows...)
			} else {
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
			}
	
			// We now get the first nibble of the leaf that was turned into branch.
			// This first nibble presents the position of the leaf once it moved
			// into the new branch.

			// Note: leafRows[0] in this case (len1 > len2) is leafRowS[0],
			// leafRows[0] in case below (len2 > len1) is leafRowC[0],
			offset := 4
			leafRow := leafRows[0]
			if isAccountProof {
				offset = 7
				leafRow = leafRows[1]
			}
			(*rows)[len(*rows)-branchRows-offset][driftedPos] =
				getDriftedPosition(leafRow, numberOfNibbles) // -branchRows-offset lands into branch init

			if isModifiedExtNode {
				(*rows)[len(*rows)-branchRows-offset][isInsertedExtNodeS] = 1
			}

			if isExtension {
				setExtNodeSelectors((*rows)[len(*rows)-branchRows-offset], proof1[len1-3], numberOfNibbles, branchC16)
			}
		} else {
			// We now get the first nibble of the leaf that was turned into branch.
			// This first nibble presents the position of the leaf once it moved
			// into the new branch.

			(*rows)[len(*rows)-branchRows][driftedPos] = getDriftedPosition(leafRows[0], numberOfNibbles) // -branchRows lands into branch init

			if isModifiedExtNode {
				(*rows)[len(*rows)-branchRows][isInsertedExtNodeC] = 1
			}

			if isExtension {
				setExtNodeSelectors((*rows)[len(*rows)-branchRows], proof2[len2-3], numberOfNibbles, branchC16)	
			}

			*toBeHashed = append(*toBeHashed, leafForHashing...)
			// All account leaf rows already generated above, for storage leaf only S is generated above.
			if isAccountProof {
				*rows = append(*rows, leafRows...)
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
		}

		// The branch contains hash of the neighbouring leaf, to be able
		// to check it, we add node RLP to toBeHashed
		addForHashing(neighbourNode, toBeHashed)

		// Neighbouring leaf - the leaf that used to be one level above,
		// but it was "drifted down" when additional branch was added.
		// Only key is needed because we already have the value (it doesn't change)
		// in the parallel proof.
		if isAccountProof {
			if !isModifiedExtNode {
				h := append(neighbourNode, 5)
				*toBeHashed = append(*toBeHashed, h)

				keyRowS, _, _, _, _, _, _ :=
					prepareAccountLeafRows(neighbourNode, neighbourNode, key, nonExistingAccountProof, false)
				keyRowS = append(keyRowS, 10)
				*rows = append(*rows, keyRowS)
			} else {
				pRows := prepareDriftedLeafPlaceholder(isAccountProof)
				*rows = append(*rows, pRows...)	
			}
		} else {
			if !isModifiedExtNode {
				sLeafRows, _ := prepareStorageLeafRows(neighbourNode, 15, false)
				*rows = append(*rows, sLeafRows[0])
			} else {
				pRows := prepareDriftedLeafPlaceholder(isAccountProof)
				*rows = append(*rows, pRows...)	
			}
			
			// For non existing proof, S and C proofs are the same
			nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
			*rows = append(*rows, nonExistingStorageRow)
		}

		if isModifiedExtNode {
			var extNibbles [][]byte
			if len1 > len2 {
				extNibbles = extNibblesC
			} else {
				extNibbles = extNibblesS
			}			

			numberOfNibbles0, extensionRowS, extensionRowC :=
				prepareExtensionRows(extNibbles, extensionNodeInd, longExtNode, longExtNode, true, false)

			extNodeSelectors := make([]byte, rowLen)
			setExtNodeSelectors(extNodeSelectors, longExtNode, int(numberOfNibbles0), branchC16)
			extNodeSelectors = append(extNodeSelectors, 24)

			var extRows [][]byte
			// We need to prove the old extension node is in S proof (when ext. node inserted).
			extRows = append(extRows, extNodeSelectors)
			extRows = append(extRows, extensionRowS)
			extRows = append(extRows, extensionRowC)

			*rows = append(*rows, extRows...)
			addForHashing(longExtNode, toBeHashed)

			// Get nibbles of the extension node that gets shortened because of the newly insertd
			// extension node:
			longNibbles := getExtensionNodeNibbles(longExtNode)

			ind := byte(keyIndex) + byte(numberOfNibbles) // where the old and new extension nodes start to be different
			// diffNibble := oldNibbles[ind]
			longExtNodeKey := make([]byte, len(key))
			copy(longExtNodeKey, key)
			// We would like to retrieve the shortened extension node from the trie via GetProof or
			// GetStorageProof (depending whether it is an account proof or storage proof),
			// the key where we find its underlying branch is `oldExtNodeKey`.
			for j := ind; int(j) < keyIndex + len(longNibbles); j++ {
				// keyIndex is where the nibbles of the old and new extension node start
				longExtNodeKey[j] = longNibbles[j - byte(keyIndex)]	
			}

			k := trie.HexToKeybytes(longExtNodeKey)
			key := common.BytesToHash(k)
			var proof [][]byte
			var err error
			if isAccountProof {
				proof, _, _, _, err = statedb.GetProof(addr)
			} else {
				proof, _, _, _, err = statedb.GetStorageProof(addr, key)
			}
			check(err)

			// There is no short extension node when `len(longNibbles) - numberOfNibbles = 1`, in this case there
			// is simply a branch instead.
			shortExtNodeIsBranch := len(longNibbles) - numberOfNibbles == 1
			if shortExtNodeIsBranch {
				(*rows)[len(*rows)-branchRows-9][isShortExtNodeBranch] = 1
			}

			var shortExtNode []byte
			extNodeSelectors1 := make([]byte, rowLen)
			emptyExtRows := prepareEmptyExtensionRows(false, true)
			extensionRowS1 := emptyExtRows[0]
			extensionRowC1 := emptyExtRows[1]

			if !shortExtNodeIsBranch {
				if len2 > len1 {
					isItBranch := isBranch(proof[len(proof) - 1])

					// Note that `oldExtNodeKey` has nibbles properly set only up to the end of nibbles,
					// this is enough to get the old extension node by `GetProof` or `GetStorageProof` -
					// we will get its underlying branch, but sometimes also the leaf in a branch if
					// the nibble will correspond to the leaf (we left the nibbles from
					// `keyIndex + len(oldNibbles)` the same as the nibbles in the new extension node).

					if isItBranch { // last element in a proof is a branch
						shortExtNode = proof[len(proof) - 2]
					} else { // last element in a proof is a leaf
						shortExtNode = proof[len(proof) - 3]
					}
				} else {
					// Needed only for len1 > len2
					(*rows)[len(*rows)-branchRows-9][driftedPos] = longNibbles[numberOfNibbles]

					shortNibbles := longNibbles[numberOfNibbles+1:]
					compact := trie.HexToCompact(shortNibbles)
					longStartBranch := 2 + (longExtNode[1] - 128) // cannot be "short" in terms of having the length at position 0; TODO: extension with length at position 2 not supported (the probability very small)

					if len(shortNibbles) > 1 {
						// add RLP2:
						compact = append([]byte{128 + byte(len(compact))}, compact...)
					}
					
					shortExtNode = append(compact, longExtNode[longStartBranch:]...)

					// add RLP1:
					shortExtNode = append([]byte{192 + byte(len(shortExtNode))}, shortExtNode...)
				}

				// Get the nibbles of the shortened extension node:
				nibbles := getExtensionNodeNibbles(shortExtNode)

				// Enable `prepareExtensionRows` call:
				extNibbles = append(extNibbles, nibbles)

				var numberOfNibbles1 byte
				numberOfNibbles1, extensionRowS1, extensionRowC1 =
					prepareExtensionRows(extNibbles, extensionNodeInd + 1, shortExtNode, shortExtNode, false, true)

				setExtNodeSelectors(extNodeSelectors1, shortExtNode, int(numberOfNibbles1), branchC16)
				extNodeSelectors1 = append(extNodeSelectors1, 25)
			} else {
				if len1 > len2 {
					// Needed only for len1 > len2
					(*rows)[len(*rows)-branchRows-9][driftedPos] = longNibbles[numberOfNibbles]
				}

				extNodeSelectors1 = append(extNodeSelectors1, 25)
			}

			// The shortened extension node is needed as a witness to be able to check in a circuit
			// that the shortened extension node and newly added leaf (that causes newly inserted
			// extension node) are the only nodes in the newly inserted extension node.
			*rows = append(*rows, extNodeSelectors1)
			*rows = append(*rows, extensionRowS1)
			*rows = append(*rows, extensionRowC1)
			addForHashing(shortExtNode, toBeHashed)
		}
	} else {
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
			keyRowS, keyRowC, nonExistingAccountRow, nonceBalanceRowS, nonceBalanceRowC, storageCodeHashRowS, storageCodeHashRowC :=
				prepareAccountLeafRows(leafS, leafC, key, nonExistingAccountProof, false)
			
			*rows = append(*rows, keyRowS)
			*rows = append(*rows, keyRowC)
			*rows = append(*rows, nonExistingAccountRow) // not really needed
			*rows = append(*rows, nonceBalanceRowS)
			*rows = append(*rows, nonceBalanceRowC)
			*rows = append(*rows, storageCodeHashRowS)
			*rows = append(*rows, storageCodeHashRowC)

			pRows := prepareDriftedLeafPlaceholder(true)
			*rows = append(*rows, pRows...)

			leafS = append(leafS, 5)
			leafC = append(leafC, 5)
			*toBeHashed = append(*toBeHashed, leafS)
			*toBeHashed = append(*toBeHashed, leafC)
		} else {
			var leafRows [][]byte
			var leafForHashing []byte
			if len1 > len2 {
				leafRows, leafForHashing = prepareStorageLeafRows(proof1[len1-1], 2, false)
			} else {
				leafRows, leafForHashing = prepareStorageLeafRows(proof2[len2-1], 2, true)
			}
			
			*rows = append(*rows, leafRows...)
			*toBeHashed = append(*toBeHashed, leafForHashing)

			// No leaf means value is 0, set valueIsZero = true:
			if len1 > len2 {
				leafRows, _ = prepareStorageLeafRows(proof1[len1-1], 3, true)
			} else {
				leafRows, _ = prepareStorageLeafRows(proof2[len2-1], 3, false)
			}
			*rows = append(*rows, leafRows...)

			pRows := prepareDriftedLeafPlaceholder(isAccountProof)
			*rows = append(*rows, pRows...)

			// For non existing proof, S and C proofs are the same
			nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
			*rows = append(*rows, nonExistingStorageRow)	
		}
	}
}

// prepareWitness takes two GetProof proofs (before and after single modification) and prepares
// a witness for an MPT circuit. Alongside, it prepares the byte streams that need to be hashed
// and inserted into Keccak lookup table.
func prepareWitness(statedb *state.StateDB, addr common.Address, proof1, proof2, extNibblesS, extNibblesC [][]byte, key []byte, neighbourNode []byte,
		isAccountProof, nonExistingAccountProof, nonExistingStorageProof, isShorterProofLastLeaf bool) ([][]byte, [][]byte, bool) {
	rows := make([][]byte, 0)
	toBeHashed := make([][]byte, 0)

	minLen := len(proof1)
	if len(proof2) < minLen {
		minLen = len(proof2)
	}

	keyIndex := 0
	len1 := len(proof1)
	len2 := len(proof2)

	// When a value in the trie is updated, both proofs are of the same length.
	// Otherwise, when a value is added (not updated) and there is no node which needs to be changed
	// into a branch, one proof has a leaf and one does not have it.
	// The third option is when a value is added and the existing leaf is turned into a branch,
	// in this case we have an additional branch in C proof (when deleting a value causes
	// that a branch with two leaves turns into a leaf, we have an additional branch in S proof).

	additionalBranch := false
	if len1 < len2 && len1 > 0 { // len = 0 when trie trie is empty
		// Check if the last proof element in the shorter proof is a leaf -
		// if it is, then there is an additional branch.
		additionalBranch = !isBranch(proof1[len1 - 1])
	} else if len2 < len1 && len2 > 0 {
		additionalBranch = !isBranch(proof2[len2 - 1])
	}

	upTo := minLen
	if (len1 != len2) && additionalBranch {
		upTo = minLen - 1
	}

	var extensionRowS []byte
	var extensionRowC []byte
	extensionNodeInd := 0

	branchC16 := byte(0); 
	branchC1 := byte(1);
	for i := 0; i < upTo; i++ {
		isItBranch := isBranch(proof1[i])
		if !isItBranch {
			if i != len1 - 1 { // extension node
				var numberOfNibbles byte
				numberOfNibbles, extensionRowS, extensionRowC = prepareExtensionRows(extNibblesS, extensionNodeInd, proof1[i], proof2[i], false, false)
				keyIndex += int(numberOfNibbles)
				extensionNodeInd++
				continue
			}

			if isAccountProof {
				l := len(proof1)
				leafS := proof1[l-1]
				leafC := proof2[l-1]

				keyRowS, keyRowC, nonExistingAccountRow, nonceBalanceRowS, nonceBalanceRowC, storageCodeHashRowS, storageCodeHashRowC :=
					prepareAccountLeafRows(leafS, leafC, key, nonExistingAccountProof, false)
				
				rows = append(rows, keyRowS)
				rows = append(rows, keyRowC)
				rows = append(rows, nonExistingAccountRow)
				rows = append(rows, nonceBalanceRowS)
				rows = append(rows, nonceBalanceRowC)
				rows = append(rows, storageCodeHashRowS)
				rows = append(rows, storageCodeHashRowC)

				leafS = append(leafS, 5)
				leafC = append(leafC, 5)
				toBeHashed = append(toBeHashed, leafS)
				toBeHashed = append(toBeHashed, leafC)
			} else {
				leafRows, leafForHashing := prepareStorageLeafRows(proof1[i], 2, false) // leaf s
				rows = append(rows, leafRows...)
				toBeHashed = append(toBeHashed, leafForHashing)
				leafRows, leafForHashing = prepareStorageLeafRows(proof2[i], 3, false) // leaf s
				rows = append(rows, leafRows...)	

				toBeHashed = append(toBeHashed, leafForHashing)
			}
		} else {
			switchC16 := true // If not extension node, switchC16 = true.
			if extensionRowS != nil {
				keyLen := getExtensionNodeKeyLen(proof1[i-1])
				if keyLen == 1 {
					switchC16 = false
				} else {
					if proof1[i-1][2] != 0 { // If even, switch16 = true.
						switchC16 = false
					}
				}
			}
			if switchC16 {
				if branchC16 == 1 {
					branchC16 = 0
					branchC1 = 1
				} else {
					branchC16 = 1
					branchC1 = 0
				}
			}

			bRows := prepareTwoBranches(proof1[i], proof2[i], key[keyIndex], branchC16, branchC1, false, false)
			keyIndex += 1

			// extension node rows
			if extensionRowS != nil {
				bRows = append(bRows, extensionRowS)
				bRows = append(bRows, extensionRowC)

				// Set isExtension to 1 in branch init.
				bRows[0][isExtensionPos] = 1

				if len(proof1[i-1]) > 56 { // 56 because there is 1 byte for length
					bRows[0][isSExtLongerThan55Pos] = 1
				}
				if len(proof2[i-1]) > 56 {
					bRows[0][isCExtLongerThan55Pos] = 1
				}

				if len(proof1[i-1]) < 32 {
					bRows[0][isExtNodeSNonHashedPos] = 1
				}
				if len(proof2[i-1]) < 32 {
					bRows[0][isExtNodeCNonHashedPos] = 1
				}

				keyLen := getExtensionNodeKeyLen(proof1[i-1])
				// Set whether key extension nibbles are of even or odd length.
				if keyLen == 1 {
					if branchC16 == 1 {
						bRows[0][isExtShortC16Pos] = 1
					} else {
						bRows[0][isExtShortC1Pos] = 1
					}
				} else {
					if proof1[i-1][2] == 0 {
						if branchC16 == 1 {
							bRows[0][isExtLongEvenC16Pos] = 1
						} else {
							bRows[0][isExtLongEvenC1Pos] = 1
						}
					} else {
						if branchC16 == 1 {
							bRows[0][isExtLongOddC16Pos] = 1
						} else {
							bRows[0][isExtLongOddC1Pos] = 1
						}
					}
				}

				// adding extension nodes for hashing:
				addForHashing(proof1[i-1], &toBeHashed)
				addForHashing(proof2[i-1], &toBeHashed)
			} else {
				extRows := prepareEmptyExtensionRows(false, false)
				bRows = append(bRows, extRows...)
			}

			rows = append(rows, bRows...)
			addForHashing(proof1[i], &toBeHashed)
			addForHashing(proof2[i], &toBeHashed)

			// check the two branches
			if extensionNodeInd == 0 {
				for k := 1; k < 17; k++ {
					if k-1 == int(key[i]) {
						continue
					}
					for j := 0; j < branchNodeRLPLen+32; j++ {
						if bRows[k][j] != bRows[k][branch2start+j] {
							panic("witness not properly generated")
						}
					}
				}
			}

			extensionRowS = nil
			extensionRowC = nil
		}
	}	
	
	if len1 != len2 {
		addPlaceholder(statedb, addr, &rows, proof1, proof2, extNibblesS, extNibblesC, key, neighbourNode,
			keyIndex, extensionNodeInd, additionalBranch,
			isAccountProof, nonExistingAccountProof, isShorterProofLastLeaf, branchC16, branchC1, &toBeHashed)
	} else {
		// Let's always use C proof for non-existing proof.
		// Account proof has drifted leaf as the last row, storage proof has non-existing-storage row
		// as the last row.
		if isBranch(proof2[len(proof2)-1]) {
			// When non existing proof and only the branches are returned, we add a placeholder leaf.
			// This is to enable the lookup (in account leaf row), most constraints are disabled for these rows.
			if !isAccountProof {
				// We need to prepare placeholder storage leaf rows.
				leaf := make([]byte, rowLen)
				// Just some values to avoid assignement errors:
				leaf[0] = 228
				leaf[1] = 130
				leaf[2] = 51

				leafRows, _ := prepareStorageLeafRows(leaf, 2, false)
				rows = append(rows, leafRows...)
				leafRows, _ = prepareStorageLeafRows(leaf, 3, false)
				rows = append(rows, leafRows...)

				pRows := prepareDriftedLeafPlaceholder(isAccountProof)
				rows = append(rows, pRows...)	

				if nonExistingStorageProof {
					leaf := prepareEmptyNonExistingStorageRow()

					isEven := keyIndex % 2 == 0 
					keyLen := int(math.Floor(float64(64-keyIndex) / float64(2))) + 1
					remainingNibbles := key[keyIndex:]
					leaf[1] = byte(keyLen) + 128
					if isEven {
						leaf[2] = 32
					} else {
						leaf[2] = remainingNibbles[0] + 48
					}

					rows = append(rows, leaf)	
				} else {
					nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
					rows = append(rows, nonExistingStorageRow)	
				}
			} else {
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
				
				keyRowS, keyRowC, nonExistingAccountRow, nonceBalanceRowS, nonceBalanceRowC, storageCodeHashRowS, storageCodeHashRowC :=
					prepareAccountLeafRows(leaf, leaf, key, nonExistingAccountProof, true)
				
				rows = append(rows, keyRowS)
				rows = append(rows, keyRowC)
				rows = append(rows, nonExistingAccountRow)
				rows = append(rows, nonceBalanceRowS)
				rows = append(rows, nonceBalanceRowC)
				rows = append(rows, storageCodeHashRowS)
				rows = append(rows, storageCodeHashRowC)

				pRows := prepareDriftedLeafPlaceholder(isAccountProof)
				rows = append(rows, pRows...)	
			}
		} else {
			pRows := prepareDriftedLeafPlaceholder(isAccountProof)
			rows = append(rows, pRows...)	

			if !isAccountProof {
				if nonExistingStorageProof {
					cKeyRow := rows[len(rows) - 3]
					noLeaf := false
					nonExistingStorageRow := prepareNonExistingStorageRow(cKeyRow, key, noLeaf)
					rows = append(rows, nonExistingStorageRow)	
				} else {
					nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
					rows = append(rows, nonExistingStorageRow)	
				}
			}
		}
	}

	return rows, toBeHashed, extensionNodeInd > 0
}