package witness

import (
	"log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// isBranch takes GetProof element and returns whether the element is a branch.
func isBranch(proofEl []byte) bool {
	elems, _, err := rlp.SplitList(proofEl)
	check(err)
	c, err1 := rlp.CountValues(elems)
	check(err1)
	if c != 2 && c != 17 {
		log.Fatal("Proof element is neither leaf or branch")
	}
	return c == 17
}

// prepareBranchWitness takes the rows that are to be filled with branch data and it takes
// a branch as returned by GetProof. There are 19 rows for a branch and prepareBranchWitness
// fills the rows from index 1 to index 16 (index 0 is init, index 17 and 18 are for extension
// node when it applies). The parameter branchStart depends on whether it is S or C branch -
// S occupies the first 34 columns, C occupies the next 34 columns.
// The branch children are positioned each in its own row.
func prepareBranchWitness(rows [][]byte, branch []byte, branchStart int, branchRLPOffset int) {
	rowInd := 1
	colInd := branchNodeRLPLen - 1

	i := 0
	insideInd := -1
	for {
		if (branchRLPOffset + i == len(branch) - 1) { // -1 because of the last 128 (branch value)
			break
		}
		b := branch[branchRLPOffset+i]
		if insideInd == -1 && b == 128 {
			rows[rowInd][branchStart] = b
			rowInd++
		} else if insideInd == -1 && b != 128 {
			if b == 160 {
				insideInd = 32
				colInd = branchNodeRLPLen - 2
			} else {
				// non-hashed node
				insideInd = int(b) - 192
				colInd = branchNodeRLPLen - 2
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

func prepareBranchNode(branch1, branch2 []byte, key, driftedInd, branchC16, branchC1 byte, isBranchSPlaceholder, isBranchCPlaceholder, isExtension bool) Node {
	extensionNode := ExtensionNode {
		ListRlpBytes: []byte{},
	}

	var listRlpBytes [2][]byte
	branch1RLPOffset := 1
	branch2RLPOffset := 1
	listRlpBytes1 := []byte{branch1[0]}
	listRlpBytes2 := []byte{branch2[0]}

	if branch1[0] == 248 { // two RLP bytes
		branch1RLPOffset = 2
	} else if branch1[0] == 249 { // three RLP bytes
		branch1RLPOffset = 3
	}
	
	if branch2[0] == 248 { // two RLP bytes
		branch2RLPOffset = 2
	} else if branch2[0] == 249 { // three RLP bytes
		branch2RLPOffset = 3
	}

	if branch1[0] == 248 || branch1[0] == 249 {
		listRlpBytes1 = append(listRlpBytes1, branch1[1])
	}
	if branch2[0] == 248 || branch2[0] == 249 {
		listRlpBytes2 = append(listRlpBytes2, branch2[1])
	}

	if branch1[0] == 249 {
		listRlpBytes1 = append(listRlpBytes1, branch1[2])
	} 
	if branch2[0] == 249 {
		listRlpBytes2 = append(listRlpBytes2, branch2[2])
	}

	listRlpBytes[0] = listRlpBytes1
	listRlpBytes[1] = listRlpBytes2

	branchNode := BranchNode {
		ModifiedIndex: int(key),
		DriftedIndex: int(driftedInd),
		ListRlpBytes: listRlpBytes,
	}

	extensionBranch := ExtensionBranchNode {
		IsExtension: isExtension,
		IsPlaceholder: [2]bool{isBranchSPlaceholder, isBranchCPlaceholder},
		Extension: extensionNode,
		Branch: branchNode,
	}

	values := make([][]byte, 21)
	for i := 0; i < len(values); i++ {
		values[i] = make([]byte, valueLen)
	}
	prepareBranchWitness(values, branch1, 0, branch1RLPOffset)

	rows := make([][]byte, 17)
	for i := 0; i < len(rows); i++ {
		rows[i] = make([]byte, valueLen)
	}
	prepareBranchWitness(rows, branch2, 0, branch2RLPOffset)
	values[0] = rows[1 + key]

	keccakData := [][]byte{branch1, branch2}
	node := Node {
		ExtensionBranch: &extensionBranch,
		Values: values,
		KeccakData: keccakData,
	}

	return node
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

// addBranchAndPlaceholder adds to the rows a branch and its placeholder counterpart
// (used when one of the proofs have one branch more than the other).
func addBranchAndPlaceholder(addr common.Address, rows *[][]byte, proof1, proof2,
		extNibblesS, extNibblesC [][]byte,
		leafRow0, key, neighbourNode []byte,
		keyIndex, extensionNodeInd int,
		additionalBranch, isAccountProof, nonExistingAccountProof,
		isShorterProofLastLeaf bool, branchC16, branchC1 byte, toBeHashed *[][]byte) (bool, bool, int, byte, Node) {
	len1 := len(proof1)
	len2 := len(proof2)

	var node Node

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

	// Note that isModifiedExtNode happens also when we have a branch instead of shortExtNode
	isModifiedExtNode := !isBranch(longExtNode) && !isShorterProofLastLeaf

	if len1 > len2 {
		bRows, branchToBeHashed := prepareParallelBranches(proof1[len1-2], proof1[len1-2], key[keyIndex + numberOfNibbles], true, branchC16, branchC1, isModifiedExtNode)

		// We now get the first nibble of the leaf that was turned into branch.
		// This first nibble presents the position of the leaf once it moved
		// into the new branch.
		driftedInd := getDriftedPosition(leafRow0, numberOfNibbles)
		
		node = prepareBranchNode(proof1[len1-2], proof1[len1-2], key[keyIndex + numberOfNibbles], driftedInd, branchC16, branchC1, false, false, isExtension)

		if isExtension {
			setExtNodeSelectors(bRows[0], proof1[len1-3], numberOfNibbles, branchC16)
		}
		if isModifiedExtNode {
			bRows[0][isInsertedExtNodeS] = 1
		}

		// We now get the first nibble of the leaf that was turned into branch.
		// This first nibble presents the position of the leaf once it moved
		// into the new branch.

		*rows = append(*rows, bRows...)
		addForHashing(branchToBeHashed, toBeHashed)
	} else {
		// TODO: remove
		bRows, branchToBeHashed := prepareParallelBranches(proof2[len2-2], proof2[len2-2], key[keyIndex + numberOfNibbles], false, branchC16, branchC1, isModifiedExtNode)

		// We now get the first nibble of the leaf that was turned into branch.
		// This first nibble presents the position of the leaf once it moved
		// into the new branch.
		driftedInd := getDriftedPosition(leafRow0, numberOfNibbles)

		node = prepareBranchNode(proof2[len2-2], proof2[len2-2], key[keyIndex + numberOfNibbles], driftedInd,
				branchC16, branchC1, false, false, isExtension)

		if isExtension {
			setExtNodeSelectors(bRows[0], proof2[len2-3], numberOfNibbles, branchC16)	
		}
		if isModifiedExtNode {
			bRows[0][isInsertedExtNodeC] = 1
		}

		*rows = append(*rows, bRows...)
		addForHashing(branchToBeHashed, toBeHashed)
	}
	*rows = append(*rows, extRows...)

	return isModifiedExtNode, isExtension, numberOfNibbles, branchC16, node
}