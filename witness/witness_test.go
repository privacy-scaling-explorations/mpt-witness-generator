package witness

import (
	"fmt"
	"log"
	"math/big"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/miha-stopar/mpt/oracle"
	"github.com/miha-stopar/mpt/state"
	"github.com/miha-stopar/mpt/trie"
)

const branchNodeRLPLen = 2 // we have two positions for RLP meta data
const branch2start = branchNodeRLPLen + 32
const branchRows = 19 // 1 (init) + 16 (children) + 2 (extension S and C)

// rowLen - each branch node has 2 positions for RLP meta data and 32 positions for hash
const rowLen = branch2start + 2 + 32 + 1 // +1 is for info about what type of row is it
const keyPos = 10
const isBranchSPlaceholderPos = 11
const isBranchCPlaceholderPos = 12
const driftedPos = 13
const isExtensionPos = 14
// extension key even or odd is about nibbles - that determines whether the first byte (not
// considering RLP bytes) is 0 or 1 (see encoding.go hexToCompact)
const isExtensionEvenKeyLenPos = 15
const isExtensionOddKeyLenPos = 16
const isExtensionKeyShortPos = 17
const isExtensionKeyLongPos = 18

/*
Info about row type (given as the last element of the row):
0: init branch (such a row contains RLP info about the branch node; key)
1: branch child
2: storage leaf s key
3: storage leaf c key
5: hash to be computed (for example branch RLP whose hash needs to be checked in the parent)
6: account leaf key S
7: account leaf nonce balance S
8: account leaf root codehash S
11: account leaf root codehash C
13: storage leaf s value
14: storage leaf c value
15: neighbouring storage leaf (when leaf turned into branch)
16: extension node S
17: extension node C
*/

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func matrixToJson(rows [][]byte) string {
	// Had some problems with json.Marshal, so I just prepare json manually.
	json := "["
	for i := 0; i < len(rows); i++ {
		json += listToJson(rows[i])
		if i != len(rows)-1 {
			json += ","
		}
	}
	json += "]"

	return json
}

func listToJson(row []byte) string {
	json := "["
	for j := 0; j < len(row); j++ {
		json += strconv.Itoa(int(row[j]))
		if j != len(row)-1 {
			json += ","
		}
	}
	json += "]"

	return json
}

func VerifyProof(proof [][]byte, key []byte) bool {
	hasher := trie.NewHasher(false)
	for i := 0; i < len(proof)-1; i++ {
		parentHash := hasher.HashData(proof[i])
		parent, err := trie.DecodeNode(parentHash, proof[i])
		check(err)

		childHash := hasher.HashData(proof[i+1])
		child, err := trie.DecodeNode(childHash, proof[i+1])
		check(err)

		r := parent.(*trie.FullNode)
		c := r.Children[key[i]] // TODO: doesn't cover all scenarios
		u, _ := hasher.Hash(child, false)

		if fmt.Sprintf("%b", u) != fmt.Sprintf("%b", c) {
			return false
		}
	}

	return true
}

func VerifyTwoProofsAndPath(proof1, proof2 [][]byte, key []byte) bool {
	if len(proof1) != len(proof2) {
		fmt.Println("constraint failed: proofs length not the same")
		return false
	}
	hasher := trie.NewHasher(false)
	for i := 0; i < len(proof1)-1; i++ { // -1 because it checks current and next row
		parentHash := hasher.HashData(proof1[i])
		parent, err := trie.DecodeNode(parentHash, proof1[i])
		check(err)

		childHash := hasher.HashData(proof1[i+1])
		child, err := trie.DecodeNode(childHash, proof1[i+1])
		check(err)

		r := parent.(*trie.FullNode)
		c := r.Children[key[i]] // TODO: doesn't cover all scenarios
		u, _ := hasher.Hash(child, false)

		if fmt.Sprintf("%b", u) != fmt.Sprintf("%b", c) {
			fmt.Println("constraint failed: proof not valid")
			return false
		}

		parentHash2 := hasher.HashData(proof2[i])
		parent2, err := trie.DecodeNode(parentHash2, proof2[i])
		check(err)

		childHash2 := hasher.HashData(proof2[i+1])
		child2, err := trie.DecodeNode(childHash2, proof2[i+1])
		check(err)

		r2 := parent2.(*trie.FullNode)
		c2 := r2.Children[key[i]] // TODO: doesn't cover all scenarios
		u2, _ := hasher.Hash(child2, false)

		if fmt.Sprintf("%b", u2) != fmt.Sprintf("%b", c2) {
			fmt.Println("constraint failed: proof not valid")
			return false
		}

		// Constraints that we are having the same path for both proofs:
		for j := 0; j < 16; j++ {
			if j != int(key[i]) {
				if fmt.Sprintf("%b", r.Children[j]) != fmt.Sprintf("%b", r2.Children[j]) {
					fmt.Println("constraint failed: path not valid")
					return false
				}
			}
		}
	}

	return true
}

// Check that elements in a branch are all the same, except at the position exceptPos.
func VerifyElementsInTwoBranches(b1, b2 *trie.FullNode, exceptPos byte) bool {
	for j := 0; j < 16; j++ {
		if j != int(exceptPos) {
			if fmt.Sprintf("%b", b1.Children[j]) != fmt.Sprintf("%b", b2.Children[j]) {
				fmt.Println("constraint failed: element in branch not the same")
				return false
			}
		}
	}
	return true
}

func prepareBranchWitness(rows [][]byte, branch []byte, branchStart int, branchRLPOffset int) {
	// TODO: ValueNode info is currently missing
	rowInd := 1 // start with 1 because rows[0] contains some RLP data
	colInd := branchNodeRLPLen
	inside32Ind := -1
	count := int(branch[1])
	if branchRLPOffset == 3 {
		count = int(branch[1])*256 + int(branch[2])
	}
	// TODO: don't loop to count when there is ValueNode
	for i := 0; i < count; i++ {
		if rowInd == 17 {
			break
		}
		b := branch[branchRLPOffset+i]
		if b == 160 && inside32Ind == -1 { // new child
			inside32Ind = 0
			colInd = branchNodeRLPLen - 1
			rows[rowInd][branchStart+colInd] = b
			colInd++
			continue
		}

		if inside32Ind >= 0 {
			rows[rowInd][branchStart+colInd] = b
			colInd++
			inside32Ind++
			// fmt.Println(rows[rowInd])
			if inside32Ind == 32 {
				inside32Ind = -1
				rowInd++
				colInd = 0
			}
		} else {
			// if we are not in a child, it can only be b = 128 which presents nil (no child
			// at this position)
			if b != 128 {
				panic("not 128")
			}
			rows[rowInd][branchStart+branchNodeRLPLen] = b
			rowInd++
			// fmt.Println(rows[rowInd-1])
		}
	}
}

func preparePlaceholderRows() [][]byte {
	leaf_in_added_branch := make([]byte, rowLen)
	leaf_in_added_branch = append(leaf_in_added_branch, 15)

	return [][]byte{leaf_in_added_branch}
}

func addForHashing(toBeHashed []byte, toBeHashedCollection *[][]byte) {
	forHashing := make([]byte, len(toBeHashed))
	copy(forHashing, toBeHashed)
	forHashing = append(forHashing, 5) // 5 means it needs to be hashed
	*toBeHashedCollection = append(*toBeHashedCollection, forHashing)
}

func prepareEmptyExtensionRows() [][]byte {
	ext_row1 := make([]byte, rowLen)
	ext_row1 = append(ext_row1, 16)

	ext_row2 := make([]byte, rowLen)
	ext_row2 = append(ext_row2, 17)

	return [][]byte{ext_row1, ext_row2}
}

func prepareExtensionRows(extNibbles[][]byte, extensionNodeInd int, proofEl1, proofEl2 []byte) (byte, []byte, []byte) {
	var extensionRowS []byte
	var extensionRowC []byte

	extRows := prepareEmptyExtensionRows()
	extensionRowS = extRows[0]
	extensionRowC = extRows[1]
	prepareExtensionRow(extensionRowS, proofEl1, true)
	prepareExtensionRow(extensionRowC, proofEl2, false)

	evenNumberOfNibbles := proofEl1[2] == 0
	numberOfNibbles := byte(0)
	keyLen := getExtensionNodeKeyLen(proofEl1)
	if keyLen == 1 {
		numberOfNibbles = 1
	} else if keyLen > 1 && evenNumberOfNibbles {
		numberOfNibbles = (keyLen - 1) * 2
	} else if keyLen > 1 && !evenNumberOfNibbles {
		numberOfNibbles = (keyLen - 1) * 2 + 1
	}

	// We need nibbles as witness to compute key RLC, so we set them
	// into extensionRowC s_advices (we can do this because both extension
	// nodes have the same key, so we can have this info only in one).
	// There can be more up to 64 nibbles, but there is only 32 bytes
	// in xtensionRowC s_advices. So we store every second nibble (having
	// the whole byte and one nibble is enough to compute the other nibble).
	startNibblePos := 2 // we don't need any nibbles for case keyLen = 1
	if keyLen > 1 {
		if evenNumberOfNibbles {
			startNibblePos = 1
		} else {
			startNibblePos = 2
		}
	}
	ind := 0
	for j := startNibblePos; j < len(extNibbles[extensionNodeInd]); j += 2 {
		extensionRowC[branchNodeRLPLen + ind] =
			extNibbles[extensionNodeInd][j]
		ind++
	}

	return numberOfNibbles, extensionRowS, extensionRowC
}

func getExtensionNodeKeyLen(proofEl []byte) byte {
	// is_long means there is more than one extension node key - there is one addition RLP
	// byte to start an array (at position 1).
	is_long := proofEl[1] > 128
	if !is_long {
		return 1
	} else {
		return proofEl[1] - 128
	}
}

func prepareExtensionRow(witnessRow, proofEl []byte, setKey bool) {
	// storageProof[i]:
	// [228,130,0,149,160,114,253,150,133,18,192,156,19,241,162,51,210,24,1,151,16,48,7,177,42,60,49,34,230,254,242,79,132,165,90,75,249]
	// elems:
	// [130,0,149,160,114,253,150,133,18,192,156,19,241,162,51,210,24,1,151,16,48,7,177,42,60,49,34,230,254,242,79,132,165,90,75,249]
	// rlp.SplitList doesn't return tag (228).

	// If only one byte in key:
	// [226,16,160,172,105,12...
	// [16,160,172,105,12...

	// is_long means there is more than one extension node key - there is one addition RLP
	// byte to start an array (at position 1).
	is_long := proofEl[1] > 128
	if setKey {
		witnessRow[0] = proofEl[0]
		witnessRow[1] = proofEl[1]
	}

	if !is_long {
		if proofEl[2] != 160 {
			panic("Extension node should be 160 S short")
		}
		for j := 0; j < 33; j++ {
			witnessRow[branch2start+branchNodeRLPLen+j-1] = proofEl[2+j]
		}
	} else {
		lenK := int(proofEl[1] - 128)
		if setKey {
			for j := 0; j < lenK; j++ {
				witnessRow[2+j] = proofEl[2+j]
			}
		}
		if proofEl[2+lenK] != 160 {
			panic("Extension node should be 160 S")
		}
		witnessRow[branch2start+branchNodeRLPLen-1] = proofEl[2+lenK]
		for j := 0; j < 32; j++ {
			witnessRow[branch2start+branchNodeRLPLen+j] = proofEl[3+lenK+j]
		}
	}
}

func prepareLeafRows(row []byte, typ byte) ([][]byte, []byte) {
	// Avoid directly changing the row as it might introduce some bugs later on.
	leaf1 := make([]byte, rowLen)
	leaf2 := make([]byte, rowLen)
	typ2 := byte(13)
	if typ == 3 {
		typ2 = 14
	}
	if row[0] == 248 {
		keyLen := row[2] - 128
		copy(leaf1, row[:keyLen+3])
		leaf1 = append(leaf1, typ)
		// there are two RLP meta data bytes which are put in s_rlp1 and s_rlp2,
		// value starts in s_advices[0]
		copy(leaf2, row[keyLen+3:]) // RLP data in s_rlp1 and s_rlp2, value starts in s_advices[0]
		leaf2 = append(leaf2, typ2)
	} else {
		keyLen := row[1] - 128
		copy(leaf1, row[:keyLen+2])
		leaf1 = append(leaf1, typ)
		copy(leaf2, row[keyLen+2:]) // value starts in s_rlp1
		leaf2 = append(leaf2, typ2)
	}

	leafForHashing := make([]byte, len(row))
	copy(leafForHashing, row)
	leafForHashing = append(leafForHashing, 5)

	return [][]byte{leaf1, leaf2}, leafForHashing
}

func prepareTwoBranchesWitness(branch1, branch2 []byte, key byte, isBranchSPlaceholder, isBranchCPlaceholder bool) [][]byte {
	rows := make([][]byte, 17)
	rows[0] = make([]byte, rowLen)

	// Branch (length 83) with two bytes of RLP meta data
	// [248,81,128,128,...

	// Branch (length 340) with three bytes of RLP meta data
	// [249,1,81,128,16,...

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
	}

	branch2RLPOffset := 2
	rows[0][2] = 1 // 1 0 means two RLP bytes
	rows[0][3] = 0
	if branch2[0] == 249 {
		branch2RLPOffset = 3
		rows[0][2] = 0 // 0 1 means three RLP bytes
		rows[0][3] = 1
	}

	// Let's put in the 0-th row some RLP data (the length of the whole branch RLP)
	rows[0][4] = branch1[0]
	rows[0][5] = branch1[1]

	rows[0][7] = branch2[0]
	rows[0][8] = branch2[1]

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

	for i := 1; i < 17; i++ {
		rows[i] = make([]byte, rowLen)
		// assign row type
		if i == 0 {
			rows[i][rowLen-1] = 0
		} else {
			rows[i][rowLen-1] = 1
		}
	}
	prepareBranchWitness(rows, branch1, 0, branch1RLPOffset)
	prepareBranchWitness(rows, branch2, 2+32, branch2RLPOffset)

	return rows
}

func prepareWitness(storageProof1, storageProof2, extNibbles [][]byte, key []byte, neighbourNode []byte, isAccountProof bool) ([][]byte, [][]byte, bool) {
	rows := make([][]byte, 0)
	toBeHashed := make([][]byte, 0)

	minLen := len(storageProof1)
	if len(storageProof2) < minLen {
		minLen = len(storageProof2)
	}

	keyIndex := 0
	len1 := len(storageProof1)
	len2 := len(storageProof2)

	// When value in the trie is updated, both proofs are of the same length.
	// When value is added and there is no node which needs to be changed
	// into branch, one proof has a leaf and one doesn't have it.

	// Check if the last proof element in the shorter proof in is a leaf -
	// if it is, then there is an additional branch.
	additionalBranchNeeded := func(proofEl []byte) bool {
		elems, _, err := rlp.SplitList(proofEl)
		check(err)
		c, _ := rlp.CountValues(elems)
		return c == 2
	}

	additionalBranch := false
	if len1 < len2 {
		additionalBranch = additionalBranchNeeded(storageProof1[len1-1])
	} else if len2 < len1 {
		additionalBranch = additionalBranchNeeded(storageProof2[len2-1])
	}

	upTo := minLen
	if (len1 != len2) && additionalBranch {
		upTo = minLen - 1
	}

	var extensionRowS []byte
	var extensionRowC []byte
	extensionNodeInd := 0
	for i := 0; i < upTo; i++ {
		elems, _, err := rlp.SplitList(storageProof1[i])
		if err != nil {
			fmt.Println("decode error", err)
		}

		switch c, _ := rlp.CountValues(elems); c {
		case 2:
			if storageProof1[i][0] < 248 && i != len1 - 1 {
				var numberOfNibbles byte
				numberOfNibbles, extensionRowS, extensionRowC = prepareExtensionRows(extNibbles, extensionNodeInd, storageProof1[i], storageProof2[i])
				keyIndex += int(numberOfNibbles)
				extensionNodeInd++
				continue
			}

			if isAccountProof {
				l := len(storageProof1)
				leafS := storageProof1[l-1]
				leafC := storageProof2[l-1]

				keyLen := int(leafS[2]) - 128
				keyRow := make([]byte, rowLen)
				for i := 0; i < 3+keyLen; i++ {
					keyRow[i] = leafS[i]
				}

				rlpStringSecondPartLen := leafS[3+keyLen] - 183
				if rlpStringSecondPartLen != 1 {
					panic("Account leaf RLP at this position should be 1")
				}
				rlpStringLen := leafS[3+keyLen+1]

				// [248,112,157,59,158,160,175,159,65,212,107,23,98,208,38,205,150,63,244,2,185,236,246,95,240,224,191,229,27,102,202,231,184,80,248,78
				// In this example RLP, there are first 36 bytes of a leaf.
				// 157 means there are 29 bytes for key (157 - 128).
				// Positions 32-35: 184, 80, 248, 78.
				// 184 - 183 = 1 means length of the second part of a string.
				// 80 means length of a string.
				// 248 - 247 = 1 means length of the second part of a list.
				// 78 means length of a list.

				rlpListSecondPartLen := leafS[3+keyLen+1+1] - 247
				if rlpListSecondPartLen != 1 {
					panic("Account leaf RLP 1")
				}
				rlpListLen := leafS[3+keyLen+1+1+1]
				if rlpStringLen != rlpListLen+2 {
					panic("Account leaf RLP 2")
				}

				nonceStart := 3 + keyLen + 1 + 1 + 1 + 1
				nonceRlpLen := leafS[nonceStart] - 128
				nonce := leafS[nonceStart : nonceStart+int(nonceRlpLen)+1]

				nonceBalanceRow := make([]byte, rowLen)
				for i := 0; i < len(nonce); i++ {
					nonceBalanceRow[branchNodeRLPLen+i] = nonce[i]
				}

				nonceBalanceRow[0] = leafS[3+keyLen]
				nonceBalanceRow[1] = leafS[3+keyLen+1]
				nonceBalanceRow[branch2start] = leafS[3+keyLen+1+1]
				nonceBalanceRow[branch2start+1] = leafS[3+keyLen+1+1+1]

				balanceStart := nonceStart + int(nonceRlpLen) + 1
				balanceRlpLen := leafS[balanceStart] - 128
				balance := leafS[balanceStart : balanceStart+int(balanceRlpLen)+1]
				for i := 0; i < len(balance); i++ {
					nonceBalanceRow[branch2start+2+i] = balance[i] // c_advices
				}

				storageCodeHashRowS := make([]byte, rowLen)

				storageStart := balanceStart + int(balanceRlpLen) + 1
				storageRlpLen := leafS[storageStart] - 128
				if storageRlpLen != 32 {
					panic("Account leaf RLP 3")
				}
				storage := leafS[storageStart : storageStart+32+1]
				for i := 0; i < 33; i++ {
					storageCodeHashRowS[branchNodeRLPLen-1+i] = storage[i]
				}

				codeHashStart := storageStart + int(storageRlpLen) + 1
				codeHashRlpLen := leafS[codeHashStart] - 128
				if codeHashRlpLen != 32 {
					panic("Account leaf RLP 4")
				}
				codeHash := leafS[codeHashStart : codeHashStart+32+1]
				for i := 0; i < 33; i++ {
					storageCodeHashRowS[branch2start+1+i] = codeHash[i] // start from c_rlp2
				}

				// Only storage root is different in S and C.
				storageCodeHashRowC := make([]byte, rowLen)
				copy(storageCodeHashRowC, storageCodeHashRowS)
				storageC := leafC[storageStart : storageStart+32+1]
				for i := 0; i < 33; i++ {
					storageCodeHashRowC[branchNodeRLPLen-1+i] = storageC[i]
				}

				keyRow = append(keyRow, 6)
				nonceBalanceRow = append(nonceBalanceRow, 7)
				storageCodeHashRowS = append(storageCodeHashRowS, 8)

				storageCodeHashRowC = append(storageCodeHashRowC, 11)

				rows = append(rows, keyRow)
				rows = append(rows, nonceBalanceRow)
				rows = append(rows, storageCodeHashRowS)

				rows = append(rows, storageCodeHashRowC)

				leafS = append(leafS, 5)
				leafC = append(leafC, 5)
				toBeHashed = append(toBeHashed, leafS)
				toBeHashed = append(toBeHashed, leafC)
			} else {
				leafRows, leafForHashing := prepareLeafRows(storageProof1[i], 2) // leaf s
				rows = append(rows, leafRows...)
				toBeHashed = append(toBeHashed, leafForHashing)
				leafRows, leafForHashing = prepareLeafRows(storageProof2[i], 3) // leaf s
				rows = append(rows, leafRows...)
				toBeHashed = append(toBeHashed, leafForHashing)
			}
		case 17:
			bRows := prepareTwoBranchesWitness(storageProof1[i], storageProof2[i], key[keyIndex], false, false)
			keyIndex += 1

			// extension node rows
			if extensionRowS != nil {
				bRows = append(bRows, extensionRowS)
				bRows = append(bRows, extensionRowC)

				// Set isExtension to 1 in branch init.
				bRows[0][isExtensionPos] = 1

				keyLen := getExtensionNodeKeyLen(storageProof1[i-1])
				// Set whether key extension nibbles are of even or odd length.
				if keyLen == 1 {
					bRows[0][isExtensionOddKeyLenPos] = 1
					bRows[0][isExtensionKeyShortPos] = 1
				} else {
					bRows[0][isExtensionKeyLongPos] = 1
					if storageProof1[i-1][2] == 0 {
						bRows[0][isExtensionEvenKeyLenPos] = 1
					} else {
						bRows[0][isExtensionOddKeyLenPos] = 1
					}
				}

				// adding extension nodes for hashing:
				addForHashing(storageProof1[i-1], &toBeHashed)
				addForHashing(storageProof2[i-1], &toBeHashed)
			} else {
				extRows := prepareEmptyExtensionRows()
				bRows = append(bRows, extRows...)
			}

			rows = append(rows, bRows...)
			addForHashing(storageProof1[i], &toBeHashed)
			addForHashing(storageProof2[i], &toBeHashed)

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
		default:
			fmt.Println("invalid number of list elements")
		}
	}

	addBranch := func(branch1, branch2 []byte, modifiedIndex byte, isCPlaceholder bool) {
		isBranchSPlaceholder := false
		isBranchCPlaceholder := false
		if isCPlaceholder {
			isBranchCPlaceholder = true
		} else {
			isBranchSPlaceholder = true
		}
		bRows := prepareTwoBranchesWitness(branch1, branch2, modifiedIndex, isBranchSPlaceholder, isBranchCPlaceholder)
		rows = append(rows, bRows...)

		branchToBeHashed := branch1
		if !isCPlaceholder {
			branchToBeHashed = branch2
		}
		addForHashing(branchToBeHashed, &toBeHashed)
	}

	getDriftedPosition := func(leafKeyRow []byte, numberOfNibbles int) byte {
		// Get position to which a leaf drifted (to be set in branch init):
		var nibbles []byte
		keyLen := int(leafKeyRow[1] - 128)
		if leafKeyRow[2] == 32 {
			for i := 0; i < keyLen - 1; i++ { // -1 because the first byte doesn't have any nibbles
				b := leafKeyRow[3 + i]
				n1 := b / 16
				n2 := b - n1 * 16
				nibbles = append(nibbles, n1)
				nibbles = append(nibbles, n2)
			}
		} else {
			nibbles = append(nibbles,leafKeyRow[2] - 48)
			for i := 0; i < keyLen - 1; i++ { // -1 because the first byte has already been taken into account
				b := leafKeyRow[3 + i]
				n1 := b / 16
				n2 := b - n1 * 16
				nibbles = append(nibbles, n1)
				nibbles = append(nibbles, n2)
			}
		}

		return nibbles[numberOfNibbles]
	}

	if len1 > len2 {
		if additionalBranch {
			// C branch is just a placeholder here.
			numberOfNibbles := 0
			var extRows [][]byte
			isExtension := len1 == len2 + 2
			if !isExtension {
				extRows = prepareEmptyExtensionRows()
			} else {
				numNibbles, extensionRowS, extensionRowC :=
					prepareExtensionRows(extNibbles, extensionNodeInd, storageProof1[len1 - 3], storageProof1[len1 - 3])
				numberOfNibbles = int(numNibbles)
				extRows = append(extRows, extensionRowS)
				extRows = append(extRows, extensionRowC)

				// adding extension node for hashing:
				addForHashing(storageProof1[len1-3], &toBeHashed)
			}

			addBranch(storageProof1[len1-2], storageProof1[len1-2], key[keyIndex + numberOfNibbles], true)
			rows = append(rows, extRows...)

			leafRows, leafForHashing := prepareLeafRows(storageProof1[len1-1], 2)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			leafRows, leafForHashing = prepareLeafRows(storageProof2[len2-1], 3)
			// We now get the first nibble of the leaf that was turned into branch.
			// This first nibble presents the position of the leaf once it moved
			// into the new branch.
			rows[len(rows)-branchRows-2][driftedPos] =
				getDriftedPosition(leafRows[0], numberOfNibbles) // -branchRows-2 lands into branch init
			if isExtension {
				rows[len(rows)-branchRows-2][isExtensionPos] = 1
				if numberOfNibbles % 2 == 0 {
					rows[len(rows)-branchRows-2][isExtensionEvenKeyLenPos] = 1
				} else {
					rows[len(rows)-branchRows-2][isExtensionOddKeyLenPos] = 1
				}
				if numberOfNibbles == 1 {
					rows[len(rows)-branchRows-2][isExtensionKeyShortPos] = 1
				} else {
					rows[len(rows)-branchRows-2][isExtensionKeyLongPos] = 1
				}
			}
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			// The branch contains hash of the neighbouring leaf, to be able
			// to check it, we add node RLP to toBeHashed
			addForHashing(neighbourNode, &toBeHashed)

			sLeafRows, _ := prepareLeafRows(neighbourNode, 15)
			// Neighbouring leaf - the leaf that used to be one level above,
			// but it was "drifted down" when additional branch was added.
			// Value (sLeafRows[1]) is not needed because we already have it
			// in the parallel proof.
			rows = append(rows, sLeafRows[0])
		} else {
			// We don't have a leaf in the shorter proof, but we will add it there
			// as a placeholder.
			leafRows, leafForHashing := prepareLeafRows(storageProof1[len1-1], 2)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			leafRows, _ = prepareLeafRows(storageProof1[len1-1], 3)
			rows = append(rows, leafRows...)

			pRows := preparePlaceholderRows()
			rows = append(rows, pRows...)
		}
	} else if len2 > len1 {
		if additionalBranch {
			// S branch is just a placeholder here.

			numberOfNibbles := 0
			var extRows [][]byte
			isExtension := len2 == len1 + 2
			if !isExtension {
				extRows = prepareEmptyExtensionRows()
			} else { // diff is 2 when extension node is added
				numNibbles, extensionRowS, extensionRowC :=
					prepareExtensionRows(extNibbles, extensionNodeInd, storageProof2[len2 - 3], storageProof2[len2 - 3])
				numberOfNibbles = int(numNibbles)
				extRows = append(extRows, extensionRowS)
				extRows = append(extRows, extensionRowC)

				// adding extension node for hashing:
				addForHashing(storageProof2[len2-3], &toBeHashed)
			}

			addBranch(storageProof2[len2-2], storageProof2[len2-2], key[keyIndex + numberOfNibbles], false)
			rows = append(rows, extRows...)

			// Note that this is not just reversed order compared to
			// len1 > len2 case - the first leaf is always from proof S
			// (the order of leaves at the end is always: first S, then C).

			leafRows, leafForHashing := prepareLeafRows(storageProof1[len1-1], 2)
			// We now get the first nibble of the leaf that was turned into branch.
			// This first nibble presents the position of the leaf once it moved
			// into the new branch.
			rows[len(rows)-branchRows][driftedPos] = getDriftedPosition(leafRows[0], numberOfNibbles) // -branchRows lands into branch init
			if isExtension {
				rows[len(rows)-branchRows][isExtensionPos] = 1
				if numberOfNibbles % 2 == 0 {
					rows[len(rows)-branchRows][isExtensionEvenKeyLenPos] = 1
				} else {
					rows[len(rows)-branchRows][isExtensionOddKeyLenPos] = 1
				}
				if numberOfNibbles == 1 {
					rows[len(rows)-branchRows][isExtensionKeyShortPos] = 1
				} else {
					rows[len(rows)-branchRows][isExtensionKeyLongPos] = 1
				}
			}
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			leafRows, leafForHashing = prepareLeafRows(storageProof2[len2-1], 3)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			// The branch contains hash of the neighbouring leaf, to be able
			// to check it, we add node RLP to toBeHashed
			addForHashing(neighbourNode, &toBeHashed)
			
			sLeafRows, _ := prepareLeafRows(neighbourNode, 15)
			// Neighbouring leaf - the leaf that used to be one level above,
			// but it was "drifted down" when additional branch was added.
			// Value (sLeafRows[1]) is not needed because we already have it
			// in the parallel proof.
			rows = append(rows, sLeafRows[0])
		} else {
			leafRows, leafForHashing := prepareLeafRows(storageProof2[len2-1], 2)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			leafRows, _ = prepareLeafRows(storageProof2[len2-1], 3)
			rows = append(rows, leafRows...)

			pRows := preparePlaceholderRows()
			rows = append(rows, pRows...)
		}
	} else if !isAccountProof {
		pRows := preparePlaceholderRows()
		rows = append(rows, pRows...)
	}

	return rows, toBeHashed, extensionNodeInd > 0
}

func updateStorageAndGetProofs(keys, values []common.Hash, toBeModified common.Hash, value common.Hash) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81c9")

	for i := 0; i < len(keys); i++ {
		statedb.SetState(addr, keys[i], values[i])
	}

	// Calling IntermediateRoot because of delete operation - without this call,
	// delete doesn't happen, see
	//if value == s.originStorage[key] {
	//		continue
	//}
	// in state_object.go, because originStorage stays set to 0 and value = 0.
	statedb.IntermediateRoot(false)
	// Let's say above state is our starting position.
	storageProof, neighbourNode1, extNibbles1, err := statedb.GetStorageProof(addr, toBeModified)
	check(err)

	kh := crypto.Keccak256(toBeModified.Bytes())
	key := trie.KeybytesToHex(kh)

	// Just to check key RLC (rand = 2)
	kh_sum := 0
	mult := 1
	for i := 0; i < len(kh); i++ {
		kh_sum += int(kh[i]) * mult
		mult *= 2
	}
	fmt.Println("key sum:")
	fmt.Println(kh_sum)

	/*
		Modifying storage:
	*/

	// We now change one existing storage slot:
	statedb.SetState(addr, toBeModified, value)

	// We ask for a proof for the modified slot:
	statedb.IntermediateRoot(false)
	storageProof1, neighbourNode2, extNibbles2, err := statedb.GetStorageProof(addr, toBeModified)
	check(err)

	// Neighbouring node (neighbour to the node that is being added or deleted) is used
	// because when a node is added which causes some node to turn into a branch, then
	// this "some" node moves into a branch and is neighbour to the node that has been added.
	// In MPT circuit, when a node is added, we check that "some" node turns into "neighbour".

	// Similarly, when a node is deleted and if it has only one neighbour in a branch,
	// this neighbour replaces the branch.
	// In MPT circuit, we check that the neighbouring node replaces the branch.
	node := neighbourNode2
	extNibbles := extNibbles2
	if len(storageProof) > len(storageProof1) {
		// delete operation
		node = neighbourNode1
		extNibbles = extNibbles1
	}

	// TODO: extNibbles are different in case of added/deleted extension
	rows, toBeHashed, hasExtensionNode :=
		prepareWitness(storageProof, storageProof1, extNibbles, key, node, false)
	rows = append(rows, toBeHashed...)
	fmt.Println(matrixToJson(rows))

	len1 := len(storageProof)
	len2 := len(storageProof1)
	if !hasExtensionNode {
		if len1 == len2 {
			if !VerifyTwoProofsAndPath(storageProof, storageProof1, key) {
				panic("proof not valid")
			}
		} else {
			minLen := len2
			if len1 > len2 {
				storageProof = storageProof[:len1-1]
			} else {
				storageProof1 = storageProof1[:len2-1]
				minLen = len1
			}

			if !VerifyProof(storageProof, key) {
				panic("proof not valid")
			}
			if !VerifyProof(storageProof1, key) {
				panic("proof 1 not valid")
			}

			hasher := trie.NewHasher(false)

			for i := 0; i < minLen-1; i++ {
				rootHash := hasher.HashData(storageProof[i])
				root, err := trie.DecodeNode(rootHash, storageProof[i])
				check(err)
				r := root.(*trie.FullNode)

				rootHash1 := hasher.HashData(storageProof1[i])
				root1, err := trie.DecodeNode(rootHash1, storageProof1[i])
				check(err)
				r1 := root1.(*trie.FullNode)

				if !VerifyElementsInTwoBranches(r, r1, key[i]) {
					panic("proof not valid")
				}
			}
		}
	}
}

func updateStateAndGetProofs(keys, values []common.Hash, toBeModified, value common.Hash, addr common.Address) {
	// Here we are checking the whole state trie, not only a storage trie for some account as in above tests.
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)

	for i := 0; i < len(keys); i++ {
		statedb.SetState(addr, keys[i], values[i])
	}
	getProofs(toBeModified, value, addr, statedb)
}

func getProofs(toBeModified, value common.Hash, addr common.Address, statedb *state.StateDB) {
	// If we don't call IntermediateRoot, obj.data.Root will be hash(emptyRoot).
	statedb.IntermediateRoot(false)

	// Let's say above is our starting position.

	// We now get a proof for the starting position for the slot that will be changed further on (ks[1]):
	// This first proof will actually be retrieved by RPC eth_getProof (see oracle.PrefetchStorage function).
	// All other proofs (after modifications) will be generated internally by buildig the internal state.

	accountProof, _, _, err := statedb.GetProof(addr)
	check(err)
	storageProof, neighbourNode1, extNibbles1, err := statedb.GetStorageProof(addr, toBeModified)
	check(err)

	// By calling RPC eth_getProof we will get accountProof and storageProof.

	// The last element in accountProof contains the state object for this address.
	// We need to verify that the state object for this address is the in last
	// element of the accountProof. The last element of the accountProof actually contains the RLP of
	// nonce, balance, code, and root.
	// We need to use a root from the storage proof (first element) and obtain balance, code, and nonce
	// by the following RPC calls:
	// eth_getBalance, eth_getCode, eth_getTransactionCount (nonce).
	// We use these four values to compute the hash and compare it to the last value in accountProof.

	// We simulate getting the RLP of the four values (instead of using RPC calls and taking the first
	// element of the storage proof):
	obj := statedb.GetOrNewStateObject(addr)
	rl, err := rlp.EncodeToBytes(obj)
	check(err)

	hasher := trie.NewHasher(false)

	ind := len(accountProof) - 1
	accountHash := hasher.HashData(accountProof[ind])
	accountLeaf, err := trie.DecodeNode(accountHash, accountProof[ind])
	check(err)

	account := accountLeaf.(*trie.ShortNode)
	accountValueNode := account.Val.(trie.ValueNode)

	// Constraint for checking the transition from storage to account proof:
	if fmt.Sprintf("%b", rl) != fmt.Sprintf("%b", accountValueNode) {
		panic("not the same")
	}

	hasher1 := trie.NewHasher(false)
	hash := hasher1.HashData(storageProof[0])
	fmt.Println(hash)

	t := obj.Trie
	fmt.Println(t)
	h := t.Hash()
	fmt.Println(h)

	addrh := crypto.Keccak256(addr.Bytes())
	accountAddr := trie.KeybytesToHex(addrh)

	kh := crypto.Keccak256(toBeModified.Bytes())
	key := trie.KeybytesToHex(kh)
	
	/*
		Modifying storage:
	*/

	// We now change one existing storage slot:
	statedb.SetState(addr, toBeModified, value)

	// We ask for a proof for the modified slot:
	statedb.IntermediateRoot(false)

	accountProof1, _, extNibblesAccount, err := statedb.GetProof(addr)
	check(err)

	storageProof1, neighbourNode2, extNibbles2, err := statedb.GetStorageProof(addr, toBeModified)
	check(err)

	node := neighbourNode2
	extNibbles := extNibbles2
	if len(storageProof) > len(storageProof1) {
		// delete operation
		node = neighbourNode1
		extNibbles = extNibbles1
	}
	
	// TODO: extNibbles not the same for storage when extension is added/deleted

	rowsState, toBeHashedAcc, hasExtensionNodeAccount :=
		prepareWitness(accountProof, accountProof1, extNibblesAccount, accountAddr, nil, true)
	rowsStorage, toBeHashedStorage, hasExtensionNode :=
		prepareWitness(storageProof, storageProof1, extNibbles, key, node, false)
	rowsState = append(rowsState, rowsStorage...)

	// Put rows that just need to be hashed at the end, because circuit assign function
	// relies on index (for example when assigning s_keccak and c_keccak).
	rowsState = append(rowsState, toBeHashedAcc...)
	rowsState = append(rowsState, toBeHashedStorage...)

	/*
		// If only storage:
		rowsStorage, toBeHashedStorage := prepareWitness(storageProof, storageProof1, key, false)
		rowsState := append(rowsStorage, toBeHashedStorage...)
	*/

	fmt.Println(matrixToJson(rowsState))

	// Just to check key RLC (rand = 2)
	kh_sum := 0
	addr_sum := 0
	mult := 1
	for i := 0; i < len(kh); i++ {
		kh_sum += int(kh[i]) * mult
		addr_sum += int(addrh[i]) * mult
		mult *= 2 // just some value that is not 1 to enable testing the multiplier too
	}
	fmt.Println("address/key RLC:")
	fmt.Println(addr_sum)
	fmt.Println(kh_sum)

	if !hasExtensionNodeAccount {
		if !VerifyTwoProofsAndPath(accountProof, accountProof1, accountAddr) {
			panic("proof not valid")
		}
	}
	if !hasExtensionNode {
		if !VerifyTwoProofsAndPath(storageProof, storageProof1, key) {
			panic("proof not valid")
		}
	}
}

func TestUpdateOneLevel(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// We have a branch with children at position 3 and 11.

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	// This key is turned into odd length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	toBeModified := ks[0]
	v := common.BigToHash(big.NewInt(int64(17)))
	addr := common.HexToAddress("0xaaaccf12580138bc2bbceeeaa111df4e42ab81ff")
	updateStateAndGetProofs(ks[:], values, toBeModified, v, addr)
}

func TestUpdateOneLevelBigVal(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// We have a branch with children at position 3 and 11.

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	// This key is turned into odd length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	toBeModified := ks[0]
	// big value so that RLP is longer than 55 bytes
	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	addr := common.HexToAddress("0xaaaccf12580138bc2bbceeeaa826df4e42ab81ff")
	updateStateAndGetProofs(ks[:], values, toBeModified, v2, addr)
}

func TestUpdateTwoLevels(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x11"), common.HexToHash("0x12"), common.HexToHash("0x21")} // this has three levels
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// First we have a branch with children at position 3 and 11.
	// The third storage change happens at key:
	// [3,10,6,3,5,7,...
	// That means leaf at position 3 turns into branch with children at position 1 and 10.
	// ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	// This key is turned into even length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	toBeModified := ks[0]
	v := common.BigToHash(big.NewInt(int64(17)))
	addr := common.HexToAddress("0xaaaccf12580138bc2bbc957aa826df4e42ab81ff")
	updateStateAndGetProofs(ks[:], values, toBeModified, v, addr)
}

func TestUpdateTwoLevelsBigVal(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x11"), common.HexToHash("0x12"), common.HexToHash("0x21")} // this has three levels
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// First we have a branch with children at position 3 and 11.
	// The third storage change happens at key:
	// [3,10,6,3,5,7,...
	// That means leaf at position 3 turns into branch with children at position 1 and 10.
	// ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	// This key is turned into even length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	toBeModified := ks[0]

	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	addr := common.HexToAddress("0xaaaccf12580138bc2bbc957aa826df4e42ab81ff")
	updateStateAndGetProofs(ks[:], values, toBeModified, v2, addr)
}

func TestUpdateThreeLevels(t *testing.T) {
	ks := [...]common.Hash{
		common.HexToHash("0x11"),
		common.HexToHash("0x12"),
		common.HexToHash("0x21"),
		common.HexToHash("0x31"),
		common.HexToHash("0x32"),
		common.HexToHash("0x33"),
		common.HexToHash("0x34"),
		common.HexToHash("0x35"),
		common.HexToHash("0x36"),
		common.HexToHash("0x37"),
		common.HexToHash("0x38"), //
		common.HexToHash("0x39"),
		common.HexToHash("0x40"),
		common.HexToHash("0x41"),
		common.HexToHash("0x42"),
		common.HexToHash("0x43"),
		common.HexToHash("0x44"),
		common.HexToHash("0x45"),
		common.HexToHash("0x46"),
	}
	/*
		ks[10] = 0x38 is at position 3 in root.Children[3].Children[8]

		nibbles
		[9,5,12,5,13,12,14,10,13,14,9,6,0,3,4,7,9,11,1,7,7,11,6,8,9,5,9,0,4,9,4,8,5,13,15,8,10,10,9,7,11,3,9,15,3,5,3,3,0,3,9,10,15,5,15,4,5,6,1,9,9,16]

		terminator flag 16 (last byte) is removed, then it remains len 61 (these are nibbles):
		[9,5,12,5,13,12,14,10,13,14,9,6,0,3,4,7,9,11,1,7,7,11,6,8,9,5,9,0,4,9,4,8,5,13,15,8,10,10,9,7,11,3,9,15,3,5,3,3,0,3,9,10,15,5,15,4,5,6,1,9,9]

		buf (31 len):
		this is key stored in leaf:
		[57,92,93,206,173,233,96,52,121,177,119,182,137,89,4,148,133,223,138,169,123,57,243,83,48,57,175,95,69,97,153]
	*/

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	toBeModified := ks[10]

	v := common.BigToHash(big.NewInt(int64(17)))
	addr := common.HexToAddress("0xaaaccf12580138bc263c95757826df4e42ab81ff")
	updateStateAndGetProofs(ks[:], values, toBeModified, v, addr)
}

func TestFromNilToValue(t *testing.T) {
	ks := [...]common.Hash{
		common.HexToHash("0x11"),
		common.HexToHash("0x12"),
		common.HexToHash("0x21"),
		common.HexToHash("0x31"),
		common.HexToHash("0x32"),
		common.HexToHash("0x33"),
		common.HexToHash("0x34"),
		common.HexToHash("0x35"),
		common.HexToHash("0x36"),
		common.HexToHash("0x37"),
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	// This test is similar as above, but the key that is being modified has not been used yet.

	toBeModified := common.HexToHash("0x38")

	v := common.BigToHash(big.NewInt(int64(17)))
	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e42ab81ff")
	updateStateAndGetProofs(ks[:], values, toBeModified, v, addr)
}

func TestDelete(t *testing.T) {
	ks := [...]common.Hash{
		common.HexToHash("0xaaaabbbbabab"),
		common.HexToHash("0xbaaabbbbabab"),
		common.HexToHash("0xcaaabbbbabab"),
		common.HexToHash("0xdaaabbbbabab"),
	}

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	toBeModified := common.HexToHash("0xdaaabbbbabab")

	val := common.Hash{} // empty value deletes the key
	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81ff")
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestUpdateOneLevel1(t *testing.T) {
	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81c9")
	// This address is turned into odd length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	// This is a storage slot that will be modified (the list will come from bus-mapping):
	toBeModified := ks[1]
	val := common.BigToHash(big.NewInt(int64(17)))
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestUpdateOneLevelEvenAddress(t *testing.T) {
	addr := common.HexToAddress("0x25efbf12580138bc263c95757826df4e24eb81c9")
	// This address is turned into even length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	// This is a storage slot that will be modified (the list will come from bus-mapping):
	toBeModified := ks[1]
	val := common.BigToHash(big.NewInt(int64(17)))
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestAddBranch(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x11"), common.HexToHash("0x12")}
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// First we have a branch with children at position 3 and 11.
	// ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	// This key is not in the trie yet, its nibbles:
	// [3,10,6,3,5,7,...
	// That means leaf at position 3 turns into branch with children at position 1 and 10.
	toBeModified := common.HexToHash("0x21")

	v := common.BigToHash(big.NewInt(int64(17)))
	addr := common.HexToAddress("0x75acef12a01883c2b3fc57957826df4e24e8baaa")
	updateStateAndGetProofs(ks[:], values, toBeModified, v, addr)
}

func TestAddBranchLong(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x11"), common.HexToHash("0x12")}
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// First we have a branch with children at position 3 and 11.
	// ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	var values []common.Hash
	// big value so that RLP will be longer than 55 bytes for the neighbouring node
	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	for i := 0; i < len(ks); i++ {
		values = append(values, v2)
	}

	// This key is not in the trie yet, its nibbles:
	// [3,10,6,3,5,7,...
	// That means leaf at position 3 turns into branch with children at position 1 and 10.
	toBeModified := common.HexToHash("0x21")

	v := common.BigToHash(big.NewInt(int64(17)))
	addr := common.HexToAddress("0x75acef12a01883c2b3fc57957826df4e24e8b19c")
	updateStateAndGetProofs(ks[:], values, toBeModified, v, addr)
}

func TestDeleteBranch(t *testing.T) {
	h := common.HexToHash("0x11dd2277aa")

	ks := [...]common.Hash{
		common.HexToHash("0xaa"),
		common.HexToHash("0xabcc"),
		common.HexToHash("0xffdd"),
		common.HexToHash("0x11dd"),
		common.HexToHash("0x11dd22"),
		common.HexToHash("0x11dd2233"),
		common.HexToHash("0x11dd2255"),
		common.HexToHash("0x11dd2277"),
		h, // this leaf turns into a branch
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	toBeModified := h

	v := common.Hash{} // empty value deletes the key
	addr := common.HexToAddress("0x75acef12a0188c32b36c57957826df4e24e8b19c")
	updateStateAndGetProofs(ks[:], values, toBeModified, v, addr)
}

func TestDeleteBranchLong(t *testing.T) {
	h := common.HexToHash("0x11dd2277aa")

	ks := [...]common.Hash{
		common.HexToHash("0xaa"),
		common.HexToHash("0xabcc"),
		common.HexToHash("0xffdd"),
		common.HexToHash("0x11dd"),
		common.HexToHash("0x11dd22"),
		common.HexToHash("0x11dd2233"),
		common.HexToHash("0x11dd2255"),
		common.HexToHash("0x11dd2277"),
		h, // this leaf turns into a branch
	}

	var values []common.Hash
	// big value so that RLP will be longer than 55 bytes for the neighbouring node
	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	for i := 0; i < len(ks); i++ {
		values = append(values, v2)
	}
	
	toBeModified := h

	v := common.Hash{} // empty value deletes the key
	addr := common.HexToAddress("0x75acef12a0188c32b36c57957826df4e24e8b19c")
	updateStateAndGetProofs(ks[:], values, toBeModified, v, addr)
}

func TestAddBranchTwoLevels(t *testing.T) {
	// Test for case when branch is added in the second level. So, instead of having only
	// branch1 with some nodes and then one of this nodes is replaced with a branch (that's
	// the case of TestAddBranch), we have here branch1 and then inside it another
	// branch: branch2. Inside brach2 we have a node which gets replaced by a branch.
	// This is to test cases when the key contains odd number of nibbles as well as
	// even number of nibbles.

	a := 1
	b := 1
	h := fmt.Sprintf("0xaa%d%d", a, b)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 33; i++ {
		// just some values to get the added branch in second level (found out trying different values)
		if i % 2 == 0 {
			a += 1
		} else {
			b += 1
		}
		if a == 4 && b == 3 {
			continue
		}
		h := fmt.Sprintf("0xaa%d%d", a, b)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	toBeModified := common.HexToHash("0xaa43")

	v := common.BigToHash(big.NewInt(int64(17)))
	addr := common.HexToAddress("0x75fbef12a0188c32b36c57957826df4e24e8b19c")
	updateStateAndGetProofs(ks[:], values, toBeModified, v, addr)
}

func TestAddBranchTwoLevelsLong(t *testing.T) {
	a := 1
	b := 1
	h := fmt.Sprintf("0xaa%d%d", a, b)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 33; i++ {
		// just some values to get the added branch in second level (found out trying different values)
		if i % 2 == 0 {
			a += 1
		} else {
			b += 1
		}
		if a == 4 && b == 3 {
			continue
		}
		h := fmt.Sprintf("0xaa%d%d", a, b)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	for i := 0; i < len(ks); i++ {
		values = append(values, v2)
	}

	toBeModified := common.HexToHash("0xaa43")

	v := common.BigToHash(big.NewInt(int64(17)))
	addr := common.HexToAddress("0x75fbef1250188c32b63c57957826df4e24e8b19c")
	updateStateAndGetProofs(ks[:], values, toBeModified, v, addr)
}

func TestDeleteBranchTwoLevels(t *testing.T) {
	a := 1
	b := 1
	h := fmt.Sprintf("0xaa%d%d", a, b)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 33; i++ {
		// just some values to get the added branch in second level (found out trying different values)
		if i % 2 == 0 {
			a += 1
		} else {
			b += 1
		}
		h := fmt.Sprintf("0xaa%d%d", a, b)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	toBeModified := common.HexToHash("0xaa43")

	v := common.Hash{}
	addr := common.HexToAddress("0x75fbef1250188c32b63c57957826df4e24eb81c9")
	updateStateAndGetProofs(ks[:], values, toBeModified, v, addr)
}

func TestDeleteBranchTwoLevelsLong(t *testing.T) {
	a := 1
	b := 1
	h := fmt.Sprintf("0xaa%d%d", a, b)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 33; i++ {
		// just some values to get the added branch in second level (found out trying different values)
		if i % 2 == 0 {
			a += 1
		} else {
			b += 1
		}
		h := fmt.Sprintf("0xaa%d%d", a, b)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	for i := 0; i < len(ks); i++ {
		values = append(values, v2)
	}

	toBeModified := common.HexToHash("0xaa43")

	v := common.Hash{}
	addr := common.HexToAddress("0x75fbef21508183c2b63c57957826df4e24eb81c9")
	updateStateAndGetProofs(ks[:], values, toBeModified, v, addr)
}

func TestExtensionOneKeyByteSel1(t *testing.T) {
	ks := [...]common.Hash{
		common.HexToHash("0x11"),
		common.HexToHash("0x12"),
		common.HexToHash("0x21"),
		common.HexToHash("0x31"),
		common.HexToHash("0x32"),
		common.HexToHash("0x33"),
		common.HexToHash("0x34"),
		common.HexToHash("0x35"),
		common.HexToHash("0x36"),
		common.HexToHash("0x37"),
		common.HexToHash("0x38"), //
		common.HexToHash("0x39"),
		common.HexToHash("0x40"),
		common.HexToHash("0x42"),
		common.HexToHash("0x43"),
		common.HexToHash("0x44"),
		common.HexToHash("0x45"),
		common.HexToHash("0x46"),
		common.HexToHash("0x47"),
		common.HexToHash("0x48"),
		common.HexToHash("0x50"),
		common.HexToHash("0x51"),
		common.HexToHash("0x52"),
		common.HexToHash("0x53"),
		common.HexToHash("0x54"),
		common.HexToHash("0x55"),
		common.HexToHash("0x56"),

		common.HexToHash("0x61"), // extension
	}

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	
	toBeModified := ks[len(ks)-1]
	addr := common.HexToAddress("0x75fbef21508183c2b63c57957826df4e24eb81c9")
	val := common.BigToHash(big.NewInt(int64(17)))
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestExtensionAddedOneKeyByteSel1(t *testing.T) {
	a := 1
	b := 1
	h := fmt.Sprintf("0x%d%d", a, b)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 33; i++ {
		// just some values to get the added branch in second level (found out trying different values)
		if i % 2 == 0 {
			a += 1
		} else {
			b += 1
		}
		h := fmt.Sprintf("0x%d%d", a, b)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	toBeModified := common.HexToHash("0x1818")

	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81c9")
	val := common.BigToHash(big.NewInt(int64(17)))
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestExtensionDeletedOneKeyByteSel1(t *testing.T) {
	a := 1
	b := 1
	h := fmt.Sprintf("0x%d%d", a, b)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 33; i++ {
		// just some values to get the added branch in second level (found out trying different values)
		if i % 2 == 0 {
			a += 1
		} else {
			b += 1
		}
		h := fmt.Sprintf("0x%d%d", a, b)
		ks = append(ks, common.HexToHash(h))
	}
	toBeModified := common.HexToHash("0x1818")
	ks = append(ks, toBeModified)
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81c9")
	val := common.Hash{} // empty value deletes the key
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestExtensionOneKeyByteSel2(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0xca%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 876; i++ {
		a += 1
		h := fmt.Sprintf("0xca%d", a)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	toBeModified := common.HexToHash("0xca644")
	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	val := common.BigToHash(big.NewInt(int64(17)))
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestExtensionAddedOneKeyByteSel2(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0xca%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	toBeModifiedStr := "0xca644"
	toBeModified := common.HexToHash(toBeModifiedStr)
	for i := 0; i < 876; i++ {
		a += 1
		h := fmt.Sprintf("0xca%d", a)
		if h == toBeModifiedStr {
			continue
		}
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	val := common.BigToHash(big.NewInt(int64(17)))
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestExtensionDeletedOneKeyByteSel2(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0xca%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	toBeModifiedStr := "0xca644"
	toBeModified := common.HexToHash(toBeModifiedStr)
	for i := 0; i < 876; i++ {
		a += 1
		h := fmt.Sprintf("0xca%d", a)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	val := common.Hash{} // empty value deletes the key
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestExtensionTwoKeyBytesSel1(t *testing.T) {
	// Extension node which has key longer than 1 (2 in this test). This is needed because RLP takes
	// different positions.
	// Key length > 1 (130 means there are two bytes for key; 160 means there are 32 hash values after it):
	// [228 130 0 149 160 ...
	// Key length = 1 (no byte specifying the length of key):
	// [226 16 160 ...
	a := 0
	h := fmt.Sprintf("0x%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 176; i++ {
		// just some values to get the extension with key length > 1 (found out trying different values)
		a += 1
		h := fmt.Sprintf("0x%d", a)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	toBeModified := common.HexToHash("0x172")
	addr := common.HexToAddress("0x75fbef21508183c2b63c59757826df4e24eb81c9")
	val := common.BigToHash(big.NewInt(int64(17)))
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestExtensionAddedTwoKeyBytesSel1(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0x%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	toBeModifiedStr := "0x172"
	toBeModified := common.HexToHash(toBeModifiedStr)
	for i := 0; i < 176; i++ {
		// just some values to get the extension with key length > 1 (found out trying different values)
		a += 1
		h := fmt.Sprintf("0x%d", a)
		if h == toBeModifiedStr {
			continue
		}
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	addr := common.HexToAddress("0x75fbef21508183c2b63c59757826df4e24eb81c9")
	val := common.BigToHash(big.NewInt(int64(17)))
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestExtensionDeletedTwoKeyBytesSel1(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0x%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	toBeModifiedStr := "0x172"
	toBeModified := common.HexToHash(toBeModifiedStr)
	for i := 0; i < 176; i++ {
		// just some values to get the extension with key length > 1 (found out trying different values)
		a += 1
		h := fmt.Sprintf("0x%d", a)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	addr := common.HexToAddress("0x75fbef21508183c2b63c59757826df4e24eb81c9")
	val := common.Hash{} // empty value deletes the key
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestExtensionTwoKeyBytesSel2(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0x2ea%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 876; i++ {
		a += 1
		h := fmt.Sprintf("0x2ea%d", a)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	toBeModified := common.HexToHash("0x2ea772")
	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	val := common.BigToHash(big.NewInt(int64(17)))
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestExtensionAddedTwoKeyBytesSel2(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0x2ea%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	toBeModifiedStr := "0x2ea772"
	toBeModified := common.HexToHash(toBeModifiedStr)
	for i := 0; i < 876; i++ {
		a += 1
		h := fmt.Sprintf("0x2ea%d", a)
		if h == toBeModifiedStr {
			continue
		}
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	val := common.BigToHash(big.NewInt(int64(17)))
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestExtensionThreeBytesSel2(t *testing.T) {
	// still searching for the right values
	a := 0
	h := fmt.Sprintf("0xf8a%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 1000; i++ {
		a += 1
		h := fmt.Sprintf("0xf8a%d", a)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	toBeModified := common.HexToHash("0xfa935")
	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	val := common.BigToHash(big.NewInt(int64(17)))
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestExtensionInFirstStorageLevel(t *testing.T) {
	ks := []common.Hash{common.HexToHash("0x12")}

	for i := 0; i < 10; i++ {
		h := fmt.Sprintf("0x%d", i)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	toBeModified := common.HexToHash("0x1")
	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	val := common.BigToHash(big.NewInt(int64(17)))
	updateStateAndGetProofs(ks[:], values, toBeModified, val, addr)
}

func TestExtensionInFirstStorageLevelOneKeyByte(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50efbf12580138bc623c95757286df4e24eb81c9")

	key1 := common.HexToHash("0x12")
	val1 := common.BigToHash(big.NewInt(int64(1)))

	statedb.SetState(addr, key1, val1)

	h := fmt.Sprintf("0x%d", 1)
	key2 := common.HexToHash(h)
	statedb.SetState(addr, key2, val1)
	statedb.IntermediateRoot(false)

	toBeModified := common.HexToHash("0x1")
	val := common.BigToHash(big.NewInt(int64(17)))
	getProofs(toBeModified, val, addr, statedb)
}

func TestExtensionAddedInFirstStorageLevelOneKeyByte(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50efbf12580138bc623c95757286df4e24eb81c9")

	key1 := common.HexToHash("0x12")
	val1 := common.BigToHash(big.NewInt(int64(1)))

	statedb.SetState(addr, key1, val1)

	toBeModified := common.HexToHash("0x1")
	// statedb.SetState(addr, toBeModified, val1)
	statedb.IntermediateRoot(false)

	val := common.BigToHash(big.NewInt(int64(17)))
	getProofs(toBeModified, val, addr, statedb)
}

func TestExtensionInFirstStorageLevelTwoKeyBytes(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50efbf12580138bc623c95757286df4e24eb81c9")

	key1 := common.HexToHash("0x12")
	val1 := common.BigToHash(big.NewInt(int64(1)))

	statedb.SetState(addr, key1, val1)

	toBeModified := common.HexToHash("0xa617")
	statedb.SetState(addr, toBeModified, val1)
	statedb.IntermediateRoot(false)

	val := common.BigToHash(big.NewInt(int64(17)))
	getProofs(toBeModified, val, addr, statedb)
}

func TestExtensionAddedInFirstStorageLevelTwoKeyBytes(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50efbf12580138bc623c95757286df4e24eb81c9")

	key1 := common.HexToHash("0x12")
	val1 := common.BigToHash(big.NewInt(int64(1)))

	statedb.SetState(addr, key1, val1)

	toBeModified := common.HexToHash("0xa617")
	// statedb.SetState(addr, toBeModified, val1)
	statedb.IntermediateRoot(false)

	val := common.BigToHash(big.NewInt(int64(17)))
	getProofs(toBeModified, val, addr, statedb)
}


func TestExtensionThreeKeyBytesSel2(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50feb1f2580138bc623c97557286df4e24eb81c9")

	for i := 0; i < 14; i++ {
		h := fmt.Sprintf("0x%d", i)
		key2 := common.HexToHash(h)
		val1 := common.BigToHash(big.NewInt(int64(1)))
		statedb.SetState(addr, key2, val1)
	}

	h := fmt.Sprintf("0x13%d", 234)
	key2 := common.HexToHash(h)
	val1 := common.BigToHash(big.NewInt(int64(1)))
	statedb.SetState(addr, key2, val1)

	toBeModified := common.HexToHash("0x13234")
	val := common.BigToHash(big.NewInt(int64(17)))
	getProofs(toBeModified, val, addr, statedb)
}

func TestExtensionThreeKeyBytes(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50fbe1f25aa0843b623c97557286df4e24eb81c9")

	for i := 0; i < 140; i++ {
		h := fmt.Sprintf("0x%d", i)
		key2 := common.HexToHash(h)
		val1 := common.BigToHash(big.NewInt(int64(1)))
		statedb.SetState(addr, key2, val1)
	}

	// Let's get a key which makes extension node at the first level.
	// (set the breakpoint in trie.go, line 313)
	for i := 0; i < 1000; i++ {
		h := fmt.Sprintf("0x2111d%d", i)
		key2 := common.HexToHash(h)
		val1 := common.BigToHash(big.NewInt(int64(1)))
		statedb.SetState(addr, key2, val1)
		statedb.IntermediateRoot(false)

		// v := common.Hash{} // empty value deletes the key
		// statedb.SetState(addr, key2, v)
	}

	toBeModified := common.HexToHash("0x333")
	val := common.BigToHash(big.NewInt(int64(17)))
	getProofs(toBeModified, val, addr, statedb)
}

func TestFindAccount(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	
	for i := 0; i < 1000; i++ {
		h := fmt.Sprintf("0x%d", i)
		addr := common.HexToAddress(h)
		// statedb.IntermediateRoot(false)
		statedb.CreateAccount(addr)

		accountProof, _, _, err := statedb.GetProof(addr)
		check(err)
		// fmt.Println(accountProof)
		if len(accountProof) < 3 {
			fmt.Println(len(accountProof))
			fmt.Println("asdfsadf")
		}

	}

}