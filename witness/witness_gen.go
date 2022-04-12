package witness

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"

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

const accountLeafRows = 5
const counterLen = 4

// rowLen - each branch node has 2 positions for RLP meta data and 32 positions for hash
const rowLen = branch2start + 2 + 32 + 1 // +1 is for info about what type of row is it
const keyPos = 10
const isBranchSPlaceholderPos = 11
const isBranchCPlaceholderPos = 12
const driftedPos = 13
const isExtensionPos = 14
// extension key even or odd is about nibbles - that determines whether the first byte (not
// considering RLP bytes) is 0 or 1 (see encoding.go hexToCompact)
const isBranchC16Pos = 19
const isBranchC1Pos = 20
const isExtShortC16Pos = 21
const isExtShortC1Pos = 22
const isExtLongEvenC16Pos = 23
const isExtLongEvenC1Pos = 24
const isExtLongOddC16Pos = 25
const isExtLongOddC1Pos = 26

/*
Info about row type (given as the last element of the row):
0: init branch (such a row contains RLP info about the branch node; key)
1: branch child
2: storage leaf s key
3: storage leaf c key
5: hash to be computed (for example branch RLP whose hash needs to be checked in the parent)
6: account leaf key S
7: account leaf nonce balance S
8: account leaf nonce balance C
9: account leaf root codehash S
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

func MatrixToJson(rows [][]byte) string {
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

func computeRLC(stream []byte) int {
	sum := 0
	mult := 1
	for i := 0; i < len(stream); i++ {
		sum += int(stream[i]) * mult
		mult *= 2 // just some value that is not 1 to enable testing the multiplier too
	}

	return sum
}

// Equip proof with intermediate state roots, first level info, counter, address RLC,
// modification tag (whether it is storage / nonce / balance change).
func insertMetaInfo(stream, sRoot, cRoot, address, counter []byte, notFirstLevel, isStorageMod, isNonceMod, isBalanceMod, isCodeHashMod byte) []byte {
	// The last byte (-1) in a row determines the type of the row.
	// Byte -2 determines whether it's the first level or not.
	// Bytes before that store intermediate final and end roots.
	l := len(stream)
	extendLen := 64 + 32 + 32 + counterLen + 1 + 4
	extended := make([]byte, l + extendLen) // make space for 32 + 32 + 32 + 1 (s hash, c hash, public_root, notFirstLevel)
	copy(extended, stream)
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

	return extended
}

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

func prepareLeafRows(row []byte, typ byte, valueIsZero bool) ([][]byte, []byte) {
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
		if !valueIsZero {
			copy(leaf2, row[keyLen+3:]) // RLP data in s_rlp1 and s_rlp2, value starts in s_advices[0]
		}
		leaf2 = append(leaf2, typ2)
	} else {
		keyLen := row[1] - 128
		copy(leaf1, row[:keyLen+2])
		leaf1 = append(leaf1, typ)
		if !valueIsZero {
			copy(leaf2, row[keyLen+2:]) // value starts in s_rlp1
		}
		leaf2 = append(leaf2, typ2)
	}

	leafForHashing := make([]byte, len(row))
	copy(leafForHashing, row)
	leafForHashing = append(leafForHashing, 5)

	return [][]byte{leaf1, leaf2}, leafForHashing
}

func prepareTwoBranchesWitness(branch1, branch2 []byte, key, branchC16, branchC1 byte, isBranchSPlaceholder, isBranchCPlaceholder bool) [][]byte {
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

	rows[0][isBranchC16Pos] = branchC16
	rows[0][isBranchC1Pos] = branchC1

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

	branchC16 := byte(0); 
	branchC1 := byte(1);
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

				// key is same for S and C
				keyLen := int(leafS[2]) - 128
				keyRow := make([]byte, rowLen)
				for i := 0; i < 3+keyLen; i++ {
					keyRow[i] = leafS[i]
				}

				rlpStringSecondPartLenS := leafS[3+keyLen] - 183
				if rlpStringSecondPartLenS != 1 {
					panic("Account leaf RLP at this position should be 1 (S)")
				}
				rlpStringSecondPartLenC := leafC[3+keyLen] - 183
				if rlpStringSecondPartLenC != 1 {
					panic("Account leaf RLP at this position should be 1 (C)")
				}
				rlpStringLenS := leafS[3+keyLen+1]
				rlpStringLenC := leafC[3+keyLen+1]

				// [248,112,157,59,158,160,175,159,65,212,107,23,98,208,38,205,150,63,244,2,185,236,246,95,240,224,191,229,27,102,202,231,184,80,248,78
				// In this example RLP, there are first 36 bytes of a leaf.
				// 157 means there are 29 bytes for key (157 - 128).
				// Positions 32-35: 184, 80, 248, 78.
				// 184 - 183 = 1 means length of the second part of a string.
				// 80 means length of a string.
				// 248 - 247 = 1 means length of the second part of a list.
				// 78 means length of a list.

				rlpListSecondPartLenS := leafS[3+keyLen+1+1] - 247
				if rlpListSecondPartLenS != 1 {
					panic("Account leaf RLP 1 (S)")
				}
				rlpListSecondPartLenC := leafC[3+keyLen+1+1] - 247
				if rlpListSecondPartLenC != 1 {
					panic("Account leaf RLP 1 (C)")
				}

				rlpListLenS := leafS[3+keyLen+1+1+1]
				if rlpStringLenS != rlpListLenS+2 {
					panic("Account leaf RLP 2 (S)")
				}

				rlpListLenC := leafC[3+keyLen+1+1+1]
				if rlpStringLenC != rlpListLenC+2 {
					panic("Account leaf RLP 2 (C)")
				}

				nonceStart := 3 + keyLen + 1 + 1 + 1 + 1
				nonceRlpLenS := leafS[nonceStart] - 128
				nonceS := leafS[nonceStart : nonceStart+int(nonceRlpLenS)+1]
				nonceRlpLenC := leafC[nonceStart] - 128
				nonceC := leafC[nonceStart : nonceStart+int(nonceRlpLenC)+1]

				balanceStartS := nonceStart + int(nonceRlpLenS) + 1
				balanceRlpLenS := leafS[balanceStartS] - 128
				balanceStartC := nonceStart + int(nonceRlpLenC) + 1
				balanceRlpLenC := leafC[balanceStartC] - 128

				getNonceBalanceRow := func(leaf, nonce []byte, balanceStart int, balanceRlpLen byte) []byte {
					nonceBalanceRow := make([]byte, rowLen)
					for i := 0; i < len(nonce); i++ {
						nonceBalanceRow[branchNodeRLPLen+i] = nonce[i]
					}
					nonceBalanceRow[0] = leaf[3+keyLen]
					nonceBalanceRow[1] = leaf[3+keyLen+1]
					nonceBalanceRow[branch2start] = leaf[3+keyLen+1+1]
					nonceBalanceRow[branch2start+1] = leaf[3+keyLen+1+1+1]
					balance := leaf[balanceStart : balanceStart+int(balanceRlpLen)+1]
					for i := 0; i < len(balance); i++ {
						nonceBalanceRow[branch2start+2+i] = balance[i] // c_advices
					}

					return nonceBalanceRow
				}
				
				nonceBalanceRowS := getNonceBalanceRow(leafS, nonceS, balanceStartS, balanceRlpLenS)
				nonceBalanceRowC := getNonceBalanceRow(leafC, nonceC, balanceStartC, balanceRlpLenC)

				getStorageCodeHashRow := func(leaf []byte, balanceStart int, balanceRlpLen byte) []byte {
					storageCodeHashRow := make([]byte, rowLen)
					storageStart := balanceStart + int(balanceRlpLen) + 1
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

				storageCodeHashRowS := getStorageCodeHashRow(leafS, balanceStartS, balanceRlpLenS)
				storageCodeHashRowC := getStorageCodeHashRow(leafC, balanceStartC, balanceRlpLenC)

				keyRow = append(keyRow, 6)
				nonceBalanceRowS = append(nonceBalanceRowS, 7)
				nonceBalanceRowC = append(nonceBalanceRowC, 8)
				storageCodeHashRowS = append(storageCodeHashRowS, 9)
				storageCodeHashRowC = append(storageCodeHashRowC, 11)

				rows = append(rows, keyRow)
				rows = append(rows, nonceBalanceRowS)
				rows = append(rows, nonceBalanceRowC)
				rows = append(rows, storageCodeHashRowS)
				rows = append(rows, storageCodeHashRowC)

				leafS = append(leafS, 5)
				leafC = append(leafC, 5)
				toBeHashed = append(toBeHashed, leafS)
				toBeHashed = append(toBeHashed, leafC)
			} else {
				leafRows, leafForHashing := prepareLeafRows(storageProof1[i], 2, false) // leaf s
				rows = append(rows, leafRows...)
				toBeHashed = append(toBeHashed, leafForHashing)
				leafRows, leafForHashing = prepareLeafRows(storageProof2[i], 3, false) // leaf s
				rows = append(rows, leafRows...)
				toBeHashed = append(toBeHashed, leafForHashing)
			}
		case 17:
			switchC16 := true // If not extension node, switchC16 = true.
			if extensionRowS != nil {
				keyLen := getExtensionNodeKeyLen(storageProof1[i-1])
				if keyLen == 1 {
					switchC16 = false
				} else {
					if storageProof1[i-1][2] != 0 { // If even, switch16 = true.
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

			bRows := prepareTwoBranchesWitness(storageProof1[i], storageProof2[i], key[keyIndex], branchC16, branchC1, false, false)
			keyIndex += 1

			// extension node rows
			if extensionRowS != nil {
				bRows = append(bRows, extensionRowS)
				bRows = append(bRows, extensionRowC)

				// Set isExtension to 1 in branch init.
				bRows[0][isExtensionPos] = 1

				keyLen := getExtensionNodeKeyLen(storageProof1[i-1])
				// TODO: remove old selectors below
				// Set whether key extension nibbles are of even or odd length.
				if keyLen == 1 {
					if branchC16 == 1 {
						bRows[0][isExtShortC16Pos] = 1
					} else {
						bRows[0][isExtShortC1Pos] = 1
					}
				} else {
					if storageProof1[i-1][2] == 0 {
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

	addBranch := func(branch1, branch2 []byte, modifiedIndex byte, isCPlaceholder bool, branchC16, branchC1 byte) {
		isBranchSPlaceholder := false
		isBranchCPlaceholder := false
		if isCPlaceholder {
			isBranchCPlaceholder = true
		} else {
			isBranchSPlaceholder = true
		}
		bRows := prepareTwoBranchesWitness(branch1, branch2, modifiedIndex, branchC16, branchC1, isBranchSPlaceholder, isBranchCPlaceholder)
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
		if leafKeyRow[0] != 248 {
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
		} else {
			keyLen := int(leafKeyRow[2] - 128)
			if leafKeyRow[3] == 32 {
				for i := 0; i < keyLen - 1; i++ { // -1 because the first byte doesn't have any nibbles
					b := leafKeyRow[4 + i]
					n1 := b / 16
					n2 := b - n1 * 16
					nibbles = append(nibbles, n1)
					nibbles = append(nibbles, n2)
				}
			} else {
				nibbles = append(nibbles,leafKeyRow[3] - 48)
				for i := 0; i < keyLen - 1; i++ { // -1 because the first byte has already been taken into account
					b := leafKeyRow[4 + i]
					n1 := b / 16
					n2 := b - n1 * 16
					nibbles = append(nibbles, n1)
					nibbles = append(nibbles, n2)
				}
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
				if branchC16 == 1 {
					branchC16 = 0
					branchC1 = 1
				} else {
					branchC16 = 1
					branchC1 = 0
				}
			} else {
				numNibbles, extensionRowS, extensionRowC :=
					prepareExtensionRows(extNibbles, extensionNodeInd, storageProof1[len1 - 3], storageProof1[len1 - 3])
				numberOfNibbles = int(numNibbles)
				extRows = append(extRows, extensionRowS)
				extRows = append(extRows, extensionRowC)

				// adding extension node for hashing:
				addForHashing(storageProof1[len1-3], &toBeHashed)

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

			addBranch(storageProof1[len1-2], storageProof1[len1-2], key[keyIndex + numberOfNibbles], true, branchC16, branchC1)
			rows = append(rows, extRows...)

			leafRows, leafForHashing := prepareLeafRows(storageProof1[len1-1], 2, false)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			leafRows, leafForHashing = prepareLeafRows(storageProof2[len2-1], 3, false)
			// We now get the first nibble of the leaf that was turned into branch.
			// This first nibble presents the position of the leaf once it moved
			// into the new branch.
			rows[len(rows)-branchRows-2][driftedPos] =
				getDriftedPosition(leafRows[0], numberOfNibbles) // -branchRows-2 lands into branch init

			if isExtension {
				rows[len(rows)-branchRows-2][isExtensionPos] = 1

				if numberOfNibbles == 1 {
					if branchC16 == 1 {
						rows[len(rows)-branchRows-2][isExtShortC16Pos] = 1
					} else {
						rows[len(rows)-branchRows-2][isExtShortC1Pos] = 1
					}
				} else {
					if numberOfNibbles % 2 == 0 {
						if branchC16 == 1 {
							rows[len(rows)-branchRows-2][isExtLongEvenC16Pos] = 1
						} else {
							rows[len(rows)-branchRows-2][isExtLongEvenC1Pos] = 1
						}
					} else {
						if branchC16 == 1 {
							rows[len(rows)-branchRows-2][isExtLongOddC16Pos] = 1
						} else {
							rows[len(rows)-branchRows-2][isExtLongOddC1Pos] = 1
						}
					}
				}
			}
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			// The branch contains hash of the neighbouring leaf, to be able
			// to check it, we add node RLP to toBeHashed
			addForHashing(neighbourNode, &toBeHashed)

			sLeafRows, _ := prepareLeafRows(neighbourNode, 15, false)
			// Neighbouring leaf - the leaf that used to be one level above,
			// but it was "drifted down" when additional branch was added.
			// Value (sLeafRows[1]) is not needed because we already have it
			// in the parallel proof.
			rows = append(rows, sLeafRows[0])
		} else {
			// We don't have a leaf in the shorter proof, but we will add it there
			// as a placeholder.
			leafRows, leafForHashing := prepareLeafRows(storageProof1[len1-1], 2, false)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			// No leaf means value is 0, set valueIsZero = true:
			leafRows, _ = prepareLeafRows(storageProof1[len1-1], 3, true)
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
				if branchC16 == 1 {
					branchC16 = 0
					branchC1 = 1
				} else {
					branchC16 = 1
					branchC1 = 0
				}
			} else { // diff is 2 when extension node is added
				numNibbles, extensionRowS, extensionRowC :=
					prepareExtensionRows(extNibbles, extensionNodeInd, storageProof2[len2 - 3], storageProof2[len2 - 3])
				numberOfNibbles = int(numNibbles)
				extRows = append(extRows, extensionRowS)
				extRows = append(extRows, extensionRowC)

				// adding extension node for hashing:
				addForHashing(storageProof2[len2-3], &toBeHashed)

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

			addBranch(storageProof2[len2-2], storageProof2[len2-2], key[keyIndex + numberOfNibbles], false, branchC16, branchC1)
			rows = append(rows, extRows...)

			// Note that this is not just reversed order compared to
			// len1 > len2 case - the first leaf is always from proof S
			// (the order of leaves at the end is always: first S, then C).

			leafRows, leafForHashing := prepareLeafRows(storageProof1[len1-1], 2, false)
			// We now get the first nibble of the leaf that was turned into branch.
			// This first nibble presents the position of the leaf once it moved
			// into the new branch.
			rows[len(rows)-branchRows][driftedPos] = getDriftedPosition(leafRows[0], numberOfNibbles) // -branchRows lands into branch init
			if isExtension {
				rows[len(rows)-branchRows][isExtensionPos] = 1

				// new selectors:
				if numberOfNibbles == 1 {
					if branchC16 == 1 {
						rows[len(rows)-branchRows][isExtShortC16Pos] = 1
					} else {
						rows[len(rows)-branchRows][isExtShortC1Pos] = 1
					}
				} else {
					if numberOfNibbles % 2 == 0 {
						if branchC16 == 1 {
							rows[len(rows)-branchRows][isExtLongEvenC16Pos] = 1
						} else {
							rows[len(rows)-branchRows][isExtLongEvenC1Pos] = 1
						}
					} else {
						if branchC16 == 1 {
							rows[len(rows)-branchRows][isExtLongOddC16Pos] = 1
						} else {
							rows[len(rows)-branchRows][isExtLongOddC1Pos] = 1
						}
					}
				}
			}
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			leafRows, leafForHashing = prepareLeafRows(storageProof2[len2-1], 3, false)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			// The branch contains hash of the neighbouring leaf, to be able
			// to check it, we add node RLP to toBeHashed
			addForHashing(neighbourNode, &toBeHashed)
			
			sLeafRows, _ := prepareLeafRows(neighbourNode, 15, false)
			// Neighbouring leaf - the leaf that used to be one level above,
			// but it was "drifted down" when additional branch was added.
			// Value (sLeafRows[1]) is not needed because we already have it
			// in the parallel proof.
			rows = append(rows, sLeafRows[0])
		} else {
			// No leaf means value is 0, set valueIsZero = true:
			leafRows, leafForHashing := prepareLeafRows(storageProof2[len2-1], 2, true)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			leafRows, _ = prepareLeafRows(storageProof2[len2-1], 3, false)
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

func GetProof(nodeUrl string, blockNum int, keys, values []common.Hash, addr []common.Address) [][]byte {
	blockNumberParent := big.NewInt(int64(blockNum))
	oracle.NodeUrl = nodeUrl
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)

	for i := 0; i < len(keys); i++ {
		// TODO: remove SetState (using it now just because this particular key might
		// not be set and we will obtain empty storageProof)
		v := common.BigToHash(big.NewInt(int64(17)))
		statedb.SetState(addr[i], keys[i], v)
		// TODO: enable GetState to get the preimages -
		// GetState calls GetCommittedState which calls PrefetchStorage to get the preimages
		// statedb.GetState(addr, keys[i])
	}

	return getProof(keys, values, addr, statedb)
}

func getProof(keys, values []common.Hash, addresses []common.Address, statedb *state.StateDB) [][]byte {
	statedb.IntermediateRoot(false)
	proof := [][]byte{}
	toBeHashed := [][]byte{}	
	var startRoot common.Hash
	var finalRoot common.Hash

	for i := 0; i < len(keys); i++ {
		kh := crypto.Keccak256(keys[i].Bytes())
		keyHashed := trie.KeybytesToHex(kh)

		addr := addresses[i]
		addrh := crypto.Keccak256(addr.Bytes())
		accountAddr := trie.KeybytesToHex(addrh)
		accountProof, _, _, err := statedb.GetProof(addr)
		check(err)
		storageProof, neighbourNode1, extNibbles1, err := statedb.GetStorageProof(addr, keys[i])
		check(err)

		sRoot := statedb.GetTrie().Hash()
		if i == 0 {
			startRoot = sRoot
		}

		statedb.SetState(addr, keys[i], values[i])
		statedb.IntermediateRoot(false)

		cRoot := statedb.GetTrie().Hash()
		if i == len(keys)-1 {
			finalRoot = cRoot
		}

		accountProof1, _, extNibblesAccount, err := statedb.GetProof(addr)
		check(err)

		storageProof1, neighbourNode2, extNibbles2, err := statedb.GetStorageProof(addr, keys[i])
		check(err)

		node := neighbourNode2
		extNibbles := extNibbles2
		if len(storageProof) > len(storageProof1) {
			// delete operation
			node = neighbourNode1
			extNibbles = extNibbles1
		}
		
		rowsState, toBeHashedAcc, _ :=
			prepareWitness(accountProof, accountProof1, extNibblesAccount, accountAddr, nil, true)
		rowsStorage, toBeHashedStorage, _ :=
			prepareWitness(storageProof, storageProof1, extNibbles, keyHashed, node, false)
		rowsState = append(rowsState, rowsStorage...)

		firstLevelBoundary := branchRows
		if rowsState[0][len(rowsState[0])-1] == 6 {
			// 6 presenting account leaf key S.
			// This happens when account leaf is without branch / extension node.
			firstLevelBoundary = accountLeafRows
		}
		counter := make([]byte, counterLen)
		binary.BigEndian.PutUint32(counter[0:4], uint32(i))
		for j := 0; j < len(rowsState); j++ {
			notFirstLevel := byte(1)
			if j < firstLevelBoundary {
				notFirstLevel = 0
			}
			r := insertMetaInfo(rowsState[j], sRoot.Bytes(), cRoot.Bytes(), addrh, counter, notFirstLevel, 1, 0, 0, 0)
			proof = append(proof, r)
		}
		insertPublicRoot(proof, startRoot.Bytes(), finalRoot.Bytes())

		// Put rows that just need to be hashed at the end, because circuit assign function
		// relies on index (for example when assigning s_keccak and c_keccak).
		toBeHashed = append(toBeHashed, toBeHashedAcc...)
		toBeHashed = append(toBeHashed, toBeHashedStorage...)
	}
	proof = append(proof, toBeHashed...)

	return proof
}

func GenerateProof(testName string, toBeModifiedKeys, toBeModifiedValues []common.Hash, addresses []common.Address, statedb *state.StateDB) {
	proof := getProof(toBeModifiedKeys, toBeModifiedValues, addresses, statedb)

	w := MatrixToJson(proof)
	fmt.Println(w)

	name := testName + ".json"
	f, err := os.Create("../generated_witnesses/" + name)
    check(err)
	defer f.Close()
	n3, err := f.WriteString(w)
    check(err)
    fmt.Printf("wrote %d bytes\n", n3)
}

func UpdateStateAndGenProof(testName string, keys, values []common.Hash, addresses []common.Address,
		toBeModifiedKeys, toBeModifiedValues []common.Hash, toBeModifiedAddresses []common.Address) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)

	// Set the state needed for the test:
	for i := 0; i < len(keys); i++ {
		statedb.SetState(addresses[i], keys[i], values[i])
	}
	
	proof := getProof(toBeModifiedKeys, toBeModifiedValues, toBeModifiedAddresses, statedb)

	w := MatrixToJson(proof)
	fmt.Println(w)

	name := testName + ".json"
	f, err := os.Create("../generated_witnesses/" + name)
    check(err)
	defer f.Close()
	n3, err := f.WriteString(w)
    check(err)
    fmt.Printf("wrote %d bytes\n", n3)
}