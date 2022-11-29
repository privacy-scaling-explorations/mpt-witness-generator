package witness

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
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

const accountLeafRows = 8
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
// short/long means having one or more than one nibbles
const isSExtLongerThan55Pos = 27
const isCExtLongerThan55Pos = 28
const isBranchSNonHashedPos = 29
const isBranchCNonHashedPos = 30
const isExtNodeSNonHashedPos = 31
const isExtNodeCNonHashedPos = 32

// nibbles_counter_pos = 33, set in the assign function.

const isInsertedExtNodeS = 34
const isInsertedExtNodeC = 35

/*
Info about row type (given as the last element of the row):
0: init branch (such a row contains RLP info about the branch node; key)
1: branch child
2: storage leaf s key
3: storage leaf c key
5: hash to be computed (for example branch RLP whose hash needs to be checked in the parent)
6: account leaf key S
4: account leaf key C
7: account leaf nonce balance S
8: account leaf nonce balance C
9: account leaf root codehash S
10: account leaf neighbouring leaf
11: account leaf root codehash C
13: storage leaf s value
14: storage leaf c value
15: neighbouring storage leaf (when leaf turned into branch)
16: extension node S
17: extension node C
18: non existing account
19: non existing storage
20: modified extension node S before modification
21: modified extension node C before modification
22: modified extension node S after modification
23: modified extension node C after modification
24: modified extension node before modification selectors
25: modified extension node after modification selectors
*/

type ModType int64

const (
	StorageMod ModType = iota
	NonceMod
	BalanceMod
	CodeHashMod
	CreateAccount
	DeleteAccount
	NonExistingAccount
	NonExistingStorage
)

type TrieModification struct {
	Type     ModType
	Key      common.Hash
	Value    common.Hash
	Address  common.Address
	Nonce    uint64
	Balance  *big.Int
	CodeHash []byte
}

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

// Equip proof with intermediate state roots, first level info, counter, address RLC,
// modification tag (whether it is storage / nonce / balance change).
func insertMetaInfo(stream, sRoot, cRoot, address, counter []byte, notFirstLevel, isStorageMod, isNonceMod, isBalanceMod, isCodeHashMod, isAccountDeleteMod, isNonExistingAccount, isNonExistingStorage byte) []byte {
	// The last byte (-1) in a row determines the type of the row.
	// Byte -2 determines whether it's the first level or not.
	// Bytes before that store intermediate final and end roots.
	l := len(stream)
	extendLen := 64 + 32 + 32 + counterLen + 1 + 7
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
	extended[l+extendLen-7] = isAccountDeleteMod
	extended[l+extendLen-8] = isNonExistingAccount
	extended[l+extendLen-9] = isNonExistingStorage

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

func prepareDriftedLeafPlaceholder(isAccount bool) [][]byte {
	driftedLeaf := make([]byte, rowLen)
	if isAccount {
		driftedLeaf = append(driftedLeaf, 10)
	} else {
		driftedLeaf = append(driftedLeaf, 15)
	}

	return [][]byte{driftedLeaf}
}

func addForHashing(toBeHashed []byte, toBeHashedCollection *[][]byte) {
	forHashing := make([]byte, len(toBeHashed))
	copy(forHashing, toBeHashed)
	forHashing = append(forHashing, 5) // 5 means it needs to be hashed
	*toBeHashedCollection = append(*toBeHashedCollection, forHashing)
}

func prepareEmptyExtensionRows(beforeModification, afterModification bool) [][]byte {
	ext_row1 := make([]byte, rowLen)
	ext_row2 := make([]byte, rowLen)
	if !beforeModification && !afterModification {
		ext_row1 = append(ext_row1, 16)
		ext_row2 = append(ext_row2, 17)
	} else if beforeModification {
		ext_row1 = append(ext_row1, 20)
		ext_row2 = append(ext_row2, 21)
	} else if afterModification {
		ext_row1 = append(ext_row1, 22)
		ext_row2 = append(ext_row2, 23)
	}

	return [][]byte{ext_row1, ext_row2}
}

func prepareExtensionRows(extNibbles[][]byte, extensionNodeInd int, proofEl1, proofEl2 []byte, beforeModification, afterModification bool) (byte, []byte, []byte) {
	var extensionRowS []byte
	var extensionRowC []byte

	extRows := prepareEmptyExtensionRows(beforeModification, afterModification)
	extensionRowS = extRows[0]
	extensionRowC = extRows[1]
	prepareExtensionRow(extensionRowS, proofEl1, true)
	prepareExtensionRow(extensionRowC, proofEl2, false)

	evenNumberOfNibbles := proofEl1[2] == 0
	keyLen := getExtensionNodeKeyLen(proofEl1)
	numberOfNibbles := getExtensionNumberOfNibbles(proofEl1)

	// We need nibbles as witness to compute key RLC, so we set them
	// into extensionRowC s_advices (we can do this because both extension
	// nodes have the same key, so we can have this info only in one).
	// There can be more up to 64 nibbles, but there is only 32 bytes
	// in extensionRowC s_advices. So we store every second nibble (having
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

func getExtensionLenStartKey(proofEl []byte) (int, int) {
	lenKey := 0
	startKey := 0
	// proofEl[1] <= 32 means only one nibble: the stored value is `16 + nibble`, note that if there are
	// at least two nibbles there will be `128 + number of bytes occupied by nibbles` in proofEl[1]
	if proofEl[1] <= 32 {
		lenKey = 1
		startKey = 1
	} else if proofEl[0] <= 247 {
		lenKey = int(proofEl[1] - 128)
		startKey = 2
	} else {
		lenKey = int(proofEl[2] - 128)
		startKey = 3
	}

	return lenKey, startKey
}

func getExtensionNodeKeyLen(proofEl []byte) byte {
	if proofEl[1] <= 32 {
		return 1
	} else if proofEl[0] <= 247 {
		return proofEl[1] - 128
	} else {
		return proofEl[2] - 128
	}
}

func getExtensionNumberOfNibbles(proofEl []byte) byte {
	evenNumberOfNibbles := proofEl[2] == 0
	numberOfNibbles := byte(0)
	keyLen := getExtensionNodeKeyLen(proofEl)
	if keyLen == 1 {
		numberOfNibbles = 1
	} else if keyLen > 1 && evenNumberOfNibbles {
		numberOfNibbles = (keyLen - 1) * 2
	} else if keyLen > 1 && !evenNumberOfNibbles {
		numberOfNibbles = (keyLen - 1) * 2 + 1
	}

	return numberOfNibbles
}

func getExtensionNodeNibbles(proofEl []byte) []byte {
	lenKey, startKey := getExtensionLenStartKey(proofEl)

	var nibbles []byte
	if proofEl[startKey] != 0 {
		nibbles = append(nibbles, proofEl[startKey] - 16)
	}
	for i := 0; i < lenKey - 1; i++ { // -1 because the first byte doesn't have any nibbles
		b := proofEl[startKey + 1 + i]
		n1 := b / 16
		n2 := b - n1 * 16
		nibbles = append(nibbles, n1)
		nibbles = append(nibbles, n2)
	}

	return nibbles
}

func prepareExtensionRow(witnessRow, proofEl []byte, setKey bool) {
	// storageProof[i]:
	// [228,130,0,149,160,114,253,150,133,18,192,156,19,241,162,51,210,24,1,151,16,48,7,177,42,60,49,34,230,254,242,79,132,165,90,75,249]
	// Note that the first element (228 in this case) can go much higher - for example, if there
	// are 40 nibbles, this would take 20 bytes which would make the first element 248.

	// If only one nibble in key:
	// [226,16,160,172,105,12...
	// Could also be non-hashed branch:
	// [223,16,221,198,132,32,0,0,0,1,198,132,32,0,0,0,1,128,128,128,128,128,128,128,128,128,128,128,128,128,128,128]

	// Extension node with non-hashed branch:
	// List contains up to 55 bytes (192 + 55)
	// [247,160,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,213,128,194,32,1,128,194,32,1,128,128,128,128,128,128,128,128,128,128,128,128,128]

	// List contains more than 55 bytes
	// [248,58,159,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,217,128,196,130,32,0,1,128,196,130,32,0,1,128,128,128,128,128,128,128,128,128,128,128,128,128]

	// Note that the extension node can be much shorter than the one above - in case when
	// there are less nibbles, so we cannot say that 226 appears as the first byte only
	// when there are hashed nodes in the branch and there is only one nibble.
	// Branch with two non-hashed nodes (that's the shortest possible branch):
	// [217,128,196,130,32,0,1,128,196,130,32,0,1,128,128,128,128,128,128,128,128,128,128,128,128,128]
	// Note: branch contains at least 26 bytes. 192 + 26 = 218

	/*
	If proofEl[0] <= 247 (length at most 55, so proofEl[1] doesn't specify the length of the whole
		remaining stream, only of the next substream)
	  If proofEl[1] <= 128:
	    There is only 1 byte for nibbles (keyLen = 1) and this is proofEl[1].
	  Else:
	    Nibbles are stored in more than 1 byte, proofEl[1] specifies the length of bytes.
	Else:
	  proofEl[1] contains the length of the remaining stream.
	  proofEl[2] specifies the length of the bytes (for storing nibbles).
	  Note that we can't have only one nibble in this case.
	*/

	if setKey {
		witnessRow[0] = proofEl[0]
		witnessRow[1] = proofEl[1]
	}

	lenKey, startKey := getExtensionLenStartKey(proofEl)
	if startKey == 3 {
		witnessRow[2] = proofEl[2]
	}

	if setKey {
		for j := 0; j < lenKey; j++ {
			witnessRow[startKey+j] = proofEl[startKey+j]
		}
	}

	encodedNodeLen := proofEl[startKey+lenKey]
	nodeLen := byte(0)
	start := branch2start+branchNodeRLPLen-1
	if encodedNodeLen > 192 {
		// we have a list, that means a non-hashed node
		nodeLen = encodedNodeLen - 192
		start = start + 1 // we put all bytes (also length) at the positions where hash is put to be compatible with hashed-node cases
	} else if encodedNodeLen == 160 {
		// hashed-node
		nodeLen = encodedNodeLen - 128
	}
	witnessRow[start] = encodedNodeLen
	for j := 0; j < int(nodeLen); j++ {
		witnessRow[start+1+j] = proofEl[startKey+lenKey+1+j]
	}
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

		getNonceBalanceRow := func(leaf, nonce []byte, keyLen, balanceStart int, balanceRlpLen byte) []byte {
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
		
		nonceBalanceRowS = getNonceBalanceRow(leafS, nonceS, keyLenS, balanceStartS, balanceRlpLenS)
		nonceBalanceRowC = getNonceBalanceRow(leafC, nonceC, keyLenC, balanceStartC, balanceRlpLenC)

		getStorageCodeHashRow := func(leaf []byte, storageStart int) []byte {
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

func prepareTwoBranchesWitness(branch1, branch2 []byte, key, branchC16, branchC1 byte, isBranchSPlaceholder, isBranchCPlaceholder bool) [][]byte {
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
			rows[i][rowLen-1] = 0
		} else {
			rows[i][rowLen-1] = 1
		}
	}

	prepareBranchWitness(rows, branch1, 0, branch1RLPOffset)
	prepareBranchWitness(rows, branch2, 2+32, branch2RLPOffset)

	return rows
}

func prepareWitness(statedb *state.StateDB, addr common.Address, proof1, proof2, extNibbles [][]byte, key []byte, neighbourNode []byte,
		isAccountProof, nonExistingAccountProof, nonExistingStorageProof bool) ([][]byte, [][]byte, bool) {
	rows := make([][]byte, 0)
	toBeHashed := make([][]byte, 0)

	minLen := len(proof1)
	if len(proof2) < minLen {
		minLen = len(proof2)
	}

	keyIndex := 0
	len1 := len(proof1)
	len2 := len(proof2)

	// When value in the trie is updated, both proofs are of the same length.
	// When value is added and there is no node which needs to be changed
	// into branch, one proof has a leaf and one doesn't have it.

	// Check if the last proof element in the shorter proof is a leaf -
	// if it is, then there is an additional branch.
	additionalBranchNeeded := func(proofEl []byte) bool {
		elems, _, err := rlp.SplitList(proofEl)
		check(err)
		c, _ := rlp.CountValues(elems)
		return c == 2
	}

	additionalBranch := false
	if len1 < len2 && len1 > 0 { // len = 0 when trie trie is empty
		additionalBranch = additionalBranchNeeded(proof1[len1-1])
	} else if len2 < len1 && len2 > 0 {
		additionalBranch = additionalBranchNeeded(proof2[len2-1])
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
		elems, _, err := rlp.SplitList(proof1[i])
		if err != nil {
			fmt.Println("decode error", err)
		}

		switch c, _ := rlp.CountValues(elems); c {
		case 2:
			if i != len1 - 1 { // extension node
				var numberOfNibbles byte
				numberOfNibbles, extensionRowS, extensionRowC = prepareExtensionRows(extNibbles, extensionNodeInd, proof1[i], proof2[i], false, false)
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
		case 17:
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

			bRows := prepareTwoBranchesWitness(proof1[i], proof2[i], key[keyIndex], branchC16, branchC1, false, false)
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
		default:
			fmt.Println("invalid number of list elements")
		}
	}

	addBranch := func(branch1, branch2 []byte, modifiedIndex byte, isCPlaceholder bool, branchC16, branchC1 byte, insertedExtension bool) {
		isBranchSPlaceholder := false
		isBranchCPlaceholder := false
		if !insertedExtension {
			if isCPlaceholder {
				isBranchCPlaceholder = true
			} else {
				isBranchSPlaceholder = true
			}
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
			if leafKeyRow[2] != 32 {
				nibbles = append(nibbles,leafKeyRow[2] - 48)
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
			if leafKeyRow[3] != 32 {
				nibbles = append(nibbles,leafKeyRow[3] - 48)
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

	setExtNodeSelectors := func(row, proofEl []byte, numberOfNibbles int, branchC16 byte) {
		row[isExtensionPos] = 1
		if len(proofEl) > 56 { // 56 because there is 1 byte for length
			// isCExtLongerThan55 doesn't need to be set here
			row[isSExtLongerThan55Pos] = 1
		}

		if len(proofEl) < 32 {
			// isExtNodeSNonHashed doesn't need to be set here
			row[isExtNodeSNonHashedPos] = 1
		}

		if numberOfNibbles == 1 {
			if branchC16 == 1 {
				row[isExtShortC16Pos] = 1
			} else {
				row[isExtShortC1Pos] = 1
			}
		} else {
			if numberOfNibbles % 2 == 0 {
				if branchC16 == 1 {
					row[isExtLongEvenC16Pos] = 1
				} else {
					row[isExtLongEvenC1Pos] = 1
				}
			} else {
				if branchC16 == 1 {
					row[isExtLongOddC16Pos] = 1
				} else {
					row[isExtLongOddC1Pos] = 1
				}
			}
		}
	}

	addPlaceholder := func() {
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
						prepareExtensionRows(extNibbles, extensionNodeInd, proof1[len1 - 3], proof1[len1 - 3], false, false)
				} else {
					numNibbles, extensionRowS, extensionRowC =
						prepareExtensionRows(extNibbles, extensionNodeInd, proof2[len2 - 3], proof2[len2 - 3], false, false)
				}
				numberOfNibbles = int(numNibbles)
				extRows = append(extRows, extensionRowS)
				extRows = append(extRows, extensionRowC)

				// adding extension node for hashing:
				if len1 > len2 {
					addForHashing(proof1[len1-3], &toBeHashed)
				} else {
					addForHashing(proof2[len2-3], &toBeHashed)
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
			var oldExtNode []byte
			if len1 > len2 {
				oldExtNode = proof2[len2 - 1]
			} else {
				oldExtNode = proof1[len1 - 1]
			}
			rlp_elems, _, err := rlp.SplitList(oldExtNode)
			check(err)
			c, _ := rlp.CountValues(rlp_elems)
			isInsertedExtNode := c == 2

			if len1 > len2 {
				addBranch(proof1[len1-2], proof1[len1-2], key[keyIndex + numberOfNibbles], true, branchC16, branchC1, isInsertedExtNode)
			} else {
				addBranch(proof2[len2-2], proof2[len2-2], key[keyIndex + numberOfNibbles], false, branchC16, branchC1, isInsertedExtNode)
			}
			rows = append(rows, extRows...)

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
				toBeHashed = append(toBeHashed, leafForHashing...)
				// All account leaf rows already generated above, for storage leaf only S is generated above.
				if isAccountProof {
					// TODO: isInsertedExtNode
					rows = append(rows, leafRows...)
				} else {
					if !isInsertedExtNode {
						rows = append(rows, leafRows...)
						var leafForHashingC []byte
						leafRows, leafForHashingC = prepareStorageLeafRows(proof2[len2-1], 3, false)
						rows = append(rows, leafRows...)
						toBeHashed = append(toBeHashed, leafForHashingC)
					} else {
						// We do not have leaf in one of the proofs when extension node is inserted.
						// We can use the same leaf for S and C because we have the same extension
						// node and branch in the rows above (inserted extension node rows are below
						// leaf rows). We just need to make sure the row selectors are the right one.
						rows = append(rows, leafRows...)

						l := len(leafRows[0])
						leafKey := make([]byte, l)
						copy(leafKey, leafRows[0])
						leafKey[l - 1] = 3
						rows = append(rows, leafKey)

						l = len(leafRows[1])
						leafVal := make([]byte, l)
						copy(leafVal, leafRows[1])
						leafVal[l - 1] = 14
						rows = append(rows, leafVal)
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
				rows[len(rows)-branchRows-offset][driftedPos] =
					getDriftedPosition(leafRow, numberOfNibbles) // -branchRows-offset lands into branch init

				if isInsertedExtNode {
					rows[len(rows)-branchRows-offset][isInsertedExtNodeS] = 1
				}

				if isExtension {
					setExtNodeSelectors(rows[len(rows)-branchRows-offset], proof1[len1-3], numberOfNibbles, branchC16)
				}
			} else {
				// We now get the first nibble of the leaf that was turned into branch.
				// This first nibble presents the position of the leaf once it moved
				// into the new branch.
				rows[len(rows)-branchRows][driftedPos] = getDriftedPosition(leafRows[0], numberOfNibbles) // -branchRows lands into branch init

				if isInsertedExtNode {
					rows[len(rows)-branchRows][isInsertedExtNodeC] = 1
				}

				if isExtension {
					setExtNodeSelectors(rows[len(rows)-branchRows], proof2[len2-3], numberOfNibbles, branchC16)	
				}

				toBeHashed = append(toBeHashed, leafForHashing...)
				// All account leaf rows already generated above, for storage leaf only S is generated above.
				if isAccountProof {
					rows = append(rows, leafRows...)
				} else {
					if !isInsertedExtNode {
						rows = append(rows, leafRows...)
						var leafForHashingC []byte
						leafRows, leafForHashingC = prepareStorageLeafRows(proof2[len2-1], 3, false)
						rows = append(rows, leafRows...)
						toBeHashed = append(toBeHashed, leafForHashingC)
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
						rows = append(rows, leafKey)

						l = len(leafRows[1])
						leafVal := make([]byte, l)
						copy(leafVal, leafRows[1])
						leafVal[l - 1] = 13
						rows = append(rows, leafVal)

						rows = append(rows, leafRows...)
						toBeHashed = append(toBeHashed, leafForHashingC)
					}
				}
			}

			// The branch contains hash of the neighbouring leaf, to be able
			// to check it, we add node RLP to toBeHashed
			addForHashing(neighbourNode, &toBeHashed)

			// Neighbouring leaf - the leaf that used to be one level above,
			// but it was "drifted down" when additional branch was added.
			// Only key is needed because we already have the value (it doesn't change)
			// in the parallel proof.
			if isAccountProof {
				if !isInsertedExtNode {
					h := append(neighbourNode, 5)
					toBeHashed = append(toBeHashed, h)

					keyRowS, _, _, _, _, _, _ :=
						prepareAccountLeafRows(neighbourNode, neighbourNode, key, nonExistingAccountProof, false)
					keyRowS = append(keyRowS, 10)
					rows = append(rows, keyRowS)
				} else {
					pRows := prepareDriftedLeafPlaceholder(isAccountProof)
					rows = append(rows, pRows...)	
				}
			} else {
				if !isInsertedExtNode {
					sLeafRows, _ := prepareStorageLeafRows(neighbourNode, 15, false)
					rows = append(rows, sLeafRows[0])
				} else {
					pRows := prepareDriftedLeafPlaceholder(isAccountProof)
					rows = append(rows, pRows...)	
				}
				
				// For non existing proof, S and C proofs are the same
				nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
				rows = append(rows, nonExistingStorageRow)
			}

			if isInsertedExtNode {
				numberOfNibbles0, extensionRowS, extensionRowC :=
					prepareExtensionRows(extNibbles, extensionNodeInd, oldExtNode, oldExtNode, true, false)

				extNodeSelectors := make([]byte, rowLen)
				setExtNodeSelectors(extNodeSelectors, oldExtNode, int(numberOfNibbles0), branchC16)
				extNodeSelectors = append(extNodeSelectors, 24)

				var extRows [][]byte
				// We need to prove the old extension node is in S proof (when ext. node inserted).
				extRows = append(extRows, extNodeSelectors)
				extRows = append(extRows, extensionRowS)
				extRows = append(extRows, extensionRowC)

				rows = append(rows, extRows...)
				addForHashing(oldExtNode, &toBeHashed)

				// Get nibbles of the extension node that gets shortened because of the newly insertd
				// extension node:
				oldNibbles := getExtensionNodeNibbles(oldExtNode)

				ind := byte(keyIndex) + byte(numberOfNibbles) // where the old and new extension nodes start to be different
				// diffNibble := oldNibbles[ind]
				oldExtNodeKey := make([]byte, len(key))
				copy(oldExtNodeKey, key)
				// We would like to retrieve the shortened extension node from the trie via GetProof or
				// GetStorageProof (depending whether it is an account proof or storage proof),
				// the key where we find its underlying branch is `oldExtNodeKey`.
				for j := ind; int(j) < keyIndex + len(oldNibbles); j++ {
					// keyIndex is where the nibbles of the old and new extension node start
					oldExtNodeKey[j] = oldNibbles[j - byte(keyIndex)]	
				}
	
				k := trie.HexToKeybytes(oldExtNodeKey)
				key := common.BytesToHash(k)
				var proof [][]byte
				if isAccountProof {
					proof, _, _, err = statedb.GetProof(addr)

				} else {
					proof, _, _, err = statedb.GetStorageProof(addr, key)
				}
				check(err)
				var oldExtNodeInNewTrie []byte
				elems, _, err := rlp.SplitList(proof[len(proof) - 1])
				check(err)
				c, _ := rlp.CountValues(elems)

				// Note that `oldExtNodeKey` has nibbles properly set only up to the end of nibbles,
				// this is enough to get the old extension node by `GetProof` or `GetStorageProof` -
				// we will get its underlying branch, but sometimes also the leaf in a branch if
				// the nibble will correspond to the leaf (we left the nibbles from
				// `keyIndex + len(oldNibbles)` the same as the nibbles in the new extension node).

				if c == 17 { // last element in a proof is a branch
					oldExtNodeInNewTrie = proof[len(proof) - 2]
				} else { // last element in a proof is a leaf
					oldExtNodeInNewTrie = proof[len(proof) - 3]
				}

				// Get the nibbles of the shortened extension node:
				nibbles := getExtensionNodeNibbles(oldExtNodeInNewTrie)

				// Enable `prepareExtensionRows` call:
				extNibbles = append(extNibbles, nibbles)

				numberOfNibbles1, extensionRowS1, extensionRowC1 :=
					prepareExtensionRows(extNibbles, extensionNodeInd + 1, oldExtNodeInNewTrie, oldExtNodeInNewTrie, false, true)

				extNodeSelectors1 := make([]byte, rowLen)
				setExtNodeSelectors(extNodeSelectors1, oldExtNodeInNewTrie, int(numberOfNibbles1), branchC16)
				extNodeSelectors1 = append(extNodeSelectors1, 25)

				// The shortened extension node is needed as a witness to be able to check in a circuit
				// that the shortened extension node and newly added leaf (that causes newly inserted
				// extension node) are the only nodes in the newly inserted extension node.
				rows = append(rows, extNodeSelectors1)
				rows = append(rows, extensionRowS1)
				rows = append(rows, extensionRowC1)
				addForHashing(oldExtNodeInNewTrie, &toBeHashed)
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
				
				rows = append(rows, keyRowS)
				rows = append(rows, keyRowC)
				rows = append(rows, nonExistingAccountRow) // not really needed
				rows = append(rows, nonceBalanceRowS)
				rows = append(rows, nonceBalanceRowC)
				rows = append(rows, storageCodeHashRowS)
				rows = append(rows, storageCodeHashRowC)

				pRows := prepareDriftedLeafPlaceholder(true)
				rows = append(rows, pRows...)

				leafS = append(leafS, 5)
				leafC = append(leafC, 5)
				toBeHashed = append(toBeHashed, leafS)
				toBeHashed = append(toBeHashed, leafC)
			} else {
				var leafRows [][]byte
				var leafForHashing []byte
				if len1 > len2 {
					leafRows, leafForHashing = prepareStorageLeafRows(proof1[len1-1], 2, false)
				} else {
					leafRows, leafForHashing = prepareStorageLeafRows(proof2[len2-1], 2, true)
				}
				
				rows = append(rows, leafRows...)
				toBeHashed = append(toBeHashed, leafForHashing)

				// No leaf means value is 0, set valueIsZero = true:
				if len1 > len2 {
					leafRows, _ = prepareStorageLeafRows(proof1[len1-1], 3, true)
				} else {
					leafRows, _ = prepareStorageLeafRows(proof2[len2-1], 3, false)
				}
				rows = append(rows, leafRows...)

				pRows := prepareDriftedLeafPlaceholder(isAccountProof)
				rows = append(rows, pRows...)

				// For non existing proof, S and C proofs are the same
				nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
				rows = append(rows, nonExistingStorageRow)	
			}
		}
	}
	
	if len1 != len2 {
		addPlaceholder()
	} else {
		// Let's always use C proof for non-existing proof.
		lastRLP := proof2[len(proof2)-1];
		elems, _, err := rlp.SplitList(lastRLP)
		check(err)
		c, _ := rlp.CountValues(elems)
		// Account proof has drifted leaf as the last row, storage proof has non-existing-storage row
		// as the last row.
		if c == 17 {
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

func GetParallelProofs(nodeUrl string, blockNum int, trieModifications []TrieModification) [][]byte {
	blockNumberParent := big.NewInt(int64(blockNum))
	oracle.NodeUrl = nodeUrl
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)

	for i := 0; i < len(trieModifications); i++ {
		// TODO: remove SetState (using it now just because this particular key might
		// not be set and we will obtain empty storageProof)
		v := common.BigToHash(big.NewInt(int64(17)))
		statedb.SetState(trieModifications[i].Address, trieModifications[i].Key, v)
		// TODO: enable GetState to get the preimages -
		// GetState calls GetCommittedState which calls PrefetchStorage to get the preimages
		// statedb.GetState(addr, keys[i])
	}

	return getParallelProofs(trieModifications, statedb, 0)
}

func prepareProof(ind int, newProof [][]byte, addrh []byte, sRoot, cRoot, startRoot, finalRoot common.Hash, mType ModType) [][]byte {
	firstLevelBoundary := branchRows
	if newProof[0][len(newProof[0])-1] == 6 {
		// 6 presents account leaf key S.
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
		r := insertMetaInfo(newProof[j], sRoot.Bytes(), cRoot.Bytes(), addrh, counter, notFirstLevel, 
			isStorageMod, isNonceMod, isBalanceMod, isCodeHashMod, isAccountDeleteMod, isNonExistingAccount,
			isNonExistingStorage)
		proof = append(proof, r)
	}
	insertPublicRoot(newProof, startRoot.Bytes(), finalRoot.Bytes())

	return proof
}

// For generating special tests - it moves account from second level to first level (key stored in a leaf
// gets longer).
func moveAccountFromSecondToFirstLevel(firstNibble byte, account []byte) []byte {
	newAccount := make([]byte, len(account)+1) 
	newAccount[0] = account[0]
	newAccount[1] = account[1] + 1
	newAccount[2] = 161
	newAccount[3] = 32	
	// The following code relies on the account being in the second level (and not being
	// after an extension node).
	newAccount[4] = firstNibble * 16 + account[3] - 48
	for i := 0; i < 31; i++ {
		newAccount[5+i] = account[4+i]
	}
	for i := 0; i < int(account[1] - 33); i++ {
		newAccount[4+32+i] = account[35+i]
	}

	return newAccount
}

// For generating special tests - it moves account from third level to second level (key stored in a leaf
// gets longer).
func moveAccountFromThirdToSecondLevel(addrh []byte, account []byte) []byte {
	// account = [248, 105, 160, 32, 77, 78,...]
	newAccount := make([]byte, len(account)) 
	copy(newAccount, account)
	// The following code relies on the account being in the third level (and not being
	// after an extension node).
	posInBranch := addrh[0] % 16
	newAccount[3] = 48 + posInBranch

	return newAccount
}

func prepareAccountProof(i int, tMod TrieModification, tModsLen int, statedb *state.StateDB, specialTest byte) ([][]byte, [][]byte) {
	statedb.IntermediateRoot(false)

	addr := tMod.Address
	addrh := crypto.Keccak256(addr.Bytes())
	accountAddr := trie.KeybytesToHex(addrh)

	// This needs to called before oracle.PrefetchAccount, otherwise oracle.PrefetchAccount
	// will cache the proof and won't return it.
	// Calling oracle.PrefetchAccount after statedb.SetStateObjectIfExists is needed only
	// for cases when statedb.loadRemoteAccountsIntoStateObjects = false.
	statedb.SetStateObjectIfExists(tMod.Address)

	oracle.PrefetchAccount(statedb.Db.BlockNumber, tMod.Address, nil)
	accountProof, aNeighbourNode1, aExtNibbles1, err := statedb.GetProof(addr)
	check(err)

	var startRoot common.Hash
	var finalRoot common.Hash

	sRoot := statedb.GetTrie().Hash()
	if i == 0 {
		startRoot = sRoot
	}

	if tMod.Type == NonceMod {
		statedb.SetNonce(addr, tMod.Nonce)
	} else if tMod.Type == BalanceMod {
		statedb.SetBalance(addr, tMod.Balance)
	} else if tMod.Type == CodeHashMod {
		statedb.SetCode(addr, tMod.CodeHash)
	} else if tMod.Type == CreateAccount {
		statedb.CreateAccount(tMod.Address)
	} else if tMod.Type == DeleteAccount {
		statedb.DeleteAccount(tMod.Address)
	}
	// No statedb change in case of NonExistingAccount

	statedb.IntermediateRoot(false)

	cRoot := statedb.GetTrie().Hash()
	if i == tModsLen-1 {
		finalRoot = cRoot
	}

	accountProof1, aNeighbourNode2, aExtNibbles2, err := statedb.GetProof(addr)
	check(err)

	if tMod.Type == NonExistingAccount && len(accountProof) == 0 {
		// If there is only one account in the state trie and we want to prove for some 
		// other account that it doesn't exist.
		// We get the root node (the only account) and put it as the only element of the proof,
		// it will act as a "wrong" leaf.
		account, err := statedb.GetTrieRootElement()
		check(err)
		accountProof = make([][]byte, 1)
		accountProof[0] = account
		accountProof1 = make([][]byte, 1)
		accountProof1[0] = account
	}

	if (specialTest == 1) {
		account := accountProof1[len(accountProof1)-1]
		if len(accountProof1) != 2 {
			panic("account should be in the second level (one branch above it)")
		}
		firstNibble := addrh[0] / 16
		newAccount := moveAccountFromSecondToFirstLevel(firstNibble, account)

		newAccount1 := make([]byte, len(account)+1) 
		copy(newAccount1, newAccount)

		// change nonce:
		newAccount1[3 + 33 + 4] = 1
		
		accountProof = make([][]byte, 1)
		accountProof[0] = newAccount
		accountProof1 = make([][]byte, 1)
		accountProof1[0] = newAccount1
	
		hasher := trie.NewHasher(false)
		sRoot = common.BytesToHash(hasher.HashData(newAccount))
		cRoot = common.BytesToHash(hasher.HashData(newAccount1))
	} else if specialTest == 3 {
		if len(accountProof) != 2 && len(accountProof1) != 3 {
			panic("account should be in the second level (one branch above it)")
		}
		accountS := accountProof[len(accountProof)-1]
		account1Pos := addrh[0] / 16
		// driftedPos := ((addrh[0] / 16) + 1) % 16 // something else than the first nibble of addrh
		driftedPos := byte(0) // TODO: remove hardcoding
		// addresses of both account now differ only in the first nibble (this is not needed,
		// it is just in this construction)
		newAccount := moveAccountFromSecondToFirstLevel(driftedPos, accountS)

		hasher := trie.NewHasher(false)

		firstNibble := accountProof[1][3] - 48
		// [248, 81, 128, 128, ...
		branch := accountProof1[len(accountProof1)-2]
		branch1 := make([]byte, len(branch))
		for i := 0; i < len(branch1); i++ {
			branch1[i] = 128
		}
		branch1[0] = branch[0]
		branch1[1] = branch[1]
		
		// drifted leaf (aNeighbourNode2) has one nibble more after moved one level up, we need to recompute the hash
		fmt.Println(driftedPos)
		aNeighbourNode2[3] = 48 + firstNibble
		driftedLeafHash := common.BytesToHash(hasher.HashData(aNeighbourNode2))
		// branch is now one level higher, both leaves are at different positions now
		// (one nibble to the left)

		branch1[2 + int(driftedPos)] = 160
		for i := 0; i < 32; i++ {
			branch1[2 + int(driftedPos) + 1 + i] = driftedLeafHash[i]
		}

		accountC3 := accountProof1[len(accountProof1)-1]
		newAccountC2 := moveAccountFromThirdToSecondLevel(addrh, accountC3)

		driftedLeafHash2 := common.BytesToHash(hasher.HashData(newAccountC2))
		branch1[2 + 32 + int(account1Pos)] = 160
		for i := 0; i < 32; i++ {
			branch1[2 + 32 + int(account1Pos) + 1 + i] = driftedLeafHash2[i]
		}
		
		// Let us have placeholder branch in the first level
		accountProof = make([][]byte, 1)
		accountProof[0] = newAccount
		accountProof1 = make([][]byte, 2)
		accountProof1[0] = branch1
		accountProof1[1] = newAccountC2

		sRoot = common.BytesToHash(hasher.HashData(accountProof[0]))
		cRoot = common.BytesToHash(hasher.HashData(accountProof1[0]))
	} else if (specialTest == 4) {
		// This test simulates having only one account in the state trie:
		account := []byte{248,106,161,32,252,237,52,8,133,130,180,167,143,97,28,115,102,25,94,62,148,249,8,6,55,244,16,75,187,208,208,127,251,120,61,73,184,70,248,68,128,128,160,86,232,31,23,27,204,85,166,255,131,69,230,146,192,248,110,91, 72,224,27,153,108,173,192,1,98,47,181,227,99,180,33,160,197,210,70,1,134,247,35,60,146,126,125,178,220,199,3,192,229,0,182,83,202,130,39,59,123,250,216,4,93,133,164,112}

		// Note: the requested address (for which the account doesn't exist) should have
		// a different address as the only one in the trie.
				
		accountProof = make([][]byte, 1)
		accountProof[0] = account
		accountProof1 = make([][]byte, 1)
		accountProof1[0] = account
	
		hasher := trie.NewHasher(false)
		sRoot = common.BytesToHash(hasher.HashData(accountProof[0]))
		cRoot = common.BytesToHash(hasher.HashData(accountProof1[0]))
	} else if (specialTest == 5) {
		ext := []byte{226, 24, 160, 194, 200, 39, 82, 205, 97, 69, 91, 92, 98, 218, 180, 101, 42, 171, 150, 75, 251, 147, 154, 59, 215, 26, 164, 201, 90, 199, 185, 190, 205, 167, 64}
		branch := []byte{248, 81, 128, 128, 128, 160, 53, 8, 52, 235, 77, 44, 138, 235, 20, 250, 15, 188, 176, 83, 178, 108, 212, 224, 40, 146, 117, 31, 154, 215, 103, 179, 234, 32, 168, 86, 167, 44, 128, 128, 128, 128, 128, 160, 174, 121, 120, 114, 157, 43, 164, 140, 103, 235, 28, 242, 186, 33, 76, 152, 157, 197, 109, 149, 229, 229, 22, 189, 233, 207, 92, 195, 82, 121, 240, 3, 128, 128, 128, 128, 128, 128, 128}
		// The original proof returns `ext` and `branch` in 2. and 3. level. We move them to 1. and 2. level.

		fmt.Println(ext)
		fmt.Println(branch)

		newAddrBytes := make([]byte, 32)
		newAddrNibbles := make([]byte, 65)
		newAddrNibbles[64] = accountAddr[16]
		for i := 0; i < 63; i++ {
			newAddrNibbles[i] = accountAddr[i+1]
		}
		newAddrNibbles[63] = accountAddr[0]

		for i := 0; i < 32; i++ {
			newAddrBytes[i] = newAddrNibbles[2*i] * 16 + newAddrNibbles[2*i + 1]
		}

		// We need to fix leaf key (adding last nibble):
		// Original leaf:
		// leaf := []byte{248, 104, 159, 59, 114, 3, 66, 104, 61, 61, 61, 175, 101, 56, 194, 213, 150, 208, 62, 118, 28, 175, 138, 112, 119, 76, 88, 109, 21, 102, 195, 8, 18, 185, 184, 70, 248, 68, 128, 128, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112}
		leaf := []byte{248, 105, 160, 32, 59, 114, 3, 66, 104, 61, 61, 61, 175, 101, 56, 194, 213, 150, 208, 62, 118, 28, 175, 138, 112, 119, 76, 88, 109, 21, 102, 195, 8, 18, 185, 184, 70, 248, 68, 128, 128, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112}
		for i := 0; i < 31; i++ {
			leaf[4 + i] = newAddrBytes[i + 1]
		}

		hasher := trie.NewHasher(false)
		// Update leaf hash in branch
		newLeafHash := common.BytesToHash(hasher.HashData(leaf))
		branch[2 + int(newAddrNibbles[1])] = 160
		for i := 0; i < 32; i++ {
			branch[2 + int(newAddrNibbles[1]) + 1 + i] = newLeafHash[i]
		}

		// Update branch hash in extension node
		newBranchHash := common.BytesToHash(hasher.HashData(branch))
		for i := 0; i < 32; i++ {
			ext[3 + i] = newBranchHash[i]
		}

		accountAddr = newAddrNibbles
		addrh = newAddrBytes

		accountProof = make([][]byte, 3)
		accountProof[0] = ext
		accountProof[1] = branch
		accountProof[2] = leaf
		accountProof1 = accountProof

		sRoot = common.BytesToHash(hasher.HashData(accountProof[0]))
		cRoot = common.BytesToHash(hasher.HashData(accountProof1[0]))
	}

	aNode := aNeighbourNode2
	aExtNibbles := aExtNibbles2
	if len(accountProof) > len(accountProof1) {
		// delete operation
		aNode = aNeighbourNode1
		aExtNibbles = aExtNibbles1
	}
	
	rowsState, toBeHashedAcc, _ :=
		prepareWitness(statedb, addr, accountProof, accountProof1, aExtNibbles, accountAddr, aNode, true, tMod.Type == NonExistingAccount, false)

	proof := prepareProof(i, rowsState, addrh, sRoot, cRoot, startRoot, finalRoot, tMod.Type)

	return proof, toBeHashedAcc
}

func getParallelProofs(trieModifications []TrieModification, statedb *state.StateDB, specialTest byte) [][]byte {
	statedb.IntermediateRoot(false)
	allProofs := [][]byte{}
	toBeHashed := [][]byte{}	
	var startRoot common.Hash
	var finalRoot common.Hash

	for i := 0; i < len(trieModifications); i++ {
		tMod := trieModifications[i]
		if tMod.Type == StorageMod || tMod.Type == NonExistingStorage {
			kh := crypto.Keccak256(tMod.Key.Bytes())
			if oracle.PreventHashingInSecureTrie {
				kh = tMod.Key.Bytes()
			}
			keyHashed := trie.KeybytesToHex(kh)

			addr := tMod.Address
			addrh := crypto.Keccak256(addr.Bytes())
			accountAddr := trie.KeybytesToHex(addrh)

			oracle.PrefetchAccount(statedb.Db.BlockNumber, tMod.Address, nil)
			// oracle.PrefetchStorage(statedb.Db.BlockNumber, addr, tMod.Key, nil)

			if specialTest == 1 {
				statedb.CreateAccount(addr)
			}

			accountProof, aNeighbourNode1, aExtNibbles1, err := statedb.GetProof(addr)
			check(err)
			storageProof, neighbourNode1, extNibbles1, err := statedb.GetStorageProof(addr, tMod.Key)
			check(err)

			sRoot := statedb.GetTrie().Hash()
			if i == 0 {
				startRoot = sRoot
			}

			if tMod.Type == StorageMod {
				statedb.SetState(addr, tMod.Key, tMod.Value)
				statedb.IntermediateRoot(false)
			}

			cRoot := statedb.GetTrie().Hash()
			if i == len(trieModifications)-1 {
				finalRoot = cRoot
			}

			accountProof1, aNeighbourNode2, aExtNibbles2, err := statedb.GetProof(addr)
			check(err)

			storageProof1, neighbourNode2, extNibbles2, err := statedb.GetStorageProof(addr, tMod.Key)
			check(err)

			aNode := aNeighbourNode2
			aExtNibbles := aExtNibbles2
			if len(accountProof) > len(accountProof1) {
				// delete operation
				aNode = aNeighbourNode1
				aExtNibbles = aExtNibbles1
			}

			node := neighbourNode2
			extNibbles := extNibbles2
			if len(storageProof) > len(storageProof1) {
				// delete operation
				node = neighbourNode1
				extNibbles = extNibbles1
			}

			if (specialTest == 1) {
				account := accountProof1[len(accountProof1)-1]
				if len(accountProof1) != 2 {
					panic("account should be in the second level (one branch above it)")
				}
				firstNibble := addrh[0] / 16
				newAccount := moveAccountFromSecondToFirstLevel(firstNibble, account)

				newAccount1 := make([]byte, len(account)+1) 
				copy(newAccount1, newAccount)
				
				accountProof = make([][]byte, 1)
				accountProof[0] = newAccount
				accountProof1 = make([][]byte, 1)
				accountProof1[0] = newAccount1

				// storage leaf in S proof is a placeholder, thus newAccount needs to have an empty trie hash
				// for the root:
				emptyTrieHash := []byte{86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33}
				rootStart := len(newAccount) - 64 - 1;

				for i := 0; i < 32; i++ {
					newAccount[rootStart + i] = emptyTrieHash[i]
				}
			
				hasher := trie.NewHasher(false)
				sRoot = common.BytesToHash(hasher.HashData(newAccount))
				cRoot = common.BytesToHash(hasher.HashData(newAccount1))
			}
			
			rowsState, toBeHashedAcc, _ :=
				prepareWitness(statedb, addr, accountProof, accountProof1, aExtNibbles, accountAddr, aNode, true, tMod.Type == NonExistingAccount, false)
			rowsStorage, toBeHashedStorage, _ :=
				prepareWitness(statedb, addr, storageProof, storageProof1, extNibbles, keyHashed, node, false, false, tMod.Type == NonExistingStorage)
			rowsState = append(rowsState, rowsStorage...)
	
			proof := prepareProof(i, rowsState, addrh, sRoot, cRoot, startRoot, finalRoot, tMod.Type)
			allProofs = append(allProofs, proof...)
			
			// Put rows that just need to be hashed at the end, because circuit assign function
			// relies on index (for example when assigning s_keccak and c_keccak).
			toBeHashed = append(toBeHashed, toBeHashedAcc...)
			toBeHashed = append(toBeHashed, toBeHashedStorage...)
		} else {
			proof, toBeHashedAcc := prepareAccountProof(i, tMod, len(trieModifications), statedb, specialTest)
			allProofs = append(allProofs, proof...)
			toBeHashed = append(toBeHashed, toBeHashedAcc...)
		}
	}
	allProofs = append(allProofs, toBeHashed...)

	return allProofs
}

func GenerateProof(testName string, trieModifications []TrieModification, statedb *state.StateDB) {
	proof := getParallelProofs(trieModifications, statedb, 0)

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

func GenerateProofSpecial(testName string, trieModifications []TrieModification, statedb *state.StateDB, specialTest byte) {
	proof := getParallelProofs(trieModifications, statedb, specialTest)

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
		trieModifications []TrieModification) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)

	statedb.DisableLoadingRemoteAccounts()

	// Set the state needed for the test:
	for i := 0; i < len(keys); i++ {
		statedb.SetState(addresses[i], keys[i], values[i])
	}
	
	proof := getParallelProofs(trieModifications, statedb, 0)

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