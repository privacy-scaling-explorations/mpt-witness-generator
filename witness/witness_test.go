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

// rowLen - each branch node has 2 positions for RLP meta data and 32 positions for hash
const rowLen = branch2start + 2 + 32 + 1 // +1 is for info about what type of row is it
const keyPos = 10
const isBranchSPlaceholderPos = 11
const isBranchCPlaceholderPos = 12

/*
Info about row type (given as the last element of the row):
0: init branch (such a row contains RLP info about the branch node; key)
1: branch child
2: storage leaf s
3: storage leaf c
5: hash to be computed (for example branch RLP whose hash needs to be checked in the parent)
6: account leaf key S
7: account leaf nonce balance S
8: account leaf root codehash S
11: account leaf root codehash C
13: storage leaf s value
14: storage leaf c value
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

func prepareWitness(storageProof1, storageProof2 [][]byte, key []byte, isAccountProof bool) ([][]byte, [][]byte) {
	rows := make([][]byte, 0)
	toBeHashed := make([][]byte, 0)

	minLen := len(storageProof1)
	if len(storageProof2) < minLen {
		minLen = len(storageProof2)
	}

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

	for i := 0; i < upTo; i++ {
		elems, _, err := rlp.SplitList(storageProof1[i])
		if err != nil {
			fmt.Println("decode error", err)
		}
		switch c, _ := rlp.CountValues(elems); c {
		case 2:
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
				// 78 means lenght of a list.

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

				// TODO: delete operation

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
			bRows := prepareTwoBranchesWitness(storageProof1[i], storageProof2[i], key[i], false, false)
			rows = append(rows, bRows...)

			branch1Ext := make([]byte, len(storageProof1[i]))
			copy(branch1Ext, storageProof1[i])
			branch1Ext = append(branch1Ext, 5) // 5 means it needs to be hashed

			branch2Ext := make([]byte, len(storageProof2[i]))
			copy(branch2Ext, storageProof2[i])
			branch2Ext = append(branch2Ext, 5) // 5 means it needs to be hashed

			toBeHashed = append(toBeHashed, branch1Ext)
			toBeHashed = append(toBeHashed, branch2Ext)

			// check the two branches
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
		branchExt := make([]byte, len(branchToBeHashed))
		copy(branchExt, branchToBeHashed)
		branchExt = append(branchExt, 5) // 5 means it needs to be hashed
		toBeHashed = append(toBeHashed, branchExt)
	}

	if len1 > len2 {
		if additionalBranch {
			// C branch is just a placeholder here.
			addBranch(storageProof1[len1-2], storageProof1[len1-2], key[len1-2], true)

			leafRows, leafForHashing := prepareLeafRows(storageProof1[len1-1], 2)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			leafRows, leafForHashing = prepareLeafRows(storageProof2[len2-1], 3)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)
		} else {
			// We don't have a leaf in the shorter proof, but we will add it there
			// too as a placeholder.
			leafRows, leafForHashing := prepareLeafRows(storageProof1[len1-1], 2)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			leafRows, _ = prepareLeafRows(storageProof1[len1-1], 3)
			rows = append(rows, leafRows...)
		}
	} else if len2 > len1 {
		if additionalBranch {
			// S branch is just a placeholder here.
			addBranch(storageProof2[len2-2], storageProof2[len2-2], key[len2-2], false)

			// Note that this is not just reversed order compared to
			// len1 > len2 case - the first leaf is always from proof S.

			leafRows, leafForHashing := prepareLeafRows(storageProof1[len1-1], 2)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			leafRows, leafForHashing = prepareLeafRows(storageProof2[len2-1], 3)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)
		} else {
			leafRows, leafForHashing := prepareLeafRows(storageProof2[len2-1], 2)
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafForHashing)

			leafRows, _ = prepareLeafRows(storageProof2[len2-1], 3)
			rows = append(rows, leafRows...)
		}
	}

	return rows, toBeHashed
}

func updateStorageAndGetProofs(keys []common.Hash, toBeModified common.Hash, value common.Hash) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81c9")

	for i := 0; i < len(keys); i++ {
		k := keys[i]
		v := common.BigToHash(big.NewInt(int64(i + 1))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
		statedb.SetState(addr, k, v)
	}

	// Let's say above state is our starting position.
	storageProof, err := statedb.GetStorageProof(addr, toBeModified)
	check(err)

	kh := crypto.Keccak256(toBeModified.Bytes())
	key := trie.KeybytesToHex(kh)

	// Just to check key RLC (rand = 1)
	kh_sum := 0
	for i := 0; i < len(kh); i++ {
		kh_sum += int(kh[i])
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
	storageProof1, err := statedb.GetStorageProof(addr, toBeModified)
	check(err)

	rows, toBeHashed := prepareWitness(storageProof, storageProof1, key, false)
	rows = append(rows, toBeHashed...)
	fmt.Println(matrixToJson(rows))

	len1 := len(storageProof)
	len2 := len(storageProof1)
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

		for i := 0; i < minLen; i++ {
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

func updateStateAndGetProofs(keys []common.Hash, toBeModified common.Hash, addr common.Address) {
	// Here we are checking the whole state trie, not only a storage trie for some account as in above tests.
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)

	for i := 0; i < len(keys); i++ {
		k := keys[i]
		v := common.BigToHash(big.NewInt(int64(i + 1))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
		statedb.SetState(addr, k, v)
	}

	// If we don't call IntermediateRoot, obj.data.Root will be hash(emptyRoot).
	statedb.IntermediateRoot(false)

	// Let's say above is our starting position.

	// We now get a proof for the starting position for the slot that will be changed further on (ks[1]):
	// This first proof will actually be retrieved by RPC eth_getProof (see oracle.PrefetchStorage function).
	// All other proofs (after modifications) will be generated internally by buildig the internal state.

	accountProof, err := statedb.GetProof(addr)
	check(err)
	storageProof, err := statedb.GetStorageProof(addr, toBeModified)
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

	accountAddr := trie.KeybytesToHex(crypto.Keccak256(addr.Bytes()))

	kh := crypto.Keccak256(toBeModified.Bytes())
	key := trie.KeybytesToHex(kh)

	// Just to check key RLC (rand = 1)
	kh_sum := 0
	for i := 0; i < len(kh); i++ {
		kh_sum += int(kh[i])
	}
	fmt.Println("key sum:")
	fmt.Println(kh_sum)

	/*
		Modifying storage:
	*/

	// We now change one existing storage slot:
	v := common.BigToHash(big.NewInt(int64(17)))
	statedb.SetState(addr, toBeModified, v)

	// We ask for a proof for the modified slot:
	statedb.IntermediateRoot(false)

	accountProof1, err := statedb.GetProof(addr)
	check(err)

	storageProof1, err := statedb.GetStorageProof(addr, toBeModified)
	check(err)

	rowsState, toBeHashedAcc := prepareWitness(accountProof, accountProof1, accountAddr, true)
	rowsStorage, toBeHashedStorage := prepareWitness(storageProof, storageProof1, key, false)
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

	if !VerifyTwoProofsAndPath(accountProof, accountProof1, accountAddr) {
		panic("proof not valid")
	}

	if !VerifyTwoProofsAndPath(storageProof, storageProof1, key) {
		panic("proof not valid")
	}
}

func TestStorageUpdateOneLevel(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// We have a branch with children at position 3 and 11.

	// This key is turned into odd length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	toBeModified := ks[0]
	v := common.BigToHash(big.NewInt(int64(17)))
	updateStorageAndGetProofs(ks[:], toBeModified, v)
}

func TestStorageUpdateOneLevelBigVal(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// We have a branch with children at position 3 and 11.

	// This key is turned into odd length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	toBeModified := ks[0]
	// big value so that RLP is longer than 55 bytes
	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	updateStorageAndGetProofs(ks[:], toBeModified, v2)
}

func TestStorageUpdateTwoLevels(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x11"), common.HexToHash("0x12"), common.HexToHash("0x21")} // this has three levels
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// First we have a branch with children at position 3 and 11.
	// The third storage change happens at key:
	// [3,10,6,3,5,7,...
	// That means leaf at position 3 turns into branch with children at position 1 and 10.
	// ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	// This key is turned into even length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	toBeModified := ks[0]
	v := common.BigToHash(big.NewInt(int64(17)))
	updateStorageAndGetProofs(ks[:], toBeModified, v)
}

func TestStorageUpdateTwoLevelsBigVal(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x11"), common.HexToHash("0x12"), common.HexToHash("0x21")} // this has three levels
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// First we have a branch with children at position 3 and 11.
	// The third storage change happens at key:
	// [3,10,6,3,5,7,...
	// That means leaf at position 3 turns into branch with children at position 1 and 10.
	// ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	// This key is turned into even length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	toBeModified := ks[0]

	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	updateStorageAndGetProofs(ks[:], toBeModified, v2)
}

func TestStorageUpdateThreeLevels1(t *testing.T) {
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
	toBeModified := ks[10]

	v := common.BigToHash(big.NewInt(int64(17)))
	updateStorageAndGetProofs(ks[:], toBeModified, v)
}

func TestStorageFromNilToValue(t *testing.T) {
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
	// This test is similar as above, but the key that is being modified has not been used yet.

	toBeModified := common.HexToHash("0x38")

	v := common.BigToHash(big.NewInt(int64(17)))
	updateStorageAndGetProofs(ks[:], toBeModified, v)
}

func TestStateUpdateOneLevel(t *testing.T) {
	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81c9")
	// This address is turned into odd length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	// This is a storage slot that will be modified (the list will come from bus-mapping):
	toBeModified := ks[1]

	updateStateAndGetProofs(ks[:], toBeModified, addr)
}

func TestStateUpdateOneLevelEvenAddress(t *testing.T) {
	addr := common.HexToAddress("0x25efbf12580138bc263c95757826df4e24eb81c9")
	// This address is turned into even length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	// This is a storage slot that will be modified (the list will come from bus-mapping):
	toBeModified := ks[1]

	updateStateAndGetProofs(ks[:], toBeModified, addr)
}

func TestStorageAddBranch(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x11"), common.HexToHash("0x12")}
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// First we have a branch with children at position 3 and 11.
	// ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	// This key is not in the trie yet, its nibbles:
	// [3,10,6,3,5,7,...
	// That means leaf at position 3 turns into branch with children at position 1 and 10.
	toBeModified := common.HexToHash("0x21")

	v := common.BigToHash(big.NewInt(int64(17)))
	updateStorageAndGetProofs(ks[:], toBeModified, v)
}

func TestStorageExtension(t *testing.T) {
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

	toBeModified := ks[10]

	v := common.BigToHash(big.NewInt(int64(17)))
	updateStorageAndGetProofs(ks[:], toBeModified, v)
}
