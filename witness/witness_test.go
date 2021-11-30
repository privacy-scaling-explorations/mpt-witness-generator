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
const keyPos = 8

/*
Info about row type (given as the last element of the row):
0: init branch (such a row contains RLP info about the branch node; key)
1: branch child
2: leaf s
3: leaf c
4: leaf key nibbles
5: hash to be computed (for example branch RLP whose hash needs to be checked in the parent)
6: account leaf S
7: account leaf S
8: account leaf S
9: account leaf C
10: account leaf C
11: account leaf C
12: account leaf key nibbles
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
	for i := 0; i < len(proof1)-1-1; i++ { // -1 because it checks current and next row; another -1 because the last row is key nibbles
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

func prepareLeaf(row []byte, typ byte) []byte {
	// Avoid directly changing the row as it might introduce some bugs later on.
	leaf := make([]byte, len(row))
	copy(leaf, row)
	leaf = append(leaf, typ)

	return leaf
}

func prepareTwoBranchesWitness(branch1, branch2 []byte, key byte) [][]byte {
	rows := make([][]byte, 17)
	rows[0] = make([]byte, rowLen)

	if branch1[0] != branch2[0] || branch1[1] != branch2[1] {
		// TODO
		panic("branches have different length")
	}

	// Branch (length 83) with two bytes of RLP meta data
	// [248,81,128,128,...

	// Branch (length 340) with three bytes of RLP meta data
	// [249,1,81,128,16,...

	branchRLPOffset := 2
	rows[0][0] = 1 // 1 0 means two RLP bytes
	rows[0][1] = 0
	if branch1[0] == 249 {
		branchRLPOffset = 3
		rows[0][0] = 0 // 0 1 means three RLP bytes
		rows[0][1] = 1
	}

	// Let's put in the 0-th row some RLP data (the length of the whole branch RLP)
	rows[0][2] = branch1[0]
	rows[0][3] = branch1[1]

	rows[0][5] = branch2[0]
	rows[0][6] = branch2[1]

	if branchRLPOffset == 3 {
		rows[0][4] = branch1[2]
		rows[0][7] = branch2[2]
	}

	rows[0][keyPos] = key

	for i := 1; i < 17; i++ {
		rows[i] = make([]byte, rowLen)
		// assign row type
		if i == 0 {
			rows[i][rowLen-1] = 0
		} else {
			rows[i][rowLen-1] = 1
		}
	}
	prepareBranchWitness(rows, branch1, 0, branchRLPOffset)
	prepareBranchWitness(rows, branch2, 2+32, branchRLPOffset)

	return rows
}

func prepareWitness(storageProof, storageProof1 [][]byte, key []byte, isAccountProof bool) ([][]byte, [][]byte) {
	rows := make([][]byte, 0)
	toBeHashed := make([][]byte, 0)
	for i := 0; i < len(storageProof); i++ {
		if i == len(storageProof)-1 {
			// both proofs have the same key
			l := make([]byte, len(storageProof[i]))
			copy(l, storageProof[i])
			if isAccountProof {
				l = append(l, 12) // 12 is account leaf key nibbles
			} else {
				l = append(l, 4) // 4 is leaf key nibbles
			}
			rows = append(rows, l)

			return rows, toBeHashed
		}
		elems, _, err := rlp.SplitList(storageProof[i])
		if err != nil {
			fmt.Println("decode error", err)
		}
		switch c, _ := rlp.CountValues(elems); c {
		case 2:
			if isAccountProof {
				l := len(storageProof)
				leafS := storageProof[l-2] // last one is nibbles
				leafC := storageProof1[l-2]

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

				keyRowC := make([]byte, rowLen)
				copy(keyRowC, keyRow)
				nonceBalanceRowC := make([]byte, rowLen)
				copy(nonceBalanceRowC, nonceBalanceRow)

				keyRow = append(keyRow, 6)
				nonceBalanceRow = append(nonceBalanceRow, 7)
				storageCodeHashRowS = append(storageCodeHashRowS, 8)

				keyRowC = append(keyRowC, 9)
				nonceBalanceRowC = append(nonceBalanceRowC, 10)
				storageCodeHashRowC = append(storageCodeHashRowC, 11)

				rows = append(rows, keyRow)
				rows = append(rows, nonceBalanceRow)
				rows = append(rows, storageCodeHashRowS)

				rows = append(rows, keyRowC)
				rows = append(rows, nonceBalanceRowC)
				rows = append(rows, storageCodeHashRowC)

				leafS = append(leafS, 5)
				leafC = append(leafC, 5)
				toBeHashed = append(toBeHashed, leafS)
				toBeHashed = append(toBeHashed, leafC)
			} else {
				leaf1 := prepareLeaf(storageProof[i], 2)  // leaf s
				leaf2 := prepareLeaf(storageProof1[i], 3) // leaf c
				rows = append(rows, leaf1)
				rows = append(rows, leaf2)
			}
		case 17:
			bRows := prepareTwoBranchesWitness(storageProof[i], storageProof1[i], key[i])
			rows = append(rows, bRows...)

			branch1Ext := make([]byte, len(storageProof[i]))
			copy(branch1Ext, storageProof[i])
			branch1Ext = append(branch1Ext, 5) // 5 means it needs to be hashed

			branch2Ext := make([]byte, len(storageProof1[i]))
			copy(branch2Ext, storageProof1[i])
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

	return rows, toBeHashed
}

func execTest(keys []common.Hash, toBeModified common.Hash) {
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

	/*
		Modifying storage:
	*/

	// We now change one existing storage slot:
	v := common.BigToHash(big.NewInt(int64(17)))
	statedb.SetState(addr, toBeModified, v)

	// We ask for a proof for the modified slot:
	statedb.IntermediateRoot(false)
	storageProof1, err := statedb.GetStorageProof(addr, toBeModified)
	check(err)

	// TODO: add key nibbles in rows to be hashed

	rows, toBeHashed := prepareWitness(storageProof, storageProof1, key, false)
	rows = append(rows, toBeHashed...)
	fmt.Println(matrixToJson(rows))

	if !VerifyTwoProofsAndPath(storageProof, storageProof1, key) {
		panic("proof not valid")
	}
}

func execStateTest(keys []common.Hash, toBeModified common.Hash, addr common.Address) {
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

	ind := len(accountProof) - 2 // last row is address nibbles
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

	// TODO: add accountAddr and key nibbles in rows to be hashed

	rowsState, toBeHashedAcc := prepareWitness(accountProof, accountProof1, accountAddr, true)
	// rowsStorage, toBeHashedStorage := prepareWitness(storageProof, storageProof1, key, false)
	// rowsState = append(rowsState, rowsStorage...)

	// Put rows that just need to be hashed at the end, because circuit assign function
	// relies on index (for example when assigning s_keccak and c_keccak).
	rowsState = append(rowsState, toBeHashedAcc...)
	// rowsState = append(rowsState, toBeHashedStorage...)
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

	toBeModified := ks[0]

	execTest(ks[:], toBeModified)
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

	toBeModified := ks[0]

	execTest(ks[:], toBeModified)
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

	execTest(ks[:], toBeModified)
}

func TestStorageAddOneLevel(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)

	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)

	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81c9")

	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	for i := 0; i < len(ks); i++ {
		k := ks[i]
		v := common.BigToHash(big.NewInt(int64(i + 1))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
		statedb.SetState(addr, k, v)
	}
	// We have a branch with two leaves at positions 3 and 11.

	// Let's say above is our starting position.

	// This is a storage slot that will be modified (the list will come from bus-mapping).
	// Compared to the test TestStorageUpdateOneLevel, there is no node in trie for this storage key.
	toBeModified := [...]common.Hash{common.HexToHash("0x31")}

	// We now get a storageProof for the starting position for the slot that will be changed further on (ks[1]):
	// This first storageProof will actually be retrieved by RPC eth_getProof (see oracle.PrefetchStorage function).
	// All other proofs (after modifications) will be generated internally by buildig the internal state.
	storageProof, err := statedb.GetStorageProof(addr, toBeModified[0])
	check(err)
	hasher := trie.NewHasher(false)

	// Compared to the test TestStorageUpdateOneLevel, there is no node in trie for this storage key - the key
	// asks for the position 12 and there is nothing. Thus, the proof will only contain one element - the root node.

	kh := crypto.Keccak256(toBeModified[0].Bytes())
	key := trie.KeybytesToHex(kh)

	rootHash := hasher.HashData(storageProof[0])
	root, err := trie.DecodeNode(rootHash, storageProof[0])
	check(err)
	r := root.(*trie.FullNode)

	// Constraint for proof verification - only one element in the proof so nothing to be verified except
	// that the key at this position is nil:
	if r.Children[key[0]] != nil {
		panic("not correct")
	}

	/*
		Modifying storage:
	*/

	// We now change the storage slot:
	v := common.BigToHash(big.NewInt(int64(17)))
	statedb.SetState(addr, toBeModified[0], v)

	// We ask for a proof for the modified slot:
	statedb.IntermediateRoot(false)
	storageProof2, err := statedb.GetStorageProof(addr, toBeModified[0])
	check(err)

	rootHash2 := hasher.HashData(storageProof2[0])
	root2, err := trie.DecodeNode(rootHash2, storageProof2[0])
	check(err)
	r2 := root2.(*trie.FullNode)

	if !VerifyProof(storageProof2, key) {
		panic("proof not valid")
	}

	if !VerifyElementsInTwoBranches(r, r2, key[0]) {
		panic("proof not valid")
	}
}

func TestStateUpdateOneLevel(t *testing.T) {
	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81c9")
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	// This is a storage slot that will be modified (the list will come from bus-mapping):
	toBeModified := ks[1]

	execStateTest(ks[:], toBeModified, addr)
}
