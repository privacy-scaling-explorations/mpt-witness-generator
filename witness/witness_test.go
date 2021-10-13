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

func check(err error) {
	if err != nil {
		log.Fatal(err)
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
	for i := 0; i < len(proof1)-1; i++ {
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

func prepareBranchWitness(rows [][]byte, branch []byte, branchOffset int) {
	offset := 2
	layoutOffset := 2
	rowInd := 0
	colInd := layoutOffset
	inside32Ind := -1
	for i := 0; i < int(branch[1]); i++ { // TODO: length can occupy more than just one byte
		if rowInd == 16 {
			break
		}
		b := branch[offset+i]
		if b == 160 && inside32Ind == -1 { // new child
			inside32Ind = 0
			colInd = 1 // TODO: length can ...
			rows[rowInd][branchOffset+colInd] = b
			colInd++
			continue
		}

		if inside32Ind >= 0 {
			rows[rowInd][branchOffset+colInd] = b
			colInd++
			inside32Ind++
			fmt.Println(rows[rowInd])
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
			rows[rowInd][branchOffset+layoutOffset] = b
			rowInd++
			fmt.Println(rows[rowInd-1])
		}
	}
}

func prepareTwoBranchesWitness(branch1, branch2 []byte) [][]byte {
	rows := make([][]byte, 16)
	for i := 0; i < 16; i++ {
		rows[i] = make([]byte, 2+32+2+32)
	}

	// TODO: length can occupy more than just one byte
	rows[0][0] = branch1[0]
	rows[0][1] = branch1[1]
	rows[0][2+32] = branch2[0]
	rows[0][2+32+1] = branch2[1]

	prepareBranchWitness(rows, branch1, 0)
	prepareBranchWitness(rows, branch2, 2+32)

	return rows
}

func TestStorageUpdateOneLevel(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)

	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)

	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81c9")

	// ks := [...]common.Hash{common.HexToHash("0x11"), common.HexToHash("0x12"), common.HexToHash("0x21")}
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	for i := 0; i < len(ks); i++ {
		k := ks[i]
		v := common.BigToHash(big.NewInt(int64(i + 1))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
		statedb.SetState(addr, k, v)
	}
	// We have a branch with two leaves at positions 3 and 11.

	// Let's say above is our starting position.

	// This is a storage slot that will be modified (the list will come from bus-mapping):
	toBeModified := [...]common.Hash{ks[1]}

	// We now get a storageProof for the starting position for the slot that will be changed further on (ks[1]):
	// This first storageProof will actually be retrieved by RPC eth_getProof (see oracle.PrefetchStorage function).
	// All other proofs (after modifications) will be generated internally by buildig the internal state.
	storageProof, err := statedb.GetStorageProof(addr, toBeModified[0])
	check(err)

	kh := crypto.Keccak256(toBeModified[0].Bytes())
	key := trie.KeybytesToHex(kh)

	/*
		Modifying storage:
	*/

	// We now change one existing storage slot:
	v := common.BigToHash(big.NewInt(int64(17)))
	statedb.SetState(addr, toBeModified[0], v)

	// We ask for a proof for the modified slot:
	statedb.IntermediateRoot(false)
	storageProof1, err := statedb.GetStorageProof(addr, toBeModified[0])
	check(err)

	branch1 := storageProof[0]
	branch2 := storageProof1[0]

	rows := prepareTwoBranchesWitness(branch1, branch2)

	// check
	l := len(rows[0]) / 2
	for i := 0; i < 16; i++ {
		if i == int(key[0]) {
			continue
		}
		for j := 0; j < l; j++ {
			if rows[i][j] != rows[i][j+l] {
				panic("witness not properly generated")
			}
		}
	}

	// Had some problems with json.Marshal, so I just prepare json manually.
	json := "["
	for i := 0; i < len(rows); i++ {
		json += "["
		for j := 0; j < len(rows[i]); j++ {
			json += strconv.Itoa(int(rows[i][j]))
			if j != len(rows[i])-1 {
				json += ","
			}
		}
		json += "]"
		if i != len(rows)-1 {
			json += ","
		}
	}
	json += "]"
	fmt.Println(json)

	if !VerifyTwoProofsAndPath(storageProof, storageProof1, key) {
		panic("proof not valid")
	}
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
	// Here we are checking the whole state trie, not only a storage trie for some account as in above tests.
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

	// This is a storage slot that will be modified (the list will come from bus-mapping):
	toBeModified := [...]common.Hash{ks[1]}

	// We now get a proof for the starting position for the slot that will be changed further on (ks[1]):
	// This first proof will actually be retrieved by RPC eth_getProof (see oracle.PrefetchStorage function).
	// All other proofs (after modifications) will be generated internally by buildig the internal state.

	accountProof, err := statedb.GetProof(addr)
	check(err)
	storageProof, err := statedb.GetStorageProof(addr, toBeModified[0])
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

	accountAddr := trie.KeybytesToHex(crypto.Keccak256(addr.Bytes()))

	kh := crypto.Keccak256(toBeModified[0].Bytes())
	key := trie.KeybytesToHex(kh)

	/*
		Modifying storage:
	*/

	// We now change one existing storage slot:
	v := common.BigToHash(big.NewInt(int64(17)))
	statedb.SetState(addr, toBeModified[0], v)

	// We ask for a proof for the modified slot:
	statedb.IntermediateRoot(false)

	accountProof1, err := statedb.GetProof(addr)
	check(err)

	storageProof1, err := statedb.GetStorageProof(addr, toBeModified[0])
	check(err)

	if !VerifyTwoProofsAndPath(accountProof, accountProof1, accountAddr) {
		panic("proof not valid")
	}

	if !VerifyTwoProofsAndPath(storageProof, storageProof1, key) {
		panic("proof not valid")
	}
}
