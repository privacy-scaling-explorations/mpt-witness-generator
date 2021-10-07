package witness

import (
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/miha-stopar/mpt/oracle"
	"github.com/miha-stopar/mpt/state"
	"github.com/miha-stopar/mpt/trie"
)

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
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

	// We now get a proof for the starting position for the slot that will be changed further on (ks[1]):
	// This first proof will actually be retrieved by RPC getProof (see oracle.PrefetchStorage function).
	// All other proofs (after modifications) will be generated internally by buildig the internal state.
	proof, err := statedb.GetStorageProof(addr, toBeModified[0])
	check(err)
	hasher := trie.NewHasher(false)

	kh := crypto.Keccak256(toBeModified[0].Bytes())
	key := trie.KeybytesToHex(kh)

	rootHash := hasher.HashData(proof[0])
	root, err := trie.DecodeNode(rootHash, proof[0])
	check(err)

	nodeHash := hasher.HashData(proof[1])
	leaf, err := trie.DecodeNode(nodeHash, proof[1])
	check(err)

	r := root.(*trie.FullNode)
	c := r.Children[key[0]]
	u, _ := hasher.Hash(leaf, false)

	// Constraints for proof verification (only one because only one level):
	if fmt.Sprintf("%b", u) != fmt.Sprintf("%b", c) {
		panic("not the same")
	}

	/*
		Modifying storage:
	*/

	// We now change one existing storage slot:
	v := common.BigToHash(big.NewInt(int64(17)))
	statedb.SetState(addr, toBeModified[0], v)

	// We ask for a proof for the modified slot:
	statedb.IntermediateRoot(false)
	proof1, err := statedb.GetStorageProof(addr, toBeModified[0])
	check(err)

	rootHash1 := hasher.HashData(proof1[0])
	root1, err := trie.DecodeNode(rootHash1, proof1[0])
	check(err)

	nodeHash1 := hasher.HashData(proof1[1])
	leaf1, err := trie.DecodeNode(nodeHash1, proof1[1])
	check(err)

	r1 := root1.(*trie.FullNode)
	c1 := r1.Children[key[0]]
	u1, _ := hasher.Hash(leaf1, false)
	// Constraints for proof verification (only one because only one level):
	if fmt.Sprintf("%b", u1) != fmt.Sprintf("%b", c1) {
		panic("not the same")
	}

	// Constraints that we are having the same path for both proofs:
	for i := 0; i < 16; i++ {
		if i != int(key[0]) {
			if fmt.Sprintf("%b", r.Children[i]) != fmt.Sprintf("%b", r1.Children[i]) {
				panic("not the same")
			}
		}

	}
}

func TestStorageAddOneLevel(t *testing.T) {
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

	// This is a storage slot that will be modified (the list will come from bus-mapping).
	// Compared to the test TestStorageUpdateOneLevel, there is no node in trie for this storage key.
	toBeModified := [...]common.Hash{common.HexToHash("0x31")}

	// We now get a proof for the starting position for the slot that will be changed further on (ks[1]):
	// This first proof will actually be retrieved by RPC getProof (see oracle.PrefetchStorage function).
	// All other proofs (after modifications) will be generated internally by buildig the internal state.
	proof, err := statedb.GetStorageProof(addr, toBeModified[0])
	check(err)
	hasher := trie.NewHasher(false)

	// Compared to the test TestStorageUpdateOneLevel, there is no node in trie for this storage key - the key
	// asks for the position 12 and there is nothing. Thus, the proof will only contain one element - the root node.

	kh := crypto.Keccak256(toBeModified[0].Bytes())
	key := trie.KeybytesToHex(kh)

	rootHash := hasher.HashData(proof[0])
	root, err := trie.DecodeNode(rootHash, proof[0])
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
	proof1, err := statedb.GetStorageProof(addr, toBeModified[0])
	check(err)

	rootHash1 := hasher.HashData(proof1[0])
	root1, err := trie.DecodeNode(rootHash1, proof1[0])
	check(err)

	nodeHash1 := hasher.HashData(proof1[1])
	leaf1, err := trie.DecodeNode(nodeHash1, proof1[1])
	check(err)

	r1 := root1.(*trie.FullNode)
	c1 := r1.Children[key[0]]
	u1, _ := hasher.Hash(leaf1, false)

	// Constraints for proof verification (only one because only one level):
	if fmt.Sprintf("%b", u1) != fmt.Sprintf("%b", c1) {
		panic("not the same")
	}

	// Constraints that we are having the same path for both proofs:
	for i := 0; i < 16; i++ {
		if i != int(key[0]) {
			if fmt.Sprintf("%b", r.Children[i]) != fmt.Sprintf("%b", r1.Children[i]) {
				panic("not the same")
			}
		}

	}
}
