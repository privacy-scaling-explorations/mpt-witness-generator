package witness

import (
	"fmt"
	"log"
	"math/big"

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

func GetProof() {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockNumber := big.NewInt(int64(blockNum + 1))

	pkw := oracle.PreimageKeyValueWriter{}
	pkwtrie := trie.NewStackTrie(pkw)

	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	blockHeader := oracle.PrefetchBlock(blockNumber, false, pkwtrie)

	fmt.Println(blockHeaderParent.Root)
	fmt.Println(blockHeader)

	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)

	// fmt.Println(statedb)

	/*
		// TODO: convert to SetState ... to enable testing
		var txs []*types.Transaction
		triedb := trie.NewDatabase(blockHeaderParent)
		tt, _ := trie.New(blockHeader.TxHash, &triedb)
		tni := tt.NodeIterator([]byte{})
		for tni.Next(true) {
			fmt.Println("---------")
			fmt.Println(tni.Hash(), tni.Leaf(), tni.Path(), tni.Error())
			if tni.Leaf() {
				tx := types.Transaction{}
				var rlpKey uint64
				check(rlp.DecodeBytes(tni.LeafKey(), &rlpKey))
				check(tx.UnmarshalBinary(tni.LeafBlob()))
				// TODO: resize an array in go?
				for uint64(len(txs)) <= rlpKey {
					txs = append(txs, nil)
				}
				txs[rlpKey] = &tx
			}
		}
		fmt.Println("read", len(txs), "transactions in block "+blockNumber.String())
	*/

	// addr := common.HexToAddress("0xA0c68C638235ee32657e8f720a23ceC1bFc77C77")
	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81c9")

	// fill some storage keys for testing
	ks := [...]common.Hash{common.HexToHash("0x11"), common.HexToHash("0x12"), common.HexToHash("0x21")}
	for i := 0; i < len(ks); i++ {
		// k := common.BigToHash(big.NewInt(int64(i)))

		k := ks[i]
		v := common.BigToHash(big.NewInt(int64(i + 1))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279

		fmt.Println("----------------")
		fmt.Println(k)
		statedb.SetState(addr, k, v)
	}

	// trie := statedb.GetTrie()

	// trie := statedb.StorageTrie(addr)
	// fmt.Println(trie)

	// keyT := common.HexToHash("0xb8")
	// sp, err := statedb.GetStorageProof(addr, keyT)
	sp, err := statedb.GetStorageProof(addr, ks[1])
	fmt.Println(err)
	fmt.Println(sp)

	hasher := trie.NewHasher(false)

	kh := crypto.Keccak256(ks[1].Bytes())
	khh := trie.KeybytesToHex(kh)
	fmt.Println(khh)

	h := hasher.HashData(sp[0])
	d, err := trie.DecodeNode(h, sp[0])
	fmt.Println(err)
	fmt.Println(d)

	h2 := hasher.HashData(sp[1])
	d2, err := trie.DecodeNode(h2, sp[1])
	fmt.Println(err)
	fmt.Println(d2)

	fmt.Println("==============================")

	// otherwise retrieved from bus-mapping:
	opType := [...]int{0, 0}

	addresses := [...]common.Address{addr, addr}

	k1 := common.BigToHash(big.NewInt(int64(30023)))
	k2 := common.BigToHash(big.NewInt(int64(30230)))
	v1 := common.BigToHash(big.NewInt(int64(301110)))
	v2 := common.BigToHash(big.NewInt(int64(222303)))
	keys := [...]common.Hash{k1, k2}
	values := [...]common.Hash{v1, v2}

	fmt.Println("===========11===========")
	fmt.Println(values)

	/* The storage change can be either (opType):
	 (0) update (storage key already existed)
	 (1) add (storage key didn't exist)
	 (2) delete

	(0) If storage key already existed, we can get a proof:
	  proof := oracle.PrefetchStorage(blockNumberParent, addresses[0], key, nil)

	(1) If the storage key didn't exist before this operation
	*/

	/*
		for i := 31; i > 0; i-- {
			// f := keys[0][:i]
			// fmt.Println(f)

			proof := oracle.PrefetchStorage(blockNumberParent, addresses[0], keys[0], nil)
			fmt.Println(len(proof))
		}
	*/

	fmt.Println("----------------000000000000000000000000000")

	if opType[0] == 0 { // update
		proof := oracle.PrefetchStorage(blockNumberParent, addresses[0], keys[0], nil)
		fmt.Println(len(proof))
	} else if opType[0] == 1 { // add

	} else if opType[0] == 2 { // delete

	}

	for i := 0; i < len(keys); i++ {
		if opType[i] == 0 { // update
			statedb.SetState(addresses[i], keys[i], values[i])
			statedb.IntermediateRoot(false)
			p, err := statedb.GetProof(addr)
			fmt.Println("++++++++=================+++++++++")
			fmt.Println(err)
			fmt.Println(len(p))

		} else if opType[i] == 1 { // add

		} else if opType[i] == 2 { // delete

		}

	}

	fmt.Println("====================")

}
