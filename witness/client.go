package witness

import (
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
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

	fmt.Println(statedb)

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

	addr := common.HexToAddress("0xA0c68C638235ee32657e8f720a23ceC1bFc77C77")

	// otherwise retrieved from bus-mapping:
	addresses := [...]common.Address{addr, addr}
	k1 := common.BigToHash(big.NewInt(int64(13)))
	k2 := common.BigToHash(big.NewInt(int64(18)))
	v1 := common.BigToHash(big.NewInt(int64(300)))
	v2 := common.BigToHash(big.NewInt(int64(303)))
	keys := [...]common.Hash{k1, k2}
	values := [...]common.Hash{v1, v2}

	fmt.Println("===========11===========")
	r := statedb.IntermediateRoot(false)
	fmt.Println(r)

	// statedb.AddBalance(addr, big.NewInt(int64(17)))
	for i := 0; i < len(keys); i++ {
		statedb.SetState(addresses[i], keys[i], values[i])

		statedb.IntermediateRoot(false)
		p, err := statedb.GetProof(addr)
		fmt.Println("++++++++=================+++++++++")
		fmt.Println(err)
		fmt.Println(p)
	}

	fmt.Println("====================")

}
