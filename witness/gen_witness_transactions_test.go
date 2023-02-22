package witness

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/privacy-scaling-explorations/mpt-witness-generator/trie"
	"github.com/privacy-scaling-explorations/mpt-witness-generator/types"
)

func createTransaction(ind int) *types.Transaction {
	key, _   := crypto.GenerateKey()
	signer := types.LatestSigner(params.TestChainConfig)

	amount := math.BigPow(2, int64(ind))
	price := big.NewInt(300000)
	data := make([]byte, 100)
	tx := types.NewTransaction(uint64(ind), common.Address{}, amount, 123457, price, data)
	signedTx, err := types.SignTx(tx, signer, key)
	if err != nil {
		panic(err)
	}

	return signedTx
}

func TestTransactions(t *testing.T) {
	db := rawdb.NewMemoryDatabase()

	tx1 := createTransaction(1)
	tx2 := createTransaction(2)
	txs1 := []*types.Transaction{tx1, tx2}
	stackTrie := types.UpdateStackTrie(types.Transactions(txs1), trie.NewStackTrie(db))

	k := []byte{0, 3}
	proof1, err := stackTrie.Prove(db, k)
	check(err)

	tx3 := createTransaction(3)
	txs2 := []*types.Transaction{tx3}
	stackTrie = types.UpdateStackTrie(types.Transactions(txs2), stackTrie)

	k = []byte{0, 3}
	proof2, err := stackTrie.Prove(db, k)
	check(err)

	fmt.Println(proof1)
	fmt.Println("===")
	fmt.Println(proof2)
}

