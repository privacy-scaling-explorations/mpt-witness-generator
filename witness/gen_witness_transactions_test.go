package witness

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/privacy-scaling-explorations/mpt-witness-generator/trie"
	"github.com/privacy-scaling-explorations/mpt-witness-generator/types"
)

func TestTransactions(t *testing.T) {
	txs := make([]*types.Transaction, 70)
	key, _   := crypto.GenerateKey()
	signer := types.LatestSigner(params.TestChainConfig)

	for i := range txs {
		amount := math.BigPow(2, int64(i))
		price := big.NewInt(300000)
		data := make([]byte, 100)
		tx := types.NewTransaction(uint64(i), common.Address{}, amount, 123457, price, data)
		signedTx, err := types.SignTx(tx, signer, key)
		if err != nil {
			panic(err)
		}
		txs[i] = signedTx
	}

	stackTrie := types.UpdateStackTrie(types.Transactions(txs), trie.NewStackTrie(nil))

	fmt.Println(stackTrie)
}

