package witness

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/miha-stopar/mpt/oracle"
)

var nodeUrl = "https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161"

var unhashMap = make(map[common.Hash]common.Address)

func unhash(addrHash common.Hash) common.Address {
	return unhashMap[addrHash]
}

var cached = make(map[string]bool)

type jsonreq struct {
	Jsonrpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	Id      uint64        `json:"id"`
}

type jsonresp struct {
	Jsonrpc string        `json:"jsonrpc"`
	Id      uint64        `json:"id"`
	Result  AccountResult `json:"result"`
}

type jsonresps struct {
	Jsonrpc string `json:"jsonrpc"`
	Id      uint64 `json:"id"`
	Result  string `json:"result"`
}

type jsonrespi struct {
	Jsonrpc string         `json:"jsonrpc"`
	Id      uint64         `json:"id"`
	Result  hexutil.Uint64 `json:"result"`
}

type jsonrespt struct {
	Jsonrpc string        `json:"jsonrpc"`
	Id      uint64        `json:"id"`
	Result  oracle.Header `json:"result"`
}

// Result structs for GetProof
type AccountResult struct {
	Address      common.Address  `json:"address"`
	AccountProof []string        `json:"accountProof"`
	Balance      *hexutil.Big    `json:"balance"`
	CodeHash     common.Hash     `json:"codeHash"`
	Nonce        hexutil.Uint64  `json:"nonce"`
	StorageHash  common.Hash     `json:"storageHash"`
	StorageProof []StorageResult `json:"storageProof"`
}

type StorageResult struct {
	Key   string       `json:"key"`
	Value *hexutil.Big `json:"value"`
	Proof []string     `json:"proof"`
}

func toFilename(key string) string {
	return fmt.Sprintf("/tmp/eth/json_%s", key)
}

func cacheRead(key string) []byte {
	dat, err := ioutil.ReadFile(toFilename(key))
	if err == nil {
		return dat
	}
	panic("cache missing")
}

func cacheExists(key string) bool {
	_, err := os.Stat(toFilename(key))
	return err == nil
}

func cacheWrite(key string, value []byte) {
	ioutil.WriteFile(toFilename(key), value, 0644)
}

func GetBlocks() {
	blockNum := 13284470
	blockNumberParent := big.NewInt(int64(blockNum))
	blockNumber := big.NewInt(int64(blockNum + 1))

	pkw := oracle.PreimageKeyValueWriter{}
	pkwtrie := trie.NewStackTrie(pkw)

	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	blockHeader := oracle.PrefetchBlock(blockNumber, false, pkwtrie)

	fmt.Println(blockHeaderParent.Root)
	fmt.Println(blockHeader)

	addr := common.HexToAddress("0xA0c68C638235ee32657e8f720a23ceC1bFc77C77")
	fmt.Println(addr)

	db := rawdb.NewMemoryDatabase()
	// statedb, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	dbb := state.NewDatabase(db)
	statedb, err := state.New(blockHeaderParent.Root, dbb, nil)
	if err != nil {
		panic(err)
	}

	statedb.AddBalance(addr, big.NewInt(int64(17)))
	k := common.BigToHash(big.NewInt(int64(13)))
	v := common.BigToHash(big.NewInt(int64(300)))
	statedb.SetState(addr, k, v)

	statedb.Commit(false)
	fmt.Println("====================")
	/*
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	*/

	/*
		db := trie.NewDatabase(memorydb.New())
		trie, _ := trie.New(blockHeader.Root, db)

		// accountProof := oracle.PrefetchAccount(blockNumberParent, common.Address{}, nil)
		accountProof := oracle.PrefetchAccount(blockNumberParent, addr, nil)

		for key, element := range oracle.Preimages() {
			k := key.Bytes()
			trie.TryUpdate(k, element)
		}

		fmt.Println(accountProof)

		fmt.Println(trie)
	*/
}
