package witness

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/miha-stopar/mpt/trie"
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
	Jsonrpc string       `json:"jsonrpc"`
	Id      uint64       `json:"id"`
	Result  types.Header `json:"result"`
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

func GetBlock() {
	blockNumber := big.NewInt(int64(13284470))
	r := jsonreq{Jsonrpc: "2.0", Method: "eth_getBlockByNumber", Id: 1}
	r.Params = make([]interface{}, 2)
	r.Params[0] = fmt.Sprintf("0x%x", blockNumber.Int64())
	r.Params[1] = true
	jsonData, _ := json.Marshal(r)

	fmt.Println(jsonData)

	jr := jsonrespt{}
	err := json.NewDecoder(getAPI(jsonData)).Decode(&jr)
	fmt.Println(err)
	blockHeader := types.Header(jr.Result)

	blockHeaderRlp, _ := rlp.EncodeToBytes(blockHeader)
	// hash := crypto.Keccak256Hash(blockHeaderRlp)
	// preimages[hash] = blockHeaderRlp

	fmt.Println("================")
	fmt.Println(blockHeaderRlp)

	triedb := trie.NewDatabase(blockHeader)
	tt, _ := trie.New(blockHeader.TxHash, &triedb)

	// statedb, _ := state.New(blockHeader.Root, database, nil)

	fmt.Println("================")
	fmt.Println(tt)

}

func Accounts() {
	blockNumber := big.NewInt(int64(13284470))
	r := jsonreq{Jsonrpc: "2.0", Method: "eth_getBlockByNumber", Id: 1}
	r.Params = make([]interface{}, 2)
	r.Params[0] = fmt.Sprintf("0x%x", blockNumber.Int64())
	r.Params[1] = true
	jsonData, _ := json.Marshal(r)

	fmt.Println(jsonData)

	jr := jsonrespt{}
	err := json.NewDecoder(getAPI(jsonData)).Decode(&jr)
	fmt.Println(err)
	blockHeader := types.Header(jr.Result)

	PrefetchAccount(blockHeader.Number, common.Address{}, nil)
}

func PrefetchAccount(blockNumber *big.Int, addr common.Address, postProcess func(map[common.Hash][]byte)) {
	key := fmt.Sprintf("proof_%d_%s", blockNumber, addr)
	if cached[key] {
		return
	}
	cached[key] = true

	ap := getProofAccount(blockNumber, addr, common.Hash{}, false)
	newPreimages := make(map[common.Hash][]byte)
	for _, s := range ap {
		ret, _ := hex.DecodeString(s[2:])
		hash := crypto.Keccak256Hash(ret)
		newPreimages[hash] = ret
	}

	if postProcess != nil {
		postProcess(newPreimages)
	}

	for hash, val := range newPreimages {
		trie.Preimages()[hash] = val
	}
}

func getProofAccount(blockNumber *big.Int, addr common.Address, skey common.Hash, storage bool) []string {
	addrHash := crypto.Keccak256Hash(addr[:])
	unhashMap[addrHash] = addr

	r := jsonreq{Jsonrpc: "2.0", Method: "eth_getProof", Id: 1}
	r.Params = make([]interface{}, 3)
	r.Params[0] = addr
	r.Params[1] = [1]common.Hash{skey}
	r.Params[2] = fmt.Sprintf("0x%x", blockNumber.Int64())
	jsonData, _ := json.Marshal(r)
	jr := jsonresp{}
	json.NewDecoder(getAPI(jsonData)).Decode(&jr)

	if storage {
		return jr.Result.StorageProof[0].Proof
	} else {
		return jr.Result.AccountProof
	}
}

func getAPI(jsonData []byte) io.Reader {
	key := hexutil.Encode(crypto.Keccak256(jsonData))
	if cacheExists(key) {
		return bytes.NewReader(cacheRead(key))
	}
	resp, _ := http.Post(nodeUrl, "application/json", bytes.NewBuffer(jsonData))
	defer resp.Body.Close()
	ret, _ := ioutil.ReadAll(resp.Body)
	cacheWrite(key, ret)
	return bytes.NewReader(ret)
}
