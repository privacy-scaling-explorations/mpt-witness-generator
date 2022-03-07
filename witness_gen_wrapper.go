package main

import "C"
import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/miha-stopar/mpt/witness"
)

type Config struct {
	NodeUrl string `json:"NodeUrl"`
	BlockNum int `json:"BlockNum"`
	Keys []string `json:"Keys"`
	Values []string `json:"Values"`
}

//export GetProofs
func GetProofs(proofConf *C.char) *C.char {
	var config Config

	err := json.Unmarshal([]byte(C.GoString(proofConf)), &config)
	fmt.Println(err)

	fmt.Println(config)

	keys := []common.Hash{}
	values := []common.Hash{}

	for i := 0; i < len(config.Keys); i++ {
		keys = append(keys, common.HexToHash(config.Keys[i]))
		values = append(values, common.HexToHash(config.Values[i]))
	}

	addr := common.HexToAddress("0xaaaccf12580138bc2bbceeeaa111df4e42ab81ff")

	proof := witness.GetProof(config.NodeUrl, config.BlockNum, keys[:], values, addr)

	return C.CString(proof)
}

func main() {}
