package main

import "C"
import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/miha-stopar/mpt/witness"
)

// "github.com/miha-stopar/mpt/oracle"
// "github.com/miha-stopar/mpt/state"
// "github.com/miha-stopar/mpt/witness"

type Config struct {
	Keys []string `json:"Keys"`
	Values []string `json:"Values"`
	ToBeModifiedKey string `json:"ToBeModifiedKey"`
	ToBeModifiedValue string `json:"ToBeModifiedValue"`
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

	v := common.BigToHash(big.NewInt(int64(17)))
	addr := common.HexToAddress("0xaaaccf12580138bc2bbceeeaa111df4e42ab81ff")

	witness.UpdateStateAndGenProofs("UpdateOneLevel", keys[:], values,
		common.HexToHash(config.ToBeModifiedKey), v, addr)

	return C.CString("test")
}

func main() {}
