package main

import "C"

// "github.com/miha-stopar/mpt/oracle"
// "github.com/miha-stopar/mpt/state"
// "github.com/miha-stopar/mpt/witness"

//export GetProofs
func GetProofs(path string) *C.char {
// func GetProofs(keys, values []common.Hash, toBeModified, value common.Hash, addr common.Address) {
	/*
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)

	for i := 0; i < len(keys); i++ {
		statedb.SetState(addr, keys[i], values[i])
	}
	witness.GetBeforeAfterProof(toBeModified, value, addr, statedb)
	*/
	return C.CString("test")
}

func main() {}
