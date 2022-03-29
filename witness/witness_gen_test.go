package witness

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/miha-stopar/mpt/oracle"
	"github.com/miha-stopar/mpt/state"
)

func TestUpdateOneLevel(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// We have a branch with children at position 3 and 11.

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	// This key is turned into odd length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	toBeModified := ks[0]
	v := common.BigToHash(big.NewInt(int64(17)))
	addr := common.HexToAddress("0xaaaccf12580138bc2bbceeeaa111df4e42ab81ff")
	UpdateStateAndGenProof("UpdateOneLevel", ks[:], values, []common.Address{addr, addr}, []common.Hash{toBeModified}, []common.Hash{v}, []common.Address{addr})
}

func TestUpdateOneLevel1(t *testing.T) {
	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81c9")
	// This address is turned into odd length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	// This is a storage slot that will be modified (the list will come from bus-mapping):
	toBeModified := ks[1]
	val := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("UpdateOneLevel", ks[:], values, []common.Address{addr, addr}, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestUpdateOneLevelBigVal(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// We have a branch with children at position 3 and 11.

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	// This key is turned into odd length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	toBeModified := ks[0]
	// big value so that RLP is longer than 55 bytes
	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	addr := common.HexToAddress("0xaaaccf12580138bc2bbceeeaa826df4e42ab81ff")
	UpdateStateAndGenProof("UpdateOneLevelBigVal", ks[:], values, []common.Address{addr, addr}, []common.Hash{toBeModified}, []common.Hash{v2}, []common.Address{addr})
}

func TestUpdateTwoLevels(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x11"), common.HexToHash("0x12"), common.HexToHash("0x21")} // this has three levels
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// First we have a branch with children at position 3 and 11.
	// The third storage change happens at key:
	// [3,10,6,3,5,7,...
	// That means leaf at position 3 turns into branch with children at position 1 and 10.
	// ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	// This key is turned into even length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	toBeModified := ks[0]
	v := common.BigToHash(big.NewInt(int64(17)))
	addr := common.HexToAddress("0xaaaccf12580138bc2bbc957aa826df4e42ab81ff")
	UpdateStateAndGenProof("UpdateTwoLevels", ks[:], values, []common.Address{addr, addr, addr},  []common.Hash{toBeModified}, []common.Hash{v}, []common.Address{addr})
}

func TestUpdateTwoLevelsBigVal(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x11"), common.HexToHash("0x12"), common.HexToHash("0x21")} // this has three levels
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// First we have a branch with children at position 3 and 11.
	// The third storage change happens at key:
	// [3,10,6,3,5,7,...
	// That means leaf at position 3 turns into branch with children at position 1 and 10.
	// ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	// This key is turned into even length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	toBeModified := ks[0]

	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	addr := common.HexToAddress("0xaaaccf12580138bc2bbc957aa826df4e42ab81ff")
	UpdateStateAndGenProof("UpdateTwoLevelsBigVal", ks[:], values, []common.Address{addr, addr, addr}, []common.Hash{toBeModified}, []common.Hash{v2}, []common.Address{addr})
}

func TestUpdateThreeLevels(t *testing.T) {
	ks := [...]common.Hash{
		common.HexToHash("0x11"),
		common.HexToHash("0x12"),
		common.HexToHash("0x21"),
		common.HexToHash("0x31"),
		common.HexToHash("0x32"),
		common.HexToHash("0x33"),
		common.HexToHash("0x34"),
		common.HexToHash("0x35"),
		common.HexToHash("0x36"),
		common.HexToHash("0x37"),
		common.HexToHash("0x38"), //
		common.HexToHash("0x39"),
		common.HexToHash("0x40"),
		common.HexToHash("0x41"),
		common.HexToHash("0x42"),
		common.HexToHash("0x43"),
		common.HexToHash("0x44"),
		common.HexToHash("0x45"),
		common.HexToHash("0x46"),
	}
	/*
		ks[10] = 0x38 is at position 3 in root.Children[3].Children[8]

		nibbles
		[9,5,12,5,13,12,14,10,13,14,9,6,0,3,4,7,9,11,1,7,7,11,6,8,9,5,9,0,4,9,4,8,5,13,15,8,10,10,9,7,11,3,9,15,3,5,3,3,0,3,9,10,15,5,15,4,5,6,1,9,9,16]

		terminator flag 16 (last byte) is removed, then it remains len 61 (these are nibbles):
		[9,5,12,5,13,12,14,10,13,14,9,6,0,3,4,7,9,11,1,7,7,11,6,8,9,5,9,0,4,9,4,8,5,13,15,8,10,10,9,7,11,3,9,15,3,5,3,3,0,3,9,10,15,5,15,4,5,6,1,9,9]

		buf (31 len):
		this is key stored in leaf:
		[57,92,93,206,173,233,96,52,121,177,119,182,137,89,4,148,133,223,138,169,123,57,243,83,48,57,175,95,69,97,153]
	*/

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0xaaaccf12580138bc263c95757826df4e42ab81ff")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	toBeModified := ks[10]

	v := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("UpdateThreeLevels", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{v}, []common.Address{addr})
}

func TestFromNilToValue(t *testing.T) {
	ks := [...]common.Hash{
		common.HexToHash("0x11"),
		common.HexToHash("0x12"),
		common.HexToHash("0x21"),
		common.HexToHash("0x31"),
		common.HexToHash("0x32"),
		common.HexToHash("0x33"),
		common.HexToHash("0x34"),
		common.HexToHash("0x35"),
		common.HexToHash("0x36"),
		common.HexToHash("0x37"),
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e42ab81ff")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	// This test is similar as above, but the key that is being modified has not been used yet.

	toBeModified := common.HexToHash("0x38")

	v := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("FromNilToValue", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{v}, []common.Address{addr})
}

func TestDelete(t *testing.T) {
	ks := [...]common.Hash{
		common.HexToHash("0xaaaabbbbabab"),
		common.HexToHash("0xbaaabbbbabab"),
		common.HexToHash("0xcaaabbbbabab"),
		common.HexToHash("0xdaaabbbbabab"),
	}

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81ff")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	toBeModified := common.HexToHash("0xdaaabbbbabab")
	val := common.Hash{} // empty value deletes the key
	UpdateStateAndGenProof("Delete", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestUpdateOneLevelEvenAddress(t *testing.T) {
	addr := common.HexToAddress("0x25efbf12580138bc263c95757826df4e24eb81c9")
	// This address is turned into even length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	// This is a storage slot that will be modified (the list will come from bus-mapping):
	toBeModified := ks[1]
	val := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("UpdateOneLevelEvenAddress", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestAddBranch(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x11"), common.HexToHash("0x12")}
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// First we have a branch with children at position 3 and 11.
	// ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75acef12a01883c2b3fc57957826df4e24e8baaa")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	// This key is not in the trie yet, its nibbles:
	// [3,10,6,3,5,7,...
	// That means leaf at position 3 turns into branch with children at position 1 and 10.
	toBeModified := common.HexToHash("0x21")

	v := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("AddBranch", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{v}, []common.Address{addr})
}

func TestAddBranchLong(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x11"), common.HexToHash("0x12")}
	// hexed keys:
	// [3,1,14,12,12,...
	// [11,11,8,10,6,...
	// First we have a branch with children at position 3 and 11.
	// ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}

	var values []common.Hash
	// big value so that RLP will be longer than 55 bytes for the neighbouring node
	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	for i := 0; i < len(ks); i++ {
		values = append(values, v2)
	}
	addr := common.HexToAddress("0x75acef12a01883c2b3fc57957826df4e24e8b19c")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	// This key is not in the trie yet, its nibbles:
	// [3,10,6,3,5,7,...
	// That means leaf at position 3 turns into branch with children at position 1 and 10.
	toBeModified := common.HexToHash("0x21")

	v := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("AddBranchLong", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{v}, []common.Address{addr})
}

func TestDeleteBranch(t *testing.T) {
	h := common.HexToHash("0x11dd2277aa")

	ks := [...]common.Hash{
		common.HexToHash("0xaa"),
		common.HexToHash("0xabcc"),
		common.HexToHash("0xffdd"),
		common.HexToHash("0x11dd"),
		common.HexToHash("0x11dd22"),
		common.HexToHash("0x11dd2233"),
		common.HexToHash("0x11dd2255"),
		common.HexToHash("0x11dd2277"),
		h, // this leaf turns into a branch
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75acef12a0188c32b36c57957826df4e24e8b19c")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	toBeModified := h

	v := common.Hash{} // empty value deletes the key
	UpdateStateAndGenProof("DeleteBranch", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{v}, []common.Address{addr})
}

func TestDeleteBranchLong(t *testing.T) {
	h := common.HexToHash("0x11dd2277aa")

	ks := [...]common.Hash{
		common.HexToHash("0xaa"),
		common.HexToHash("0xabcc"),
		common.HexToHash("0xffdd"),
		common.HexToHash("0x11dd"),
		common.HexToHash("0x11dd22"),
		common.HexToHash("0x11dd2233"),
		common.HexToHash("0x11dd2255"),
		common.HexToHash("0x11dd2277"),
		h, // this leaf turns into a branch
	}

	var values []common.Hash
	// big value so that RLP will be longer than 55 bytes for the neighbouring node
	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	for i := 0; i < len(ks); i++ {
		values = append(values, v2)
	}
	addr := common.HexToAddress("0x75acef12a0188c32b36c57957826df4e24e8b19c")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}
	
	toBeModified := h

	v := common.Hash{} // empty value deletes the key
	UpdateStateAndGenProof("DeleteBranchLong", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{v}, []common.Address{addr})
}

func TestAddBranchTwoLevels(t *testing.T) {
	// Test for case when branch is added in the second level. So, instead of having only
	// branch1 with some nodes and then one of this nodes is replaced with a branch (that's
	// the case of TestAddBranch), we have here branch1 and then inside it another
	// branch: branch2. Inside brach2 we have a node which gets replaced by a branch.
	// This is to test cases when the key contains odd number of nibbles as well as
	// even number of nibbles.

	a := 1
	b := 1
	h := fmt.Sprintf("0xaa%d%d", a, b)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 33; i++ {
		// just some values to get the added branch in second level (found out trying different values)
		if i % 2 == 0 {
			a += 1
		} else {
			b += 1
		}
		if a == 4 && b == 3 {
			continue
		}
		h := fmt.Sprintf("0xaa%d%d", a, b)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75fbef12a0188c32b36c57957826df4e24e8b19c")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	toBeModified := common.HexToHash("0xaa43")

	v := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("AddBranchTwoLevels", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{v}, []common.Address{addr})
}

func TestAddBranchTwoLevelsLong(t *testing.T) {
	a := 1
	b := 1
	h := fmt.Sprintf("0xaa%d%d", a, b)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 33; i++ {
		// just some values to get the added branch in second level (found out trying different values)
		if i % 2 == 0 {
			a += 1
		} else {
			b += 1
		}
		if a == 4 && b == 3 {
			continue
		}
		h := fmt.Sprintf("0xaa%d%d", a, b)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	for i := 0; i < len(ks); i++ {
		values = append(values, v2)
	}
	addr := common.HexToAddress("0x75fbef1250188c32b63c57957826df4e24e8b19c")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	toBeModified := common.HexToHash("0xaa43")

	v := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("AddBranchTwoLevelsLong", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{v}, []common.Address{addr})
}

func TestDeleteBranchTwoLevels(t *testing.T) {
	a := 1
	b := 1
	h := fmt.Sprintf("0xaa%d%d", a, b)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 33; i++ {
		// just some values to get the added branch in second level (found out trying different values)
		if i % 2 == 0 {
			a += 1
		} else {
			b += 1
		}
		h := fmt.Sprintf("0xaa%d%d", a, b)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75fbef1250188c32b63c57957826df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	toBeModified := common.HexToHash("0xaa43")

	v := common.Hash{}
	UpdateStateAndGenProof("DeleteBranchTwoLevels", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{v}, []common.Address{addr})
}

func TestDeleteBranchTwoLevelsLong(t *testing.T) {
	a := 1
	b := 1
	h := fmt.Sprintf("0xaa%d%d", a, b)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 33; i++ {
		// just some values to get the added branch in second level (found out trying different values)
		if i % 2 == 0 {
			a += 1
		} else {
			b += 1
		}
		h := fmt.Sprintf("0xaa%d%d", a, b)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	v1 := common.FromHex("0xbbefaa12580138bc263c95757826df4e24eb81c9aaaaaaaaaaaaaaaaaaaaaaaa")
	v2 := common.BytesToHash(v1)
	for i := 0; i < len(ks); i++ {
		values = append(values, v2)
	}
	addr := common.HexToAddress("0x75fbef21508183c2b63c57957826df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	toBeModified := common.HexToHash("0xaa43")

	v := common.Hash{}
	UpdateStateAndGenProof("DeleteBranchTwoLevelsLong", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{v}, []common.Address{addr})
}

func TestExtensionOneKeyByteSel1(t *testing.T) {
	ks := [...]common.Hash{
		common.HexToHash("0x11"),
		common.HexToHash("0x12"),
		common.HexToHash("0x21"),
		common.HexToHash("0x31"),
		common.HexToHash("0x32"),
		common.HexToHash("0x33"),
		common.HexToHash("0x34"),
		common.HexToHash("0x35"),
		common.HexToHash("0x36"),
		common.HexToHash("0x37"),
		common.HexToHash("0x38"), //
		common.HexToHash("0x39"),
		common.HexToHash("0x40"),
		common.HexToHash("0x42"),
		common.HexToHash("0x43"),
		common.HexToHash("0x44"),
		common.HexToHash("0x45"),
		common.HexToHash("0x46"),
		common.HexToHash("0x47"),
		common.HexToHash("0x48"),
		common.HexToHash("0x50"),
		common.HexToHash("0x51"),
		common.HexToHash("0x52"),
		common.HexToHash("0x53"),
		common.HexToHash("0x54"),
		common.HexToHash("0x55"),
		common.HexToHash("0x56"),

		common.HexToHash("0x61"), // extension
	}

	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75fbef21508183c2b63c57957826df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}
	
	toBeModified := ks[len(ks)-1]
	val := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("ExtensionOneKeyByteSel1", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestExtensionAddedOneKeyByteSel1(t *testing.T) {
	a := 1
	b := 1
	h := fmt.Sprintf("0x%d%d", a, b)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 33; i++ {
		// just some values to get the added branch in second level (found out trying different values)
		if i % 2 == 0 {
			a += 1
		} else {
			b += 1
		}
		h := fmt.Sprintf("0x%d%d", a, b)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	toBeModified := common.HexToHash("0x1818")

	val := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("ExtensionAddedOneKeyByteSel1", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestExtensionDeletedOneKeyByteSel1(t *testing.T) {
	a := 1
	b := 1
	h := fmt.Sprintf("0x%d%d", a, b)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 33; i++ {
		// just some values to get the added branch in second level (found out trying different values)
		if i % 2 == 0 {
			a += 1
		} else {
			b += 1
		}
		h := fmt.Sprintf("0x%d%d", a, b)
		ks = append(ks, common.HexToHash(h))
	}
	toBeModified := common.HexToHash("0x1818")
	ks = append(ks, toBeModified)
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x50efbf12580138bc263c95757826df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	val := common.Hash{} // empty value deletes the key
	UpdateStateAndGenProof("ExtensionDeletedOneKeyByteSel1", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestExtensionOneKeyByteSel2(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0xca%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 876; i++ {
		a += 1
		h := fmt.Sprintf("0xca%d", a)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	toBeModified := common.HexToHash("0xca644")
	val := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("ExtensionOneKeyByteSel2", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestExtensionAddedOneKeyByteSel2(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0xca%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	toBeModifiedStr := "0xca644"
	toBeModified := common.HexToHash(toBeModifiedStr)
	for i := 0; i < 876; i++ {
		a += 1
		h := fmt.Sprintf("0xca%d", a)
		if h == toBeModifiedStr {
			continue
		}
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	val := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("ExtensionAddedOneKeyByteSel2", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestExtensionDeletedOneKeyByteSel2(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0xca%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	toBeModifiedStr := "0xca644"
	toBeModified := common.HexToHash(toBeModifiedStr)
	for i := 0; i < 876; i++ {
		a += 1
		h := fmt.Sprintf("0xca%d", a)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	val := common.Hash{} // empty value deletes the key
	UpdateStateAndGenProof("ExtensionDeletedOneKeyByteSel2", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestExtensionTwoKeyBytesSel1(t *testing.T) {
	// Extension node which has key longer than 1 (2 in this test). This is needed because RLP takes
	// different positions.
	// Key length > 1 (130 means there are two bytes for key; 160 means there are 32 hash values after it):
	// [228 130 0 149 160 ...
	// Key length = 1 (no byte specifying the length of key):
	// [226 16 160 ...
	a := 0
	h := fmt.Sprintf("0x%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 176; i++ {
		// just some values to get the extension with key length > 1 (found out trying different values)
		a += 1
		h := fmt.Sprintf("0x%d", a)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75fbef21508183c2b63c59757826df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	toBeModified := common.HexToHash("0x172")
	val := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("ExtensionTwoKeyBytesSel1", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestExtensionAddedTwoKeyBytesSel1(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0x%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	toBeModifiedStr := "0x172"
	toBeModified := common.HexToHash(toBeModifiedStr)
	for i := 0; i < 176; i++ {
		// just some values to get the extension with key length > 1 (found out trying different values)
		a += 1
		h := fmt.Sprintf("0x%d", a)
		if h == toBeModifiedStr {
			continue
		}
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75fbef21508183c2b63c59757826df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	val := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("ExtensionAddedTwoKeyBytesSel1", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestExtensionDeletedTwoKeyBytesSel1(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0x%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	toBeModifiedStr := "0x172"
	toBeModified := common.HexToHash(toBeModifiedStr)
	for i := 0; i < 176; i++ {
		// just some values to get the extension with key length > 1 (found out trying different values)
		a += 1
		h := fmt.Sprintf("0x%d", a)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75fbef21508183c2b63c59757826df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	val := common.Hash{} // empty value deletes the key
	UpdateStateAndGenProof("ExtensionDeletedTwoKeyBytesSel1", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestExtensionTwoKeyBytesSel2(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0x2ea%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 876; i++ {
		a += 1
		h := fmt.Sprintf("0x2ea%d", a)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	toBeModified := common.HexToHash("0x2ea772")
	val := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("ExtensionTwoKeyBytesSel2", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestExtensionAddedTwoKeyBytesSel2(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0x2ea%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	toBeModifiedStr := "0x2ea772"
	toBeModified := common.HexToHash(toBeModifiedStr)
	for i := 0; i < 876; i++ {
		a += 1
		h := fmt.Sprintf("0x2ea%d", a)
		if h == toBeModifiedStr {
			continue
		}
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	val := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("ExtensionAddedTwoKeyBytesSel2", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestExtensionDeletedTwoKeyBytesSel2(t *testing.T) {
	a := 0
	h := fmt.Sprintf("0x2ea%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	toBeModifiedStr := "0x2ea772"
	toBeModified := common.HexToHash(toBeModifiedStr)
	for i := 0; i < 876; i++ {
		a += 1
		h := fmt.Sprintf("0x2ea%d", a)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	val := common.Hash{} // empty value deletes the key
	UpdateStateAndGenProof("ExtensionDeletedTwoKeyBytesSel2", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

/*
func TestExtensionThreeBytesSel2(t *testing.T) {
	// still searching for the right values
	a := 0
	h := fmt.Sprintf("0xf8a%d", a)
	ks := []common.Hash{common.HexToHash(h)}
	for i := 0; i < 1000; i++ {
		a += 1
		h := fmt.Sprintf("0xf8a%d", a)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}

	toBeModified := common.HexToHash("0xfa935")
	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	val := common.BigToHash(big.NewInt(int64(17)))
	updateStateAndGetProofs("ExtensionThreeBytesSel2", ks[:], values, toBeModified, val, addr)
}
*/

func TestExtensionInFirstStorageLevel(t *testing.T) {
	ks := []common.Hash{common.HexToHash("0x12")}

	for i := 0; i < 10; i++ {
		h := fmt.Sprintf("0x%d", i)
		ks = append(ks, common.HexToHash(h))
	}
	
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x75fbef2150818c32b36c57957226df4e24eb81c9")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	toBeModified := common.HexToHash("0x1")
	val := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("ExtensionInFirstStorageLevel", ks[:], values, addresses, []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr})
}

func TestExtensionInFirstStorageLevelOneKeyByte(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50efbf12580138bc623c95757286df4e24eb81c9")

	key1 := common.HexToHash("0x12")
	val1 := common.BigToHash(big.NewInt(int64(1)))

	statedb.SetState(addr, key1, val1)

	h := fmt.Sprintf("0x%d", 1)
	key2 := common.HexToHash(h)
	statedb.SetState(addr, key2, val1)
	statedb.IntermediateRoot(false)

	toBeModified := common.HexToHash("0x1")
	val := common.BigToHash(big.NewInt(int64(17)))
	GenerateProof("ExtensionInFirstStorageLevelOneKeyByte", []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr}, statedb)
}

func TestExtensionAddedInFirstStorageLevelOneKeyByte(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50efbf12580138bc623c95757286df4e24eb81c9")

	key1 := common.HexToHash("0x12")
	val1 := common.BigToHash(big.NewInt(int64(1)))

	statedb.SetState(addr, key1, val1)

	toBeModified := common.HexToHash("0x1")
	// statedb.SetState(addr, toBeModified, val1)
	statedb.IntermediateRoot(false)

	val := common.BigToHash(big.NewInt(int64(17)))
	GenerateProof("ExtensionAddedInFirstStorageLevelOneKeyByte", []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr}, statedb)
}

func TestExtensionInFirstStorageLevelTwoKeyBytes(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50efbf12580138bc623c95757286df4e24eb81c9")

	key1 := common.HexToHash("0x12")
	val1 := common.BigToHash(big.NewInt(int64(1)))

	statedb.SetState(addr, key1, val1)

	toBeModified := common.HexToHash("0xa617")
	statedb.SetState(addr, toBeModified, val1)
	statedb.IntermediateRoot(false)

	val := common.BigToHash(big.NewInt(int64(17)))
	GenerateProof("ExtensionInFirstStorageLevelTwoKeyBytes", []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr}, statedb)
}

func TestExtensionAddedInFirstStorageLevelTwoKeyBytes(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50efbf12580138bc623c95757286df4e24eb81c9")

	key1 := common.HexToHash("0x12")
	val1 := common.BigToHash(big.NewInt(int64(1)))

	statedb.SetState(addr, key1, val1)

	toBeModified := common.HexToHash("0xa617")
	// statedb.SetState(addr, toBeModified, val1)
	statedb.IntermediateRoot(false)

	val := common.BigToHash(big.NewInt(int64(17)))
	GenerateProof("ExtensionAddedInFirstStorageLevelTwoKeyBytes", []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr}, statedb)
}


func TestExtensionThreeKeyBytesSel2(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50feb1f2580138bc623c97557286df4e24eb81c9")

	for i := 0; i < 14; i++ {
		h := fmt.Sprintf("0x%d", i)
		key2 := common.HexToHash(h)
		val1 := common.BigToHash(big.NewInt(int64(1)))
		statedb.SetState(addr, key2, val1)
	}

	toBeModified := common.HexToHash("0x13234")
	val1 := common.BigToHash(big.NewInt(int64(1)))
	statedb.SetState(addr, toBeModified, val1)

	val := common.BigToHash(big.NewInt(int64(17)))
	GenerateProof("ExtensionThreeKeyBytesSel2", []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr}, statedb)
}

func TestExtensionAddedThreeKeyBytesSel2(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50feb1f2580138bc623c97557286df4e24eb81c9")

	for i := 0; i < 14; i++ {
		h := fmt.Sprintf("0x%d", i)
		key2 := common.HexToHash(h)
		val1 := common.BigToHash(big.NewInt(int64(1)))
		statedb.SetState(addr, key2, val1)
	}

	toBeModified := common.HexToHash("0x13234")

	val := common.BigToHash(big.NewInt(int64(17)))
	GenerateProof("ExtensionAddedThreeKeyBytesSel2", []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr}, statedb)
}

func TestExtensionDeletedThreeKeyBytesSel2(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50feb1f2580138bc623c97557286df4e24eb81c9")

	for i := 0; i < 14; i++ {
		h := fmt.Sprintf("0x%d", i)
		key2 := common.HexToHash(h)
		val1 := common.BigToHash(big.NewInt(int64(1)))
		statedb.SetState(addr, key2, val1)
	}

	toBeModified := common.HexToHash("0x13234")
	val1 := common.BigToHash(big.NewInt(int64(1)))
	statedb.SetState(addr, toBeModified, val1)

	val := common.Hash{} // empty value deletes the key
	GenerateProof("ExtensionDeletedThreeKeyBytesSel2", []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr}, statedb)
}

func TestExtensionThreeKeyBytes(t *testing.T) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	addr := common.HexToAddress("0x50fbe1f25aa0843b623c97557286df4e24eb81c9")

	for i := 0; i < 140; i++ {
		h := fmt.Sprintf("0x%d", i)
		key2 := common.HexToHash(h)
		val1 := common.BigToHash(big.NewInt(int64(1)))
		statedb.SetState(addr, key2, val1)
	}

	// Let's get a key which makes extension node at the first level.
	// (set the breakpoint in trie.go, line 313)
	for i := 0; i < 1000; i++ {
		h := fmt.Sprintf("0x2111d%d", i)
		key2 := common.HexToHash(h)
		val1 := common.BigToHash(big.NewInt(int64(1)))
		statedb.SetState(addr, key2, val1)
		statedb.IntermediateRoot(false)

		// v := common.Hash{} // empty value deletes the key
		// statedb.SetState(addr, key2, v)
	}

	toBeModified := common.HexToHash("0x333")
	val := common.BigToHash(big.NewInt(int64(17)))
	GenerateProof("ExtensionThreeKeyBytes", []common.Hash{toBeModified}, []common.Hash{val}, []common.Address{addr}, statedb)
}

func TestOnlyLeafInStorageProof(t *testing.T) {
	blockNum := 14209217
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	
	h := fmt.Sprintf("0x%d", 0)
	addr := common.HexToAddress(h)
	// statedb.IntermediateRoot(false)
	statedb.CreateAccount(addr)

	accountProof, _, _, err := statedb.GetProof(addr)
	fmt.Println(len(accountProof))
	check(err)
	
	h = fmt.Sprintf("0x2111d%d", 0)
	key2 := common.HexToHash(h)
	val1 := common.BigToHash(big.NewInt(int64(1)))
	statedb.SetState(addr, key2, val1)
	statedb.IntermediateRoot(false)

	// storageProof, _, _, err := statedb.GetStorageProof(addr, key2)
	// check(err)

	val := common.BigToHash(big.NewInt(int64(17)))
	GenerateProof("OnlyLeafInStorageProof", []common.Hash{key2}, []common.Hash{val}, []common.Address{addr}, statedb)
}

/*
func TestFindAccount(t *testing.T) {
	blockNum := 0
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)
	
	for i := 14000; i < 17000; i++ {
		h := fmt.Sprintf("0x%d", i)
		addr := common.HexToAddress(h)
		// statedb.IntermediateRoot(false)
		// statedb.CreateAccount(addr)

		if statedb.GetCode(addr) == nil {
			continue
		}
		accountProof, _, _, err := statedb.GetProof(addr)
		fmt.Println(len(accountProof))
		check(err)
		fmt.Println(len(accountProof))
		if len(accountProof) < 2 {
			fmt.Println(len(accountProof))
			fmt.Println("asdfsadf")
		}

		for i := 0; i < 1000; i++ {
			h := fmt.Sprintf("0x2111d%d", i)
			key2 := common.HexToHash(h)
			val1 := common.BigToHash(big.NewInt(int64(1)))
			statedb.SetState(addr, key2, val1)
			statedb.IntermediateRoot(false)

			storageProof, _, _, err := statedb.GetStorageProof(addr, key2)
			check(err)
			fmt.Println(len(storageProof))

			v := common.Hash{} // empty value deletes the key
			statedb.SetState(addr, key2, v)
			statedb.IntermediateRoot(false)
		}
	}
}
*/

func TestFoo(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0x4E5B2e1dc63F6b91cb6Cd759936495434C7e972F")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	nodeUrl := "https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161"
	blockNum := 14359865

	GetProof(nodeUrl, blockNum, ks[:], values, addresses)
}

func TestUpdateTwoModifications(t *testing.T) {
	ks := [...]common.Hash{common.HexToHash("0x12"), common.HexToHash("0x21")}
	var values []common.Hash
	for i := 0; i < len(ks); i++ {
		values = append(values, common.BigToHash(big.NewInt(int64(i + 1)))) // don't put 0 value because otherwise nothing will be set (if 0 is prev value), see state_object.go line 279
	}
	addr := common.HexToAddress("0xaaaccf12580138bc2bbceeeaa111df4e42ab81ff")
	var addresses []common.Address
	for i := 0; i < len(ks); i++ {
		addresses = append(addresses, addr)
	}

	// This key is turned into odd length (see hexToCompact in encoding.go to see
	// odd and even length are handled differently)
	toBeModified1 := ks[0]
	v1 := common.BigToHash(big.NewInt(int64(17)))
	toBeModified2 := ks[1]
	v2 := common.BigToHash(big.NewInt(int64(17)))
	UpdateStateAndGenProof("UpdateTwoModifications", ks[:], values, addresses, []common.Hash{toBeModified1, toBeModified2}, []common.Hash{v1, v2}, []common.Address{addr, addr})
}