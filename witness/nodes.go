package witness

import (
	"fmt"
	"strings"
)

type BranchNode struct {
    ModifiedIndex int `json:"modified_index"`
    DriftedIndex int `json:"drifted_index"`
    ListRlpBytes [2][]byte `json:"list_rlp_bytes"`
}

type ExtensionNode struct {
   ListRlpBytes []byte `json:"list_rlp_bytes"`
}

type StartNode struct {
    ProofType string `json:"proof_type"`
}

type ExtensionBranchNode struct {
    IsExtension bool `json:"is_extension"`
    IsPlaceholder [2]bool `json:"is_placeholder"`
    Extension ExtensionNode `json:"extension"`
    Branch BranchNode `json:"branch"`
}

type AccountNode struct {
    Address []byte
    ListRlpBytes [2][]byte
    ValueRlpBytes [2][]byte
    ValueListRlpBytes [2][]byte
    DriftedRlpBytes []byte
    WrongRlpBytes []byte
}

// When marshalling, []byte encodes as a base64-encoded string.
func base64ToString(bs []byte) string {
    var s string
    if bs == nil {
        s = "null"
    } else {
        s = strings.Join(strings.Fields(fmt.Sprintf("%d", bs)), ",")
    }

    return s
}

func (n *AccountNode) MarshalJSON() ([]byte, error) {
    address := base64ToString(n.Address) 
    listRlpBytes1 := base64ToString(n.ListRlpBytes[0]) 
    listRlpBytes2 := base64ToString(n.ListRlpBytes[1]) 
    valueRlpBytes1 := base64ToString(n.ValueRlpBytes[0]) 
    valueRlpBytes2 := base64ToString(n.ValueRlpBytes[1]) 
    valueListRlpBytes1 := base64ToString(n.ValueListRlpBytes[0]) 
    valueListRlpBytes2 := base64ToString(n.ValueListRlpBytes[1]) 
    driftedRlpBytes := base64ToString(n.DriftedRlpBytes) 
    wrongRlpBytes := base64ToString(n.WrongRlpBytes) 
    jsonResult := fmt.Sprintf(`{"address":%s, "list_rlp_bytes":[%s,%s], "value_rlp_bytes":[%s,%s], "value_list_rlp_bytes":[%s,%s], "drifted_rlp_bytes":%s, "wrong_rlp_bytes":%s}`,
        address, listRlpBytes1, listRlpBytes2, valueRlpBytes1, valueRlpBytes2, valueListRlpBytes1, valueListRlpBytes2,
        driftedRlpBytes, wrongRlpBytes)
    return []byte(jsonResult), nil
}

type StorageNode struct {
    ListRlpBytes [2][]byte `json:"list_rlp_bytes"`
    ValueRlpBytes [2][]byte `json:"value_rlp_bytes"`
    DriftedRlpBytes []byte `json:"drifted_rlp_bytes"`
    WrongRlpBytes []byte `json:"wrong_rlp_bytes"`
}

/*
Note: using pointers for fields to be null when not set (otherwise the field is set to default value
when marshalling).
*/
type Node struct {
    Start *StartNode `json:"start"`
    ExtensionBranch *ExtensionBranchNode `json:"extension_branch"`
    Account *AccountNode `json:"account"`
    Storage *StorageNode `json:"storage"`
    Values[][]byte `json:"values"`
}

/*
s := StartNode {
	ProofType: "StorageChanged",
}

n := Node {
	Start: &s,
}

b, err := json.Marshal(n)
if err != nil {
	fmt.Println(err)
}
fmt.Println(string(b))
*/