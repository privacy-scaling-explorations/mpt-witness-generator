package witness

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
    Address []byte `json:"address"`
    ListRlpBytes [2][]byte `json:"list_rlp_bytes"`
    ValueRlpBytes [2][]byte `json:"value_rlp_bytes"`
    ValueListRlpBytes [2][]byte `json:"value_list_rlp_bytes"`
    DriftedRlpBytes []byte `json:"drifted_rlp_bytes"`
    WrongRlpBytes []byte `json:"wrong_rlp_bytes"`
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