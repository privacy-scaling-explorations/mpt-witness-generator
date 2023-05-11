package witness

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/privacy-scaling-explorations/mpt-witness-generator/oracle"
	"github.com/privacy-scaling-explorations/mpt-witness-generator/state"
	"github.com/privacy-scaling-explorations/mpt-witness-generator/trie"
)

const branchNodeRLPLen = 2 // we have two positions for RLP meta data
const branch2start = branchNodeRLPLen + 32
const branchRows = 19 // 1 (init) + 16 (children) + 2 (extension S and C)

const accountLeafRows = 8
const storageLeafRows = 6
const counterLen = 4

// rowLen - each branch node has 2 positions for RLP meta data and 32 positions for hash
const rowLen = branch2start + 2 + 32 + 1 // +1 is for info about what type of row is it
const valueLen = 34
const keyPos = 10
const isBranchSPlaceholderPos = 11
const isBranchCPlaceholderPos = 12
const driftedPos = 13
const isExtensionPos = 14
// extension key even or odd is about nibbles - that determines whether the first byte (not
// considering RLP bytes) is 0 or 1 (see encoding.go hexToCompact)
const isBranchC16Pos = 19
const isBranchC1Pos = 20
const isExtShortC16Pos = 21
const isExtShortC1Pos = 22
const isExtLongEvenC16Pos = 23
const isExtLongEvenC1Pos = 24
const isExtLongOddC16Pos = 25
const isExtLongOddC1Pos = 26
// short/long means having one or more than one nibbles
const isSExtLongerThan55Pos = 27
const isCExtLongerThan55Pos = 28
const isBranchSNonHashedPos = 29
const isBranchCNonHashedPos = 30
const isExtNodeSNonHashedPos = 31
const isExtNodeCNonHashedPos = 32

// nibbles_counter_pos = 33, set in the assign function.

const isInsertedExtNodeS = 34
const isInsertedExtNodeC = 35
const isShortExtNodeBranch = 36

/*
Info about row type (given as the last element of the row):
0: init branch (such a row contains RLP info about the branch node; key)
1: branch child
2: storage leaf s key
3: storage leaf c key
5: hash to be computed (for example branch RLP whose hash needs to be checked in the parent)
6: account leaf key S
4: account leaf key C
7: account leaf nonce balance S
8: account leaf nonce balance C
9: account leaf root codehash S
10: account leaf neighbouring leaf
11: account leaf root codehash C
13: storage leaf s value
14: storage leaf c value
15: neighbouring storage leaf (when leaf turned into branch)
16: extension node S
17: extension node C
18: non existing account
19: non existing storage
20: modified extension node S before modification
21: modified extension node C before modification
22: modified extension node S after modification
23: modified extension node C after modification
24: modified extension node before modification selectors
25: modified extension node after modification selectors
*/

const (
	BranchInitRow = iota
	BranchChildRow
	StorageLeafKeySRow
	StorageLeafKeyCRow
	AccountLeafKeyCRow // 4
	HashRow
	AccountLeafKeySRow // 6
	// TODO
)

type AccountRowType int64
const (
	AccountKeyS AccountRowType = iota
    AccountKeyC
    AccountNonceS
    AccountBalanceS
    AccountStorageS
    AccountCodehashS
    AccountNonceC
    AccountBalanceC
    AccountStorageC
    AccountCodehashC
    AccountDrifted
    AccountWrong	
)

// TODO: replace with ProofType
type ModType int64
const (
	StorageMod ModType = iota
	NonceMod
	BalanceMod
	CodeHashMod
	CreateAccount
	DeleteAccount
	NonExistingAccount
	NonExistingStorage
)

type TrieModification struct {
	Type     ModType
	Key      common.Hash
	Value    common.Hash
	Address  common.Address
	Nonce    uint64
	Balance  *big.Int
	CodeHash []byte
}

/*
type ProofType int64
const (
    Disabled ProofType = iota
    NonceChanged
    BalanceChanged
    CodeHashExists
    AccountDestructed
    AccountDoesNotExist
    StorageChanged
    StorageDoesNotExist
)
*/

// addForHashing takes the stream of bytes and append a byte to it that marks this stream
// to be hashed and put into keccak lookup table that is to be used by MPT circuit.
func addForHashing(toBeHashed []byte, toBeHashedCollection *[][]byte) {
	forHashing := make([]byte, len(toBeHashed))
	copy(forHashing, toBeHashed)
	forHashing = append(forHashing, HashRow)
	*toBeHashedCollection = append(*toBeHashedCollection, forHashing)
}

// GetWitness is to be used by external programs to generate the witness. 
func GetWitness(nodeUrl string, blockNum int, trieModifications []TrieModification) [][]byte {
	blockNumberParent := big.NewInt(int64(blockNum))
	oracle.NodeUrl = nodeUrl
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)

	for i := 0; i < len(trieModifications); i++ {
		// TODO: remove SetState (using it now just because this particular key might
		// not be set and we will obtain empty storageProof)
		v := common.BigToHash(big.NewInt(int64(17)))
		statedb.SetState(trieModifications[i].Address, trieModifications[i].Key, v)
		// TODO: enable GetState to get the preimages -
		// GetState calls GetCommittedState which calls PrefetchStorage to get the preimages
		// statedb.GetState(addr, keys[i])
	}

	return obtainTwoProofsAndConvertToWitness(trieModifications, statedb, 0)
}

func obtainAccountProofAndConvertToWitness(i int, tMod TrieModification, tModsLen int, statedb *state.StateDB, specialTest byte) ([][]byte, [][]byte) {
	statedb.IntermediateRoot(false)

	addr := tMod.Address
	addrh := crypto.Keccak256(addr.Bytes())
	accountAddr := trie.KeybytesToHex(addrh)

	// This needs to called before oracle.PrefetchAccount, otherwise oracle.PrefetchAccount
	// will cache the proof and won't return it.
	// Calling oracle.PrefetchAccount after statedb.SetStateObjectIfExists is needed only
	// for cases when statedb.loadRemoteAccountsIntoStateObjects = false.
	statedb.SetStateObjectIfExists(tMod.Address)

	oracle.PrefetchAccount(statedb.Db.BlockNumber, tMod.Address, nil)
	accountProof, aNeighbourNode1, aExtNibbles1, isLastLeaf1, err := statedb.GetProof(addr)
	check(err)

	var startRoot common.Hash
	var finalRoot common.Hash

	var nodes []Node

	sRoot := statedb.GetTrie().Hash()
	if i == 0 {
		startRoot = sRoot
	}

	if tMod.Type == NonceMod {
		statedb.SetNonce(addr, tMod.Nonce)
	} else if tMod.Type == BalanceMod {
		statedb.SetBalance(addr, tMod.Balance)
	} else if tMod.Type == CodeHashMod {
		statedb.SetCode(addr, tMod.CodeHash)
	} else if tMod.Type == CreateAccount {
		statedb.CreateAccount(tMod.Address)
	} else if tMod.Type == DeleteAccount {
		statedb.DeleteAccount(tMod.Address)
	}
	// No statedb change in case of NonExistingAccount

	statedb.IntermediateRoot(false)

	cRoot := statedb.GetTrie().Hash()
	if i == tModsLen-1 {
		finalRoot = cRoot
	}
	
	accountProof1, aNeighbourNode2, aExtNibbles2, isLastLeaf2, err := statedb.GetProof(addr)
	check(err)

	if tMod.Type == NonExistingAccount && len(accountProof) == 0 {
		// If there is only one account in the state trie and we want to prove for some 
		// other account that it doesn't exist.
		// We get the root node (the only account) and put it as the only element of the proof,
		// it will act as a "wrong" leaf.
		account, err := statedb.GetTrieRootElement()
		check(err)
		accountProof = make([][]byte, 1)
		accountProof[0] = account
		accountProof1 = make([][]byte, 1)
		accountProof1[0] = account
	}

	addrh, accountAddr, accountProof, accountProof1, sRoot, cRoot = modifyAccountProofSpecialTests(addrh, accountAddr, sRoot, cRoot, accountProof, accountProof1, aNeighbourNode2, specialTest)	

	aNode := aNeighbourNode2
	isShorterProofLastLeaf := isLastLeaf1
	if len(accountProof) > len(accountProof1) {
		// delete operation
		aNode = aNeighbourNode1
		isShorterProofLastLeaf = isLastLeaf2
	}
	
	// TODO: CodeHashExists
	proofType := "NonceChanged"
	if tMod.Type == BalanceMod {
		proofType = "BalanceChanged"
	} else if tMod.Type == DeleteAccount {
		proofType = "AccountDestructed"
	} else if tMod.Type == NonExistingAccount {
		proofType = "AccountDoesNotExist"
	}
		
	nodes = append(nodes, GetStartNode(proofType, sRoot, cRoot))

	rowsState, toBeHashedAcc, nodesAccount, _ :=
		convertProofToWitness(statedb, addr, accountProof, accountProof1, aExtNibbles1, aExtNibbles2, accountAddr, aNode, true, tMod.Type == NonExistingAccount, false, isShorterProofLastLeaf)
	nodes = append(nodes, nodesAccount...)
	
	nodes = append(nodes, GetEndNode())

	// only for debugging
	storeNodes("AccountInFirstLevel", nodes)
	fmt.Println("=======================")

	proof := finalizeProof(i, rowsState, addrh, sRoot, cRoot, startRoot, finalRoot, tMod.Type)

	return proof, toBeHashedAcc
}

// obtainTwoProofsAndConvertToWitness obtains the GetProof proof before and after the modification for each
// of the modification. It then converts the two proofs into an MPT circuit witness. Witness is thus
// prepared for each of the modifications and the witnesses are chained together - the final root of
// the previous witness is the same as the start root of the current witness.
func obtainTwoProofsAndConvertToWitness(trieModifications []TrieModification, statedb *state.StateDB, specialTest byte) [][]byte {
	statedb.IntermediateRoot(false)
	allProofs := [][]byte{}
	toBeHashed := [][]byte{}	
	var startRoot common.Hash
	var finalRoot common.Hash

	var nodes []Node

	for i := 0; i < len(trieModifications); i++ {
		tMod := trieModifications[i]
		if tMod.Type == StorageMod || tMod.Type == NonExistingStorage {
			kh := crypto.Keccak256(tMod.Key.Bytes())
			if oracle.PreventHashingInSecureTrie {
				kh = tMod.Key.Bytes()
			}
			keyHashed := trie.KeybytesToHex(kh)

			addr := tMod.Address
			addrh := crypto.Keccak256(addr.Bytes())
			accountAddr := trie.KeybytesToHex(addrh)

			oracle.PrefetchAccount(statedb.Db.BlockNumber, tMod.Address, nil)
			// oracle.PrefetchStorage(statedb.Db.BlockNumber, addr, tMod.Key, nil)

			if specialTest == 1 {
				statedb.CreateAccount(addr)
			}
	
			accountProof, aNeighbourNode1, aExtNibbles1, aIsLastLeaf1, err := statedb.GetProof(addr)
			check(err)
			storageProof, neighbourNode1, extNibbles1, isLastLeaf1, err := statedb.GetStorageProof(addr, tMod.Key)
			check(err)

			sRoot := statedb.GetTrie().Hash()
			if i == 0 {
				startRoot = sRoot
			}

			if tMod.Type == StorageMod {
				statedb.SetState(addr, tMod.Key, tMod.Value)
				statedb.IntermediateRoot(false)
			}

			cRoot := statedb.GetTrie().Hash()
			if i == len(trieModifications)-1 {
				finalRoot = cRoot
			}

			proofType := "StorageChanged"
			if tMod.Type == NonExistingStorage {
				proofType = "StorageDoesNotExist"
			}
			
			s := StartNode {
				ProofType: proofType,
			}
			var values [][]byte
			values = append(values, sRoot.Bytes())
			values = append(values, cRoot.Bytes())
			n := Node {
				Start: &s,
				Values: values,
			}
			nodes = append(nodes, n)

			accountProof1, aNeighbourNode2, aExtNibbles2, aIsLastLeaf2, err := statedb.GetProof(addr)
			check(err)

			storageProof1, neighbourNode2, extNibbles2, isLastLeaf2, err := statedb.GetStorageProof(addr, tMod.Key)
			check(err)

			aNode := aNeighbourNode2
			aIsLastLeaf := aIsLastLeaf1
			if len(accountProof) > len(accountProof1) {
				// delete operation
				aNode = aNeighbourNode1
				aIsLastLeaf = aIsLastLeaf2
			}

			node := neighbourNode2
			isLastLeaf := isLastLeaf1
			if len(storageProof) > len(storageProof1) {
				// delete operation
				node = neighbourNode1
				isLastLeaf = isLastLeaf2
			}

			if (specialTest == 1) {
				if len(accountProof1) != 2 {
					panic("account should be in the second level (one branch above it)")
				}
				accountProof, accountProof1, sRoot, cRoot = modifyAccountSpecialEmptyTrie(addrh, accountProof1[len(accountProof1)-1])
			}
			
			rowsState, toBeHashedAcc, nodesAccount, _ :=
				convertProofToWitness(statedb, addr, accountProof, accountProof1, aExtNibbles1, aExtNibbles2, accountAddr, aNode, true, tMod.Type == NonExistingAccount, false, aIsLastLeaf)
			nodes = append(nodes, nodesAccount...)
			rowsStorage, toBeHashedStorage, nodesStorage, _ :=
				convertProofToWitness(statedb, addr, storageProof, storageProof1, extNibbles1, extNibbles2, keyHashed, node, false, false, tMod.Type == NonExistingStorage, isLastLeaf)
			nodes = append(nodes, nodesStorage...)

			fmt.Println("=========")
			fmt.Println(nodes)
	
			rowsState = append(rowsState, rowsStorage...)
	
			proof := finalizeProof(i, rowsState, addrh, sRoot, cRoot, startRoot, finalRoot, tMod.Type)
			allProofs = append(allProofs, proof...)
			
			// Put rows that just need to be hashed at the end, because circuit assign function
			// relies on index (for example when assigning s_keccak and c_keccak).
			toBeHashed = append(toBeHashed, toBeHashedAcc...)
			toBeHashed = append(toBeHashed, toBeHashedStorage...)
		} else {
			proof, toBeHashedAcc := obtainAccountProofAndConvertToWitness(i, tMod, len(trieModifications), statedb, specialTest)
			allProofs = append(allProofs, proof...)
			toBeHashed = append(toBeHashed, toBeHashedAcc...)
		}
	}
	allProofs = append(allProofs, toBeHashed...)

	return allProofs
}

// prepareWitness obtains the GetProof proof before and after the modification for each
// of the modification. It then converts the two proofs into an MPT circuit witness for each of
// the modifications and stores it into a file.
func prepareWitness(testName string, trieModifications []TrieModification, statedb *state.StateDB) {
	proof := obtainTwoProofsAndConvertToWitness(trieModifications, statedb, 0)
	storeWitness(testName, proof)
}

// prepareWitnessSpecial obtains the GetProof proof before and after the modification for each
// of the modification. It then converts the two proofs into an MPT circuit witness for each of
// the modifications and stores it into a file. It is named special as the flag specialTest
// instructs the function obtainTwoProofsAndConvertToWitness to prepare special trie states, like moving
// the account leaf in the first trie level.
func prepareWitnessSpecial(testName string, trieModifications []TrieModification, statedb *state.StateDB, specialTest byte) {
	proof := obtainTwoProofsAndConvertToWitness(trieModifications, statedb, specialTest)
	storeWitness(testName, proof)
}

// updateStateAndPrepareWitness updates the state according to the specified keys and values and then
// prepares a witness for the proof before given modifications and after.
// This function is used when some specific trie state needs to be prepared before the actual modifications
// take place and for which the witness is needed.
func updateStateAndPrepareWitness(testName string, keys, values []common.Hash, addresses []common.Address,
		trieModifications []TrieModification) {
	blockNum := 13284469
	blockNumberParent := big.NewInt(int64(blockNum))
	blockHeaderParent := oracle.PrefetchBlock(blockNumberParent, true, nil)
	database := state.NewDatabase(blockHeaderParent)
	statedb, _ := state.New(blockHeaderParent.Root, database, nil)

	statedb.DisableLoadingRemoteAccounts()

	// Set the state needed for the test:
	for i := 0; i < len(keys); i++ {
		statedb.SetState(addresses[i], keys[i], values[i])
	}

	prepareWitness(testName, trieModifications, statedb)
}

// convertProofToWitness takes two GetProof proofs (before and after a single modification) and prepares
// a witness for the MPT circuit. Alongside, it prepares the byte streams that need to be hashed
// and inserted into the Keccak lookup table.
func convertProofToWitness(statedb *state.StateDB, addr common.Address, proof1, proof2, extNibblesS, extNibblesC [][]byte, key []byte, neighbourNode []byte,
		isAccountProof, nonExistingAccountProof, nonExistingStorageProof, isShorterProofLastLeaf bool) ([][]byte, [][]byte, []Node, bool) {
	rows := make([][]byte, 0)
	toBeHashed := make([][]byte, 0)

	minLen := len(proof1)
	if len(proof2) < minLen {
		minLen = len(proof2)
	}

	keyIndex := 0
	len1 := len(proof1)
	len2 := len(proof2)

	// When a value in the trie is updated, both proofs are of the same length.
	// Otherwise, when a value is added (not updated) and there is no node which needs to be changed
	// into a branch, one proof has a leaf and one does not have it.
	// The third option is when a value is added and the existing leaf is turned into a branch,
	// in this case we have an additional branch in C proof (when deleting a value causes
	// that a branch with two leaves turns into a leaf, we have an additional branch in S proof).

	additionalBranch := false
	if len1 < len2 && len1 > 0 { // len = 0 when trie trie is empty
		// Check if the last proof element in the shorter proof is a leaf -
		// if it is, then there is an additional branch.
		additionalBranch = !isBranch(proof1[len1 - 1])
	} else if len2 < len1 && len2 > 0 {
		additionalBranch = !isBranch(proof2[len2 - 1])
	}

	upTo := minLen
	if (len1 != len2) && additionalBranch {
		upTo = minLen - 1
	}

	var extensionRowS []byte
	var extensionRowC []byte
	extensionNodeInd := 0

	var nodes []Node

	branchC16 := byte(0); 
	branchC1 := byte(1);
	for i := 0; i < upTo; i++ {
		if !isBranch(proof1[i]) {
			if i != len1 - 1 { // extension node
				var numberOfNibbles byte
				numberOfNibbles, extensionRowS, extensionRowC = prepareExtensionRows(extNibblesS, extensionNodeInd, proof1[i], proof2[i], false, false)
				keyIndex += int(numberOfNibbles)
				extensionNodeInd++
				continue
			}

			l := len(proof1)
			var leafRows, leafToBeHashed [][]byte
			var node Node
			
			if isAccountProof {
				leafRows, leafToBeHashed, node = getAccountLeaf(addr, proof1[l-1], proof2[l-1], key, nonExistingAccountProof)
			} else {
				leafRows, leafToBeHashed, node = getStorageLeaf(proof1[l-1], proof2[l-1], key, nonExistingStorageProof)
			}
			rows = append(rows, leafRows...)
			toBeHashed = append(toBeHashed, leafToBeHashed...)	

			nodes = append(nodes, node)
		} else {
			switchC16 := true // If not extension node, switchC16 = true.
			if extensionRowS != nil {
				keyLen := getExtensionNodeKeyLen(proof1[i-1])
				if keyLen == 1 {
					switchC16 = false
				} else {
					if proof1[i-1][2] != 0 { // If even, switch16 = true.
						switchC16 = false
					}
				}
			}
			if switchC16 {
				if branchC16 == 1 {
					branchC16 = 0
					branchC1 = 1
				} else {
					branchC16 = 1
					branchC1 = 0
				}
			}

			bRows := prepareTwoBranches(proof1[i], proof2[i], key[keyIndex], branchC16, branchC1, false, false)
			keyIndex += 1

			// extension node rows
			if extensionRowS != nil {
				bRows = append(bRows, extensionRowS)
				bRows = append(bRows, extensionRowC)

				setExtensionNodeSelectors(&bRows, proof1[i-1], proof2[i-1], branchC16, branchC1)

				// adding extension nodes for hashing:
				addForHashing(proof1[i-1], &toBeHashed)
				addForHashing(proof2[i-1], &toBeHashed)
			} else {
				extRows := prepareEmptyExtensionRows(false, false)
				bRows = append(bRows, extRows...)
			}

			rows = append(rows, bRows...)
			addForHashing(proof1[i], &toBeHashed)
			addForHashing(proof2[i], &toBeHashed)

			extensionRowS = nil
			extensionRowC = nil
		}
	}	
	
	if len1 != len2 {
		if additionalBranch {	
			var leafRows [][]byte
			var leafForHashing [][]byte
			if isAccountProof {
				leafRows, leafForHashing = prepareAccountLeaf(proof1[len1-1], proof2[len2-1], key, nonExistingAccountProof, false)
				toBeHashed = append(toBeHashed, leafForHashing...)
			} else {
				leafRows, leafForHashing = prepareStorageLeaf(proof1[len1-1], key, nonExistingAccountProof)
				toBeHashed = append(toBeHashed, leafForHashing...)
			}

			// To compute drifted position:
			leafRow0 := leafRows[0]
			if len1 > len2 {
				leafRow0 = proof2[len2-1]
			}
			
			isModifiedExtNode, isExtension, numberOfNibbles, branchC16 := addBranchAndPlaceholder(addr, &rows, proof1, proof2, extNibblesS, extNibblesC,
				leafRow0, key, neighbourNode,
				keyIndex, extensionNodeInd, additionalBranch,
				isAccountProof, nonExistingAccountProof, isShorterProofLastLeaf, branchC16, branchC1, &toBeHashed)

			if isAccountProof {
				addAccountLeafAfterBranchPlaceholder(&rows, proof1, proof2, leafRows, neighbourNode, key, nonExistingAccountProof, isModifiedExtNode, isExtension, numberOfNibbles, &toBeHashed)	
			} else {	
				addStorageLeafAfterBranchPlaceholder(&rows, proof1, proof2, leafRows, neighbourNode, key, nonExistingAccountProof, isModifiedExtNode, isExtension, numberOfNibbles, &toBeHashed)
			}

			// When a proof element is a modified extension node (new extension node appears at the position
			// of the existing extension node), additional rows are added (extension node before and after
			// modification).
			if isModifiedExtNode {
				addModifiedExtNode(statedb, addr, &rows, proof1, proof2, extNibblesS, extNibblesC, key, neighbourNode,
					keyIndex, extensionNodeInd, numberOfNibbles, additionalBranch,
					isAccountProof, nonExistingAccountProof, isShorterProofLastLeaf, branchC16, branchC1, &toBeHashed)
			}
		} else {
			addLeafAndPlaceholder(&rows, proof1, proof2, key, nonExistingAccountProof, isAccountProof, &toBeHashed)
		}
	} else if isBranch(proof2[len(proof2)-1]) {
		// Let's always use C proof for non-existing proof.
		// Account proof has drifted leaf as the last row, storage proof has non-existing-storage row
		// as the last row.
		// When non existing proof and only the branches are returned, we add a placeholder leaf.
		// This is to enable the lookup (in account leaf row), most constraints are disabled for these rows.
		if isAccountProof {
			leafRows := prepareAccountLeafPlaceholderRows(key, keyIndex, nonExistingAccountProof)
			rows = append(rows, leafRows...)	
		} else {
			leafRows := prepareStorageLeafPlaceholderRows(key, keyIndex, nonExistingStorageProof)
			rows = append(rows, leafRows...)	
		}
	}

	return rows, toBeHashed, nodes, extensionNodeInd > 0
}