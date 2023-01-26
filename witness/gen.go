package witness

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/miha-stopar/mpt/oracle"
	"github.com/miha-stopar/mpt/state"
	"github.com/miha-stopar/mpt/trie"
)

const branchNodeRLPLen = 2 // we have two positions for RLP meta data
const branch2start = branchNodeRLPLen + 32
const branchRows = 19 // 1 (init) + 16 (children) + 2 (extension S and C)

const accountLeafRows = 8
const counterLen = 4

// rowLen - each branch node has 2 positions for RLP meta data and 32 positions for hash
const rowLen = branch2start + 2 + 32 + 1 // +1 is for info about what type of row is it
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
	AccountLeafKeyRow // 6
	// TODO
)

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

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func MatrixToJson(rows [][]byte) string {
	// Had some problems with json.Marshal, so I just prepare json manually.
	json := "["
	for i := 0; i < len(rows); i++ {
		json += listToJson(rows[i])
		if i != len(rows)-1 {
			json += ","
		}
	}
	json += "]"

	return json
}

func listToJson(row []byte) string {
	json := "["
	for j := 0; j < len(row); j++ {
		json += strconv.Itoa(int(row[j]))
		if j != len(row)-1 {
			json += ","
		}
	}
	json += "]"

	return json
}

// isBranch takes GetProof element and returns whether the element is a branch.
func isBranch(proofEl []byte) bool {
	elems, _, err := rlp.SplitList(proofEl)
	check(err)
	c, err1 := rlp.CountValues(elems)
	check(err1)
	if c != 2 && c != 17 {
		log.Fatal("Proof element is neither leaf or branch")
	}
	return c == 17
}

// Equip proof with intermediate state roots, first level info, counter, address RLC,
// modification tag (whether it is storage / nonce / balance change).
func insertMetaInfo(stream, sRoot, cRoot, address, counter []byte, notFirstLevel, isStorageMod, isNonceMod, isBalanceMod, isCodeHashMod, isAccountDeleteMod, isNonExistingAccount, isNonExistingStorage byte) []byte {
	// The last byte (-1) in a row determines the type of the row.
	// Byte -2 determines whether it's the first level or not.
	// Bytes before that store intermediate final and end roots.
	l := len(stream)
	extendLen := 64 + 32 + 32 + counterLen + 1 + 7
	extended := make([]byte, l + extendLen) // make space for 32 + 32 + 32 + 1 (s hash, c hash, public_root, notFirstLevel)
	copy(extended, stream)
	extended[l+extendLen-1] = extended[l-1] // put selector to the last place
	for i := 0; i < len(sRoot); i++ {
		extended[l-1+i] = sRoot[i]
	}
	for i := 0; i < len(cRoot); i++ {
		extended[l-1+len(sRoot)+i] = cRoot[i]
	}
	for i := 0; i < len(address); i++ {
		extended[l-1+len(sRoot) + len(cRoot) + i] = address[i]
	}
	for i := 0; i < len(counter); i++ {
		extended[l-1+len(sRoot) + len(cRoot) + len(address) + i] = counter[i]
	}
	// public root set later

	extended[l+extendLen-2] = notFirstLevel
	extended[l+extendLen-3] = isStorageMod
	extended[l+extendLen-4] = isNonceMod
	extended[l+extendLen-5] = isBalanceMod
	extended[l+extendLen-6] = isCodeHashMod
	extended[l+extendLen-7] = isAccountDeleteMod
	extended[l+extendLen-8] = isNonExistingAccount
	extended[l+extendLen-9] = isNonExistingStorage

	return extended
}

func insertPublicRoot(proof [][]byte, startRoot, finalRoot []byte) {
	for i := 0; i < len(proof); i++ {
		l := len(proof[i])
		if i == 0 {
			for j := 0; j < 32; j++ {
				proof[i][l - 32 - 6 + j] = startRoot[j]
			}
		} else {
			for j := 0; j < 32; j++ {
				proof[i][l - 32 - 6 + j] = finalRoot[j]
			}
		}
	}
}

func VerifyProof(proof [][]byte, key []byte) bool {
	hasher := trie.NewHasher(false)
	for i := 0; i < len(proof)-1; i++ {
		parentHash := hasher.HashData(proof[i])
		parent, err := trie.DecodeNode(parentHash, proof[i])
		check(err)

		childHash := hasher.HashData(proof[i+1])
		child, err := trie.DecodeNode(childHash, proof[i+1])
		check(err)

		r := parent.(*trie.FullNode)
		c := r.Children[key[i]] // TODO: doesn't cover all scenarios
		u, _ := hasher.Hash(child, false)

		if fmt.Sprintf("%b", u) != fmt.Sprintf("%b", c) {
			return false
		}
	}

	return true
}

func VerifyTwoProofsAndPath(proof1, proof2 [][]byte, key []byte) bool {
	if len(proof1) != len(proof2) {
		fmt.Println("constraint failed: proofs length not the same")
		return false
	}
	hasher := trie.NewHasher(false)
	for i := 0; i < len(proof1)-1; i++ { // -1 because it checks current and next row
		parentHash := hasher.HashData(proof1[i])
		parent, err := trie.DecodeNode(parentHash, proof1[i])
		check(err)

		childHash := hasher.HashData(proof1[i+1])
		child, err := trie.DecodeNode(childHash, proof1[i+1])
		check(err)

		r := parent.(*trie.FullNode)
		c := r.Children[key[i]] // TODO: doesn't cover all scenarios
		u, _ := hasher.Hash(child, false)

		if fmt.Sprintf("%b", u) != fmt.Sprintf("%b", c) {
			fmt.Println("constraint failed: proof not valid")
			return false
		}

		parentHash2 := hasher.HashData(proof2[i])
		parent2, err := trie.DecodeNode(parentHash2, proof2[i])
		check(err)

		childHash2 := hasher.HashData(proof2[i+1])
		child2, err := trie.DecodeNode(childHash2, proof2[i+1])
		check(err)

		r2 := parent2.(*trie.FullNode)
		c2 := r2.Children[key[i]] // TODO: doesn't cover all scenarios
		u2, _ := hasher.Hash(child2, false)

		if fmt.Sprintf("%b", u2) != fmt.Sprintf("%b", c2) {
			fmt.Println("constraint failed: proof not valid")
			return false
		}

		// Constraints that we are having the same path for both proofs:
		for j := 0; j < 16; j++ {
			if j != int(key[i]) {
				if fmt.Sprintf("%b", r.Children[j]) != fmt.Sprintf("%b", r2.Children[j]) {
					fmt.Println("constraint failed: path not valid")
					return false
				}
			}
		}
	}

	return true
}

// Check that elements in a branch are all the same, except at the position exceptPos.
func VerifyElementsInTwoBranches(b1, b2 *trie.FullNode, exceptPos byte) bool {
	for j := 0; j < 16; j++ {
		if j != int(exceptPos) {
			if fmt.Sprintf("%b", b1.Children[j]) != fmt.Sprintf("%b", b2.Children[j]) {
				fmt.Println("constraint failed: element in branch not the same")
				return false
			}
		}
	}
	return true
}

// addForHashing takes the stream of bytes and append a byte to it that marks this stream
// to be hashed and put into keccak lookup table that is to be used by MPT circuit.
func addForHashing(toBeHashed []byte, toBeHashedCollection *[][]byte) {
	forHashing := make([]byte, len(toBeHashed))
	copy(forHashing, toBeHashed)
	forHashing = append(forHashing, HashRow)
	*toBeHashedCollection = append(*toBeHashedCollection, forHashing)
}

func GetParallelProofs(nodeUrl string, blockNum int, trieModifications []TrieModification) [][]byte {
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

	return getParallelProofs(trieModifications, statedb, 0)
}

func prepareProof(ind int, newProof [][]byte, addrh []byte, sRoot, cRoot, startRoot, finalRoot common.Hash, mType ModType) [][]byte {
	firstLevelBoundary := branchRows
	if newProof[0][len(newProof[0])-1] == 6 {
		// 6 presents account leaf key S.
		// This happens when account leaf is without branch / extension node.
		firstLevelBoundary = accountLeafRows
	}

	isStorageMod := byte(0)
	isNonceMod := byte(0)
	isBalanceMod := byte(0)
	isCodeHashMod := byte(0)
	isAccountDeleteMod := byte(0)
	isNonExistingAccount := byte(0)
	isNonExistingStorage := byte(0)
	if mType == StorageMod {
		isStorageMod = 1
	} else if mType == NonceMod {
		isNonceMod = 1
	} else if mType == BalanceMod {
		isBalanceMod = 1
	} else if mType == CodeHashMod {
		isCodeHashMod = 1
	} else if mType == CreateAccount {
		isNonceMod = 1 // TODO: setting as nonce mod for now, this depends on the lookup
	} else if mType == DeleteAccount {
		isAccountDeleteMod = 1
	} else if mType == NonExistingAccount {
		isNonExistingAccount = 1
	} else if mType == NonExistingStorage {
		isNonExistingStorage = 1
	}

	counter := make([]byte, counterLen)
	binary.BigEndian.PutUint32(counter[0:4], uint32(ind))

	proof := [][]byte{}
	for j := 0; j < len(newProof); j++ {
		notFirstLevel := byte(1)
		if j < firstLevelBoundary {
			notFirstLevel = 0
		}
		r := insertMetaInfo(newProof[j], sRoot.Bytes(), cRoot.Bytes(), addrh, counter, notFirstLevel, 
			isStorageMod, isNonceMod, isBalanceMod, isCodeHashMod, isAccountDeleteMod, isNonExistingAccount,
			isNonExistingStorage)
		proof = append(proof, r)
	}
	insertPublicRoot(newProof, startRoot.Bytes(), finalRoot.Bytes())

	return proof
}

func prepareAccountProof(i int, tMod TrieModification, tModsLen int, statedb *state.StateDB, specialTest byte) ([][]byte, [][]byte) {
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
	
	rowsState, toBeHashedAcc, _ :=
		prepareWitness(statedb, addr, accountProof, accountProof1, aExtNibbles1, aExtNibbles2, accountAddr, aNode, true, tMod.Type == NonExistingAccount, false, isShorterProofLastLeaf)

	proof := prepareProof(i, rowsState, addrh, sRoot, cRoot, startRoot, finalRoot, tMod.Type)

	return proof, toBeHashedAcc
}

func getParallelProofs(trieModifications []TrieModification, statedb *state.StateDB, specialTest byte) [][]byte {
	statedb.IntermediateRoot(false)
	allProofs := [][]byte{}
	toBeHashed := [][]byte{}	
	var startRoot common.Hash
	var finalRoot common.Hash

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
				account := accountProof1[len(accountProof1)-1]
				if len(accountProof1) != 2 {
					panic("account should be in the second level (one branch above it)")
				}
				firstNibble := addrh[0] / 16
				newAccount := moveAccountFromSecondToFirstLevel(firstNibble, account)

				newAccount1 := make([]byte, len(account)+1) 
				copy(newAccount1, newAccount)
				
				accountProof = make([][]byte, 1)
				accountProof[0] = newAccount
				accountProof1 = make([][]byte, 1)
				accountProof1[0] = newAccount1

				// storage leaf in S proof is a placeholder, thus newAccount needs to have an empty trie hash
				// for the root:
				emptyTrieHash := []byte{86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33}
				rootStart := len(newAccount) - 64 - 1;

				for i := 0; i < 32; i++ {
					newAccount[rootStart + i] = emptyTrieHash[i]
				}
			
				hasher := trie.NewHasher(false)
				sRoot = common.BytesToHash(hasher.HashData(newAccount))
				cRoot = common.BytesToHash(hasher.HashData(newAccount1))
			}
			
			rowsState, toBeHashedAcc, _ :=
				prepareWitness(statedb, addr, accountProof, accountProof1, aExtNibbles1, aExtNibbles2, accountAddr, aNode, true, tMod.Type == NonExistingAccount, false, aIsLastLeaf)
			rowsStorage, toBeHashedStorage, _ :=
				prepareWitness(statedb, addr, storageProof, storageProof1, extNibbles1, extNibbles2, keyHashed, node, false, false, tMod.Type == NonExistingStorage, isLastLeaf)
			rowsState = append(rowsState, rowsStorage...)
	
			proof := prepareProof(i, rowsState, addrh, sRoot, cRoot, startRoot, finalRoot, tMod.Type)
			allProofs = append(allProofs, proof...)
			
			// Put rows that just need to be hashed at the end, because circuit assign function
			// relies on index (for example when assigning s_keccak and c_keccak).
			toBeHashed = append(toBeHashed, toBeHashedAcc...)
			toBeHashed = append(toBeHashed, toBeHashedStorage...)
		} else {
			proof, toBeHashedAcc := prepareAccountProof(i, tMod, len(trieModifications), statedb, specialTest)
			allProofs = append(allProofs, proof...)
			toBeHashed = append(toBeHashed, toBeHashedAcc...)
		}
	}
	allProofs = append(allProofs, toBeHashed...)

	return allProofs
}

func GenerateProof(testName string, trieModifications []TrieModification, statedb *state.StateDB) {
	proof := getParallelProofs(trieModifications, statedb, 0)

	w := MatrixToJson(proof)
	fmt.Println(w)

	name := testName + ".json"
	f, err := os.Create("../generated_witnesses/" + name)
    check(err)
	defer f.Close()
	n3, err := f.WriteString(w)
    check(err)
    fmt.Printf("wrote %d bytes\n", n3)
}

func GenerateProofSpecial(testName string, trieModifications []TrieModification, statedb *state.StateDB, specialTest byte) {
	proof := getParallelProofs(trieModifications, statedb, specialTest)

	w := MatrixToJson(proof)
	fmt.Println(w)

	name := testName + ".json"
	f, err := os.Create("../generated_witnesses/" + name)
    check(err)
	defer f.Close()
	n3, err := f.WriteString(w)
    check(err)
    fmt.Printf("wrote %d bytes\n", n3)
}

func UpdateStateAndGenProof(testName string, keys, values []common.Hash, addresses []common.Address,
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
	
	proof := getParallelProofs(trieModifications, statedb, 0)

	w := MatrixToJson(proof)
	fmt.Println(w)

	name := testName + ".json"
	f, err := os.Create("../generated_witnesses/" + name)
    check(err)
	defer f.Close()
	n3, err := f.WriteString(w)
    check(err)
    fmt.Printf("wrote %d bytes\n", n3)
}