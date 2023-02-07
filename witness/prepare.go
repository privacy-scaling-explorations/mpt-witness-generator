package witness

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/miha-stopar/mpt/state"
)

// prepareWitness takes two GetProof proofs (before and after single modification) and prepares
// a witness for the MPT circuit. Alongside, it prepares the byte streams that need to be hashed
// and inserted into Keccak lookup table.
func prepareWitness(statedb *state.StateDB, addr common.Address, proof1, proof2, extNibblesS, extNibblesC [][]byte, key []byte, neighbourNode []byte,
		isAccountProof, nonExistingAccountProof, nonExistingStorageProof, isShorterProofLastLeaf bool) ([][]byte, [][]byte, bool) {
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
			addLeafRows(&rows, proof1[l-1], proof2[l-1], key, nonExistingAccountProof, nonExistingStorageProof, isAccountProof, &toBeHashed)
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
			
			isModifiedExtNode, isExtension, numberOfNibbles, branchC16 := addBranchAndPlaceholder(statedb, addr, &rows, proof1, proof2, extNibblesS, extNibblesC,
				leafRows[0], key, neighbourNode,
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

	return rows, toBeHashed, extensionNodeInd > 0
}