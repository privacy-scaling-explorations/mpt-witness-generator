package witness

import (
	"fmt"
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/miha-stopar/mpt/state"
	"github.com/miha-stopar/mpt/trie"
)

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

	// When value in the trie is updated, both proofs are of the same length.
	// When value is added and there is no node which needs to be changed
	// into branch, one proof has a leaf and one doesn't have it.

	// Check if the last proof element in the shorter proof is a leaf -
	// if it is, then there is an additional branch.
	additionalBranchNeeded := func(proofEl []byte) bool {
		elems, _, err := rlp.SplitList(proofEl)
		check(err)
		c, _ := rlp.CountValues(elems)
		return c == 2
	}

	additionalBranch := false
	if len1 < len2 && len1 > 0 { // len = 0 when trie trie is empty
		additionalBranch = additionalBranchNeeded(proof1[len1-1])
	} else if len2 < len1 && len2 > 0 {
		additionalBranch = additionalBranchNeeded(proof2[len2-1])
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
		elems, _, err := rlp.SplitList(proof1[i])
		if err != nil {
			fmt.Println("decode error", err)
		}

		switch c, _ := rlp.CountValues(elems); c {
		case 2:
			if i != len1 - 1 { // extension node
				var numberOfNibbles byte
				numberOfNibbles, extensionRowS, extensionRowC = prepareExtensionRows(extNibblesS, extensionNodeInd, proof1[i], proof2[i], false, false)
				keyIndex += int(numberOfNibbles)
				extensionNodeInd++
				continue
			}

			if isAccountProof {
				l := len(proof1)
				leafS := proof1[l-1]
				leafC := proof2[l-1]

				keyRowS, keyRowC, nonExistingAccountRow, nonceBalanceRowS, nonceBalanceRowC, storageCodeHashRowS, storageCodeHashRowC :=
					prepareAccountLeafRows(leafS, leafC, key, nonExistingAccountProof, false)
				
				rows = append(rows, keyRowS)
				rows = append(rows, keyRowC)
				rows = append(rows, nonExistingAccountRow)
				rows = append(rows, nonceBalanceRowS)
				rows = append(rows, nonceBalanceRowC)
				rows = append(rows, storageCodeHashRowS)
				rows = append(rows, storageCodeHashRowC)

				leafS = append(leafS, 5)
				leafC = append(leafC, 5)
				toBeHashed = append(toBeHashed, leafS)
				toBeHashed = append(toBeHashed, leafC)
			} else {
				leafRows, leafForHashing := prepareStorageLeafRows(proof1[i], 2, false) // leaf s
				rows = append(rows, leafRows...)
				toBeHashed = append(toBeHashed, leafForHashing)
				leafRows, leafForHashing = prepareStorageLeafRows(proof2[i], 3, false) // leaf s
				rows = append(rows, leafRows...)	

				toBeHashed = append(toBeHashed, leafForHashing)
			}
		case 17:
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

			bRows := prepareTwoBranchesWitness(proof1[i], proof2[i], key[keyIndex], branchC16, branchC1, false, false)
			keyIndex += 1

			// extension node rows
			if extensionRowS != nil {
				bRows = append(bRows, extensionRowS)
				bRows = append(bRows, extensionRowC)

				// Set isExtension to 1 in branch init.
				bRows[0][isExtensionPos] = 1

				if len(proof1[i-1]) > 56 { // 56 because there is 1 byte for length
					bRows[0][isSExtLongerThan55Pos] = 1
				}
				if len(proof2[i-1]) > 56 {
					bRows[0][isCExtLongerThan55Pos] = 1
				}

				if len(proof1[i-1]) < 32 {
					bRows[0][isExtNodeSNonHashedPos] = 1
				}
				if len(proof2[i-1]) < 32 {
					bRows[0][isExtNodeCNonHashedPos] = 1
				}

				keyLen := getExtensionNodeKeyLen(proof1[i-1])
				// Set whether key extension nibbles are of even or odd length.
				if keyLen == 1 {
					if branchC16 == 1 {
						bRows[0][isExtShortC16Pos] = 1
					} else {
						bRows[0][isExtShortC1Pos] = 1
					}
				} else {
					if proof1[i-1][2] == 0 {
						if branchC16 == 1 {
							bRows[0][isExtLongEvenC16Pos] = 1
						} else {
							bRows[0][isExtLongEvenC1Pos] = 1
						}
					} else {
						if branchC16 == 1 {
							bRows[0][isExtLongOddC16Pos] = 1
						} else {
							bRows[0][isExtLongOddC1Pos] = 1
						}
					}
				}

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

			// check the two branches
			if extensionNodeInd == 0 {
				for k := 1; k < 17; k++ {
					if k-1 == int(key[i]) {
						continue
					}
					for j := 0; j < branchNodeRLPLen+32; j++ {
						if bRows[k][j] != bRows[k][branch2start+j] {
							panic("witness not properly generated")
						}
					}
				}
			}

			extensionRowS = nil
			extensionRowC = nil
		default:
			fmt.Println("invalid number of list elements")
		}
	}

	addBranch := func(branch1, branch2 []byte, modifiedIndex byte, isCPlaceholder bool, branchC16, branchC1 byte, insertedExtension bool) {
		isBranchSPlaceholder := false
		isBranchCPlaceholder := false
		if isCPlaceholder {
			isBranchCPlaceholder = true
		} else {
			isBranchSPlaceholder = true
		}

		bRows := prepareTwoBranchesWitness(branch1, branch2, modifiedIndex, branchC16, branchC1, isBranchSPlaceholder, isBranchCPlaceholder)
		rows = append(rows, bRows...)

		branchToBeHashed := branch1
		if !isCPlaceholder {
			branchToBeHashed = branch2
		}
		addForHashing(branchToBeHashed, &toBeHashed)
	}

	getDriftedPosition := func(leafKeyRow []byte, numberOfNibbles int) byte {
		// Get position to which a leaf drifted (to be set in branch init):
		var nibbles []byte
		if leafKeyRow[0] != 248 {
			keyLen := int(leafKeyRow[1] - 128)
			if (leafKeyRow[2] != 32) && (leafKeyRow[2] != 0) { // second term is for extension node
				if leafKeyRow[2] < 32 { // extension node
					nibbles = append(nibbles, leafKeyRow[2] - 16)
				} else { // leaf
					nibbles = append(nibbles, leafKeyRow[2] - 48)
				}
			}
			for i := 0; i < keyLen - 1; i++ { // -1 because the first byte doesn't have any nibbles
				b := leafKeyRow[3 + i]
				n1 := b / 16
				n2 := b - n1 * 16
				nibbles = append(nibbles, n1)
				nibbles = append(nibbles, n2)
			}
		} else {
			keyLen := int(leafKeyRow[2] - 128)
			if (leafKeyRow[3] != 32) && (leafKeyRow[3] != 0) { // second term is for extension node
				if leafKeyRow[3] < 32 { // extension node
					nibbles = append(nibbles, leafKeyRow[3] - 16)
				} else { // leaf
					nibbles = append(nibbles, leafKeyRow[3] - 48)
				}
			}
			for i := 0; i < keyLen - 1; i++ { // -1 because the first byte doesn't have any nibbles
				b := leafKeyRow[4 + i]
				n1 := b / 16
				n2 := b - n1 * 16
				nibbles = append(nibbles, n1)
				nibbles = append(nibbles, n2)
			}
		}

		return nibbles[numberOfNibbles]
	}	

	setExtNodeSelectors := func(row, proofEl []byte, numberOfNibbles int, branchC16 byte) {
		row[isExtensionPos] = 1
		if len(proofEl) > 56 { // 56 because there is 1 byte for length
			// isCExtLongerThan55 doesn't need to be set here
			row[isSExtLongerThan55Pos] = 1
		}

		if len(proofEl) < 32 {
			// isExtNodeSNonHashed doesn't need to be set here
			row[isExtNodeSNonHashedPos] = 1
		}

		if numberOfNibbles == 1 {
			if branchC16 == 1 {
				row[isExtShortC16Pos] = 1
			} else {
				row[isExtShortC1Pos] = 1
			}
		} else {
			if numberOfNibbles % 2 == 0 {
				if branchC16 == 1 {
					row[isExtLongEvenC16Pos] = 1
				} else {
					row[isExtLongEvenC1Pos] = 1
				}
			} else {
				if branchC16 == 1 {
					row[isExtLongOddC16Pos] = 1
				} else {
					row[isExtLongOddC1Pos] = 1
				}
			}
		}
	}

	addPlaceholder := func() {
		if additionalBranch {
			numberOfNibbles := 0
			var extRows [][]byte
			isExtension := (len1 == len2 + 2) || (len2 == len1 + 2)
			if !isExtension {
				extRows = prepareEmptyExtensionRows(false, false)
				if branchC16 == 1 {
					branchC16 = 0
					branchC1 = 1
				} else {
					branchC16 = 1
					branchC1 = 0
				}
			} else {
				var numNibbles byte
				var extensionRowS []byte
				var extensionRowC []byte
				if len1 > len2 {
					numNibbles, extensionRowS, extensionRowC =
						prepareExtensionRows(extNibblesS, extensionNodeInd, proof1[len1 - 3], proof1[len1 - 3], false, false)
				} else {
					numNibbles, extensionRowS, extensionRowC =
						prepareExtensionRows(extNibblesC, extensionNodeInd, proof2[len2 - 3], proof2[len2 - 3], false, false)
				}
				numberOfNibbles = int(numNibbles)
				extRows = append(extRows, extensionRowS)
				extRows = append(extRows, extensionRowC)

				// adding extension node for hashing:
				if len1 > len2 {
					addForHashing(proof1[len1-3], &toBeHashed)
				} else {
					addForHashing(proof2[len2-3], &toBeHashed)
				}

				if numberOfNibbles % 2 == 0 {
					if branchC16 == 1 {
						branchC16 = 0
						branchC1 = 1
					} else {
						branchC16 = 1
						branchC1 = 0
					}
				}
			}

			/*
			For special cases when a new extension node is inserted.

			Imagine you have an extension node at n1 n2 n3 n4 (where each of these is a nibble).
			Let's say this extension node has the following nibbles as the extension: n5 n6 n7.
			So at position n1 n2 n3 n4 n5 n6 n7 there is some branch.
			Now we want to add a leaf at position n1 n2 n3 n4 n5 m1 where m1 != n6.
			The adding algorithm walks through the trie, but it bumps into an extension node where
			it should put this leaf. So a new extension node is added at position n1 n2 n3 n4 which only
			has one nibble: n5. So at n1 n2 n3 n4 n5 we have a branch now. In this brach, at position m we
			have a leaf, while at position n6 we have another extension node with one extension nibble: n7.
			At this position (n7) we have the branch from the original extension node.

			When an extension node is inserted because of the added key, C proof will contain this new
			extension node and the underlying branch. However, S proof will stop at the old extension node. 
			This old extension node is not part of the C proof, but we need to ensure that it is in the C trie.
			We need to take into accout that in the C trie the old extension node has a shortened extension.

			The problem is where to store the old extension node. Note that in the above code the new
			extension node and the underlying branch rows are prepared. For example, when len2 > len1 we
			take extension node from proof2[len2 - 3] and branch from proof2[len2 - 2]. In this case,
			the old extension node in proof1[len1 - 1] has been ignored. For this reason we store it
			in the rows before we add a leaf.
			*/
			var longExtNode []byte
			if len1 > len2 {
				longExtNode = proof2[len2 - 1]
			} else {
				longExtNode = proof1[len1 - 1]
			}

			rlp_elems, _, err := rlp.SplitList(longExtNode)
			check(err)
			c, _ := rlp.CountValues(rlp_elems)
			// Note that isModifiedExtNode happens also when we have a branch instead of shortExtNode
			isModifiedExtNode := (c == 2) && !isShorterProofLastLeaf

			if len1 > len2 {
				addBranch(proof1[len1-2], proof1[len1-2], key[keyIndex + numberOfNibbles], true, branchC16, branchC1, isModifiedExtNode)
			} else {
				addBranch(proof2[len2-2], proof2[len2-2], key[keyIndex + numberOfNibbles], false, branchC16, branchC1, isModifiedExtNode)
			}
			rows = append(rows, extRows...)

			var leafRows [][]byte
			var leafForHashing [][]byte
			if isAccountProof {
				leafS := proof1[len1-1]
				leafC := proof2[len2-1]

				// When generating a proof that account doesn't exist, the length of both proofs is the same (doesn't reach
				// this code).
				keyRowS, keyRowC, nonExistingAccountRow, nonceBalanceRowS, nonceBalanceRowC, storageCodeHashRowS, storageCodeHashRowC :=
					prepareAccountLeafRows(leafS, leafC, key, nonExistingAccountProof, false)
				leafRows = append(leafRows, keyRowS)
				leafRows = append(leafRows, keyRowC)
				leafRows = append(leafRows, nonExistingAccountRow) // not really needed
				leafRows = append(leafRows, nonceBalanceRowS)
				leafRows = append(leafRows, nonceBalanceRowC)
				leafRows = append(leafRows, storageCodeHashRowS)
				leafRows = append(leafRows, storageCodeHashRowC)

				leafS = append(leafS, 5)
				leafC = append(leafC, 5)
				leafForHashing = append(leafForHashing, leafS)
				leafForHashing = append(leafForHashing, leafC)
			} else {
				var leafForHashingS []byte
				leafRows, leafForHashingS = prepareStorageLeafRows(proof1[len1-1], 2, false)
				leafForHashing = append(leafForHashing, leafForHashingS)
			}

			if len1 > len2 {
				toBeHashed = append(toBeHashed, leafForHashing...)
				// All account leaf rows already generated above, for storage leaf only S is generated above.
				if isAccountProof {
					// TODO: isInsertedExtNode
					rows = append(rows, leafRows...)
				} else {
					if !isModifiedExtNode {
						rows = append(rows, leafRows...)
						var leafForHashingC []byte
						leafRows, leafForHashingC = prepareStorageLeafRows(proof2[len2-1], 3, false)
						rows = append(rows, leafRows...)
						toBeHashed = append(toBeHashed, leafForHashingC)
					} else {
						// We do not have leaf in one of the proofs when extension node is inserted.
						// We can use the same leaf for S and C because we have the same extension
						// node and branch in the rows above (inserted extension node rows are below
						// leaf rows). We just need to make sure the row selectors are the right one.
						rows = append(rows, leafRows...)

						l := len(leafRows[0])
						leafKey := make([]byte, l)
						copy(leafKey, leafRows[0])
						leafKey[l - 1] = 3
						rows = append(rows, leafKey)

						l = len(leafRows[1])
						leafVal := make([]byte, l)
						copy(leafVal, leafRows[1])
						leafVal[l - 1] = 14
						rows = append(rows, leafVal)
					}
				}
		
				// We now get the first nibble of the leaf that was turned into branch.
				// This first nibble presents the position of the leaf once it moved
				// into the new branch.

				// Note: leafRows[0] in this case (len1 > len2) is leafRowS[0],
				// leafRows[0] in case below (len2 > len1) is leafRowC[0],
				offset := 4
				leafRow := leafRows[0]
				if isAccountProof {
					offset = 7
					leafRow = leafRows[1]
				}
				rows[len(rows)-branchRows-offset][driftedPos] =
					getDriftedPosition(leafRow, numberOfNibbles) // -branchRows-offset lands into branch init

				if isModifiedExtNode {
					rows[len(rows)-branchRows-offset][isInsertedExtNodeS] = 1
				}

				if isExtension {
					setExtNodeSelectors(rows[len(rows)-branchRows-offset], proof1[len1-3], numberOfNibbles, branchC16)
				}
			} else {
				// We now get the first nibble of the leaf that was turned into branch.
				// This first nibble presents the position of the leaf once it moved
				// into the new branch.

				rows[len(rows)-branchRows][driftedPos] = getDriftedPosition(leafRows[0], numberOfNibbles) // -branchRows lands into branch init

				if isModifiedExtNode {
					rows[len(rows)-branchRows][isInsertedExtNodeC] = 1
				}

				if isExtension {
					setExtNodeSelectors(rows[len(rows)-branchRows], proof2[len2-3], numberOfNibbles, branchC16)	
				}

				toBeHashed = append(toBeHashed, leafForHashing...)
				// All account leaf rows already generated above, for storage leaf only S is generated above.
				if isAccountProof {
					rows = append(rows, leafRows...)
				} else {
					if !isModifiedExtNode {
						rows = append(rows, leafRows...)
						var leafForHashingC []byte
						leafRows, leafForHashingC = prepareStorageLeafRows(proof2[len2-1], 3, false)
						rows = append(rows, leafRows...)
						toBeHashed = append(toBeHashed, leafForHashingC)
					} else {
						var leafForHashingC []byte
						leafRows, leafForHashingC = prepareStorageLeafRows(proof2[len2-1], 3, false)
						// We do not have leaf in one of the proofs when extension node is inserted.
						// We can use the same leaf for S and C because we have the same extension
						// node and branch in the rows above (inserted extension node rows are below
						// leaf rows). We just need to make sure the row selectors are the right one.

						l := len(leafRows[0])
						leafKey := make([]byte, l)
						copy(leafKey, leafRows[0])
						leafKey[l - 1] = 2
						rows = append(rows, leafKey)

						l = len(leafRows[1])
						leafVal := make([]byte, l)
						copy(leafVal, leafRows[1])
						leafVal[l - 1] = 13
						rows = append(rows, leafVal)

						rows = append(rows, leafRows...)
						toBeHashed = append(toBeHashed, leafForHashingC)
					}
				}
			}

			// The branch contains hash of the neighbouring leaf, to be able
			// to check it, we add node RLP to toBeHashed
			addForHashing(neighbourNode, &toBeHashed)

			// Neighbouring leaf - the leaf that used to be one level above,
			// but it was "drifted down" when additional branch was added.
			// Only key is needed because we already have the value (it doesn't change)
			// in the parallel proof.
			if isAccountProof {
				if !isModifiedExtNode {
					h := append(neighbourNode, 5)
					toBeHashed = append(toBeHashed, h)

					keyRowS, _, _, _, _, _, _ :=
						prepareAccountLeafRows(neighbourNode, neighbourNode, key, nonExistingAccountProof, false)
					keyRowS = append(keyRowS, 10)
					rows = append(rows, keyRowS)
				} else {
					pRows := prepareDriftedLeafPlaceholder(isAccountProof)
					rows = append(rows, pRows...)	
				}
			} else {
				if !isModifiedExtNode {
					sLeafRows, _ := prepareStorageLeafRows(neighbourNode, 15, false)
					rows = append(rows, sLeafRows[0])
				} else {
					pRows := prepareDriftedLeafPlaceholder(isAccountProof)
					rows = append(rows, pRows...)	
				}
				
				// For non existing proof, S and C proofs are the same
				nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
				rows = append(rows, nonExistingStorageRow)
			}

			if isModifiedExtNode {
				var extNibbles [][]byte
				if len1 > len2 {
					extNibbles = extNibblesC
				} else {
					extNibbles = extNibblesS
				}			

				numberOfNibbles0, extensionRowS, extensionRowC :=
					prepareExtensionRows(extNibbles, extensionNodeInd, longExtNode, longExtNode, true, false)

				extNodeSelectors := make([]byte, rowLen)
				setExtNodeSelectors(extNodeSelectors, longExtNode, int(numberOfNibbles0), branchC16)
				extNodeSelectors = append(extNodeSelectors, 24)

				var extRows [][]byte
				// We need to prove the old extension node is in S proof (when ext. node inserted).
				extRows = append(extRows, extNodeSelectors)
				extRows = append(extRows, extensionRowS)
				extRows = append(extRows, extensionRowC)

				rows = append(rows, extRows...)
				addForHashing(longExtNode, &toBeHashed)

				// Get nibbles of the extension node that gets shortened because of the newly insertd
				// extension node:
				longNibbles := getExtensionNodeNibbles(longExtNode)

				ind := byte(keyIndex) + byte(numberOfNibbles) // where the old and new extension nodes start to be different
				// diffNibble := oldNibbles[ind]
				longExtNodeKey := make([]byte, len(key))
				copy(longExtNodeKey, key)
				// We would like to retrieve the shortened extension node from the trie via GetProof or
				// GetStorageProof (depending whether it is an account proof or storage proof),
				// the key where we find its underlying branch is `oldExtNodeKey`.
				for j := ind; int(j) < keyIndex + len(longNibbles); j++ {
					// keyIndex is where the nibbles of the old and new extension node start
					longExtNodeKey[j] = longNibbles[j - byte(keyIndex)]	
				}
	
				k := trie.HexToKeybytes(longExtNodeKey)
				key := common.BytesToHash(k)
				var proof [][]byte
				if isAccountProof {
					proof, _, _, _, err = statedb.GetProof(addr)
				} else {
					proof, _, _, _, err = statedb.GetStorageProof(addr, key)
				}
				check(err)

				// There is no short extension node when `len(longNibbles) - numberOfNibbles = 1`, in this case there
				// is simply a branch instead.
				shortExtNodeIsBranch := len(longNibbles) - numberOfNibbles == 1
				if shortExtNodeIsBranch {
					rows[len(rows)-branchRows-9][isShortExtNodeBranch] = 1
				}

				var shortExtNode []byte
				extNodeSelectors1 := make([]byte, rowLen)
				emptyExtRows := prepareEmptyExtensionRows(false, true)
				extensionRowS1 := emptyExtRows[0]
				extensionRowC1 := emptyExtRows[1]

				if !shortExtNodeIsBranch {
					if len2 > len1 {
						elems, _, err := rlp.SplitList(proof[len(proof) - 1])
						check(err)
						c, _ := rlp.CountValues(elems)

						// Note that `oldExtNodeKey` has nibbles properly set only up to the end of nibbles,
						// this is enough to get the old extension node by `GetProof` or `GetStorageProof` -
						// we will get its underlying branch, but sometimes also the leaf in a branch if
						// the nibble will correspond to the leaf (we left the nibbles from
						// `keyIndex + len(oldNibbles)` the same as the nibbles in the new extension node).

						if c == 17 { // last element in a proof is a branch
							shortExtNode = proof[len(proof) - 2]
						} else { // last element in a proof is a leaf
							shortExtNode = proof[len(proof) - 3]
						}
					} else {
						// Needed only for len1 > len2
						rows[len(rows)-branchRows-9][driftedPos] = longNibbles[numberOfNibbles]

						shortNibbles := longNibbles[numberOfNibbles+1:]
						compact := trie.HexToCompact(shortNibbles)
						longStartBranch := 2 + (longExtNode[1] - 128) // cannot be "short" in terms of having the length at position 0; TODO: extension with length at position 2 not supported (the probability very small)

						if len(shortNibbles) > 1 {
							// add RLP2:
							compact = append([]byte{128 + byte(len(compact))}, compact...)
						}
						
						shortExtNode = append(compact, longExtNode[longStartBranch:]...)

						// add RLP1:
						shortExtNode = append([]byte{192 + byte(len(shortExtNode))}, shortExtNode...)
					}

					// Get the nibbles of the shortened extension node:
					nibbles := getExtensionNodeNibbles(shortExtNode)

					// Enable `prepareExtensionRows` call:
					extNibbles = append(extNibbles, nibbles)

					var numberOfNibbles1 byte
					numberOfNibbles1, extensionRowS1, extensionRowC1 =
						prepareExtensionRows(extNibbles, extensionNodeInd + 1, shortExtNode, shortExtNode, false, true)

					setExtNodeSelectors(extNodeSelectors1, shortExtNode, int(numberOfNibbles1), branchC16)
					extNodeSelectors1 = append(extNodeSelectors1, 25)
				} else {
					if len1 > len2 {
						// Needed only for len1 > len2
						rows[len(rows)-branchRows-9][driftedPos] = longNibbles[numberOfNibbles]
					}

					extNodeSelectors1 = append(extNodeSelectors1, 25)
				}

				// The shortened extension node is needed as a witness to be able to check in a circuit
				// that the shortened extension node and newly added leaf (that causes newly inserted
				// extension node) are the only nodes in the newly inserted extension node.
				rows = append(rows, extNodeSelectors1)
				rows = append(rows, extensionRowS1)
				rows = append(rows, extensionRowC1)
				addForHashing(shortExtNode, &toBeHashed)
			}
		} else {
			// We don't have a leaf in the shorter proof, but we will add it there
			// as a placeholder.
			if isAccountProof {
				var leafS []byte
				var leafC []byte
				if len1 > len2 {
					leafS = proof1[len1-1]
					leafC = proof1[len1-1] // placeholder
				} else {
					leafC = proof2[len2-1]
					leafS = proof2[len2-1] // placeholder
				}

				// When generating a proof that account doesn't exist, the length of both proofs is the same (doesn't reach
				// this code).
				keyRowS, keyRowC, nonExistingAccountRow, nonceBalanceRowS, nonceBalanceRowC, storageCodeHashRowS, storageCodeHashRowC :=
					prepareAccountLeafRows(leafS, leafC, key, nonExistingAccountProof, false)
				
				rows = append(rows, keyRowS)
				rows = append(rows, keyRowC)
				rows = append(rows, nonExistingAccountRow) // not really needed
				rows = append(rows, nonceBalanceRowS)
				rows = append(rows, nonceBalanceRowC)
				rows = append(rows, storageCodeHashRowS)
				rows = append(rows, storageCodeHashRowC)

				pRows := prepareDriftedLeafPlaceholder(true)
				rows = append(rows, pRows...)

				leafS = append(leafS, 5)
				leafC = append(leafC, 5)
				toBeHashed = append(toBeHashed, leafS)
				toBeHashed = append(toBeHashed, leafC)
			} else {
				var leafRows [][]byte
				var leafForHashing []byte
				if len1 > len2 {
					leafRows, leafForHashing = prepareStorageLeafRows(proof1[len1-1], 2, false)
				} else {
					leafRows, leafForHashing = prepareStorageLeafRows(proof2[len2-1], 2, true)
				}
				
				rows = append(rows, leafRows...)
				toBeHashed = append(toBeHashed, leafForHashing)

				// No leaf means value is 0, set valueIsZero = true:
				if len1 > len2 {
					leafRows, _ = prepareStorageLeafRows(proof1[len1-1], 3, true)
				} else {
					leafRows, _ = prepareStorageLeafRows(proof2[len2-1], 3, false)
				}
				rows = append(rows, leafRows...)

				pRows := prepareDriftedLeafPlaceholder(isAccountProof)
				rows = append(rows, pRows...)

				// For non existing proof, S and C proofs are the same
				nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
				rows = append(rows, nonExistingStorageRow)	
			}
		}
	}
	
	if len1 != len2 {
		addPlaceholder()
	} else {
		// Let's always use C proof for non-existing proof.
		lastRLP := proof2[len(proof2)-1];
		elems, _, err := rlp.SplitList(lastRLP)
		check(err)
		c, _ := rlp.CountValues(elems)
		// Account proof has drifted leaf as the last row, storage proof has non-existing-storage row
		// as the last row.
		if c == 17 {
			// When non existing proof and only the branches are returned, we add a placeholder leaf.
			// This is to enable the lookup (in account leaf row), most constraints are disabled for these rows.
			if !isAccountProof {
				// We need to prepare placeholder storage leaf rows.
				leaf := make([]byte, rowLen)
				// Just some values to avoid assignement errors:
				leaf[0] = 228
				leaf[1] = 130
				leaf[2] = 51

				leafRows, _ := prepareStorageLeafRows(leaf, 2, false)
				rows = append(rows, leafRows...)
				leafRows, _ = prepareStorageLeafRows(leaf, 3, false)
				rows = append(rows, leafRows...)

				pRows := prepareDriftedLeafPlaceholder(isAccountProof)
				rows = append(rows, pRows...)	

				if nonExistingStorageProof {
					leaf := prepareEmptyNonExistingStorageRow()

					isEven := keyIndex % 2 == 0 
					keyLen := int(math.Floor(float64(64-keyIndex) / float64(2))) + 1
					remainingNibbles := key[keyIndex:]
					leaf[1] = byte(keyLen) + 128
					if isEven {
						leaf[2] = 32
					} else {
						leaf[2] = remainingNibbles[0] + 48
					}

					rows = append(rows, leaf)	
				} else {
					nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
					rows = append(rows, nonExistingStorageRow)	
				}
			} else {
				isEven := keyIndex % 2 == 0 
				keyLen := int(math.Floor(float64(64-keyIndex) / float64(2))) + 1
				remainingNibbles := key[keyIndex:]
				offset := 0
				leaf := make([]byte, rowLen)
				leaf[0] = 248
				leaf[2] = byte(keyLen) + 128
				leaf[3 + keyLen] = 184
				leaf[3 + keyLen + 1 + 1] = 248
				leaf[3 + keyLen + 1 + 1 + 1] = leaf[3 + keyLen + 1] - 2
				if isEven {
					leaf[3] = 32
				} else {
					leaf[3] = remainingNibbles[0] + 48
					offset = 1
				}
				for i := 0; i < keyLen - 1; i++ {
					leaf[4+i] = remainingNibbles[2*i + offset] * 16 + remainingNibbles[2*i + 1 + offset]
				}
				
				keyRowS, keyRowC, nonExistingAccountRow, nonceBalanceRowS, nonceBalanceRowC, storageCodeHashRowS, storageCodeHashRowC :=
					prepareAccountLeafRows(leaf, leaf, key, nonExistingAccountProof, true)
				
				rows = append(rows, keyRowS)
				rows = append(rows, keyRowC)
				rows = append(rows, nonExistingAccountRow)
				rows = append(rows, nonceBalanceRowS)
				rows = append(rows, nonceBalanceRowC)
				rows = append(rows, storageCodeHashRowS)
				rows = append(rows, storageCodeHashRowC)

				pRows := prepareDriftedLeafPlaceholder(isAccountProof)
				rows = append(rows, pRows...)	
			}
		} else {
			pRows := prepareDriftedLeafPlaceholder(isAccountProof)
			rows = append(rows, pRows...)	

			if !isAccountProof {
				if nonExistingStorageProof {
					cKeyRow := rows[len(rows) - 3]
					noLeaf := false
					nonExistingStorageRow := prepareNonExistingStorageRow(cKeyRow, key, noLeaf)
					rows = append(rows, nonExistingStorageRow)	
				} else {
					nonExistingStorageRow := prepareEmptyNonExistingStorageRow()
					rows = append(rows, nonExistingStorageRow)	
				}
			}
		}
	}

	return rows, toBeHashed, extensionNodeInd > 0
}