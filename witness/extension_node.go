package witness

// setExtNodeSelectors sets in the branch init row the information about the extension node.
func setExtNodeSelectors(row, proofEl []byte, numberOfNibbles int, branchC16 byte) {
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