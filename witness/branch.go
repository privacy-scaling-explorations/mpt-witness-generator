package witness

// getDriftedPosition returns the position in branch to which the leaf drifted because another
// leaf has been added to the same slot. This information is stored into a branch init row.
func getDriftedPosition(leafKeyRow []byte, numberOfNibbles int) byte {
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