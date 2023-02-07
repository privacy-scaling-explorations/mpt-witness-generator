package witness

import (
	"log"
	"strconv"
)

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