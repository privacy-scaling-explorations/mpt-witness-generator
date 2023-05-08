package witness

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
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

func storeWitness(testName string, proof [][]byte) {
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

func storeNodes(testName string, nodes []Node) {
	name := testName + ".json"
	f, err := os.Create("../generated_witnesses/" + name)
    check(err)
	defer f.Close()
	b, err := json.Marshal(nodes)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(string(b))

	n3, err := f.WriteString(string(b))
    check(err)
    fmt.Printf("wrote %d bytes\n", n3)
}