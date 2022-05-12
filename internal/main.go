package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/RealmTools/emailVerification"
)

func main () {
	response, err := emailVerification.Verify("contact@realmtools.com")
	if err != nil {
		log.Printf("response: %v", err)
	}

	bs, _ := json.Marshal(response)
    fmt.Println(string(bs))

}