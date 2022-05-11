package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/RealmTools/email-verification/meta"
)
 
func checkIsDisposable(domain string) bool {
	
	return meta.ThrowAwayDomain[domain]
}


func main() {

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("Type a domain name: IE apple.com\n")

	for scanner.Scan() {
		checkDomain(scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal("Error: could not read from input: %v\n", err)
	}
}

func checkDomain(domain string) {

	isDisposable := checkIsDisposable(domain)


	var hasMX, hasSPF, hasDMARC bool
	var spfRecord, dmarcRecord string

	mxRecords, err := net.LookupMX(domain)

	if err != nil {
		log.Printf("Error: %v\n", err)
	}

	if len(mxRecords) > 0 {
		hasMX = true
	}

	txtRecords, err := net.LookupTXT(domain)

	if err != nil {
		log.Printf("Error:%v\n", err)
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			hasSPF = true
			spfRecord = record
			break
		}
	}

	dmarcRecords, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		log.Printf("ErrorL%v\n", err)
	}

	for _, record := range dmarcRecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			hasDMARC = true
			dmarcRecord = record
			break
		}
	}

	fmt.Printf("Domain Name: %v \nMX record found: %v \nSPF record found: %v \nSPF record content: %v \nDMARC found: %v \nDMARC content: %v\nis disposable email: %v\n", domain, hasMX, hasSPF, spfRecord, hasDMARC, dmarcRecord, isDisposable)
}
