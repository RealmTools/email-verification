package emailVerification

import (
	"errors"
	"log"
	"net"
	"regexp"
	"strings"

	"github.com/RealmTools/emailVerification/meta"
)


type EmailInformation struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Valid    bool   `json:"valid"`
}

// ParseEmail: returns email username, domain, and checks if the format is valid
func parseEmail(email string) EmailInformation {

	isAddressValid := isEmailAddressValid(email)
	if !isAddressValid {
		return EmailInformation{Valid: false}
	}

	idx := strings.LastIndex(email, "@")
	username := email[:idx]
	domain := strings.ToLower(email[idx+1:])

	return EmailInformation{
		Username: username,
		Domain:   domain,
		Valid:    isAddressValid,
	}
}


// IsEmailAddressValid: checks email format using regex
func isEmailAddressValid(email string) bool {
	var emailRegexString = "^(?:(?:(?:(?:[a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(?:\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|(?:(?:\\x22)(?:(?:(?:(?:\\x20|\\x09)*(?:\\x0d\\x0a))?(?:\\x20|\\x09)+)?(?:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(?:(?:(?:\\x20|\\x09)*(?:\\x0d\\x0a))?(\\x20|\\x09)+)?(?:\\x22))))@(?:(?:(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])(?:[a-zA-Z]|\\d|-|\\.|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(?:(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])(?:[a-zA-Z]|\\d|-|\\.|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$"
	var emailRegex = regexp.MustCompile(emailRegexString)
	return emailRegex.MatchString(email)
}



// checkIsDisposable: references a collection of known throwaway domains
func checkIsDisposable(domain string) bool {
	return meta.ThrowawayDomains[domain]
}

type Response struct {
	Email string `json:"email"`
	Domain string `json:"domain"`
	MXRecordFound bool `json:"mxRecordFound"`
	SPFRecordFound bool `json:"spfRecordFound"`
	SPFRecordContent string `json:"spfRecordContent"`
	DMARCRecordFound bool `json:"dmarcRecordFound"`
	DMARCRecordContent string `json:"dmarcRecordContent"`
	IsThrowawayEmail bool `json:"isThrowAwayEmail"`
}


// retrieves email and dns information
func Verify(email string) (Response, error) {
 
	email_information := parseEmail(email)
	
	if email_information.Valid == false {
		return Response{}, errors.New("Error: email is invalid")
	}

	domain := email_information.Domain

 

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
	return Response{Email: email, Domain: domain, MXRecordFound: hasMX, SPFRecordFound: hasSPF, SPFRecordContent: spfRecord, DMARCRecordFound: hasDMARC, DMARCRecordContent: dmarcRecord, IsThrowawayEmail: isDisposable}, nil
}
 