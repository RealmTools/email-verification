package smtpEmailVerification

import (
	"errors"
	"log"
	"net"
	"net/smtp"
	"sync"
	"time"

	"golang.org/x/net/idna"
)


func newSMTPClient(domain_ string) (*smtp.Client, error) {
	domain := domainToASCII(domain_)
	mxRecords, err := net.LookupMX(domain)

	smtpPort  := ":25"

	if err != nil {
		return nil, err
	}

	if len(mxRecords) == 0 {
		return nil, errors.New("No MX records found")
	}


		// Create a channel for receiving response from
		ch := make(chan interface{}, 1)

		// Done indicates if we're still waiting on dial responses
		var done bool
	
		// mutex for data race
		var mutex sync.Mutex
	
		// Attempt to connect to all SMTP servers concurrently
		for _, r := range mxRecords {
			addr := r.Host + smtpPort


		

	
			go func() {
				c, err := dialSMTP(addr)
				if err != nil {
					if !done {
						ch <- err
					}
					return
				}
	
				// Place the client on the channel or close it
				mutex.Lock()
				switch {
				case !done:
					done = true
					ch <- c
				default:
					c.Close()
				}
				mutex.Unlock()
			}()
		}

		// Collect errors or return a client
		var errs []error
		for {
			res := <-ch
			switch r := res.(type) {
			case *smtp.Client:
				return r, nil
			case error:
				errs = append(errs, r)
				if len(errs) == len(mxRecords) {
					return nil, errs[0]
				}
			default:
				return nil, errors.New("Unexpected response dialing SMTP server")
			}
		}
}

// domainToASCII converts any internationalized domain names to ASCII
// reference: https://en.wikipedia.org/wiki/Punycode
func domainToASCII(domain string) string {
	asciiDomain, err := idna.ToASCII(domain)
	if err != nil {
		return domain
	}
	return asciiDomain

}



// dialSMTP is a timeout wrapper for smtp.Dial. It attempts to dial an
// SMTP server (socks5 proxy supported) and fails with a timeout if timeout is reached while
// attempting to establish a new connection
func dialSMTP(addr string) (*smtp.Client, error) {
	// Channel holding the new smtp.Client or error
	ch := make(chan interface{}, 1)

	smtpTimeout := 30 * time.Second

	log.Printf("connection: %v", smtpTimeout)
	
	// Dial the new smtp connection
	go func() {
		var conn net.Conn
		var err error


		conn, err = establishConnection(addr)
		
		if err != nil {
			ch <- err
			return
		}

		host, _, _ := net.SplitHostPort(addr)
		client, err := smtp.NewClient(conn, host)
		if err != nil {
			ch <- err
			return
		}
		ch <- client
	}()

	// Retrieve the smtp client from our client channel or timeout
	select {
	case res := <-ch:
		switch r := res.(type) {
		case *smtp.Client:
			return r, nil
		case error:
			return nil, r
		default:
			return nil, errors.New("Unexpected response dialing SMTP server")
		}
	case <-time.After(smtpTimeout):
		return nil, errors.New("Timeout connecting to mail-exchanger")
	}
}


// establishConnection connects to the address on the named network address.
func establishConnection(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

