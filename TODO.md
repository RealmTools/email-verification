- GenerateRandomEmail generates a random email address using the domain passed. Used primarily for checking the existence of a catch-all address

- setup test to run locally rather than internal " Go test can be used for that, too. I often use a test as an entrypoint to my code to exercise it and figure out what it's doing. Just slap a func TestStuff(t \*testing.T) { } in a foo_test.go file, and put the "main" code inside the test to run your code. Then running go test in the library directory will run that test function (if you have other tests in the same file, you can tell it to only run that one function with go test -test.run=TestStuff)."

Email verification /smtp

- https://golangexample.com/a-go-library-for-email-verification-without-sending-any-emails/
- Email Verification Lookup via SMTP: performs an email verification on the passed email
- Email Reachability: checks how confident in sending an email to the address
