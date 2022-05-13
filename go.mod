module github.com/RealmTools/emailVerification

go 1.18

retract (
	v0.1.2 // Contains retractions only.
	v0.1.1 // Contains retractions only.
	v0.1.0 // Published accidentally.
)

require (
	golang.org/x/net v0.0.0-20220425223048-2871e0cb64e4 // indirect
	golang.org/x/text v0.3.7 // indirect
	h12.io/socks v1.0.3 // indirect
)
