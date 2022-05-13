### About

A email verification utility

### Install

```sh
go get -u github.com/RealmTools/emailVerification
```

### Example

```go
func main() {
    response, err := emailVerification.Verify("contact@realmtools.com")
}
```

#### Function response

```json
{
  "email": "contact@realmtools.com",
  "domain": "realmtools.com",
  "mxRecordFound": true,
  "spfRecordFound": true,
  "spfRecordContent": "v=spf1 include:_spf.mx.cloudflare.net ~all",
  "dmarcRecordFound": false,
  "dmarcRecordContent": "",
  "isThrowAwayEmail": false
}
```
