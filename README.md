<img src="certsearch.svg" width="200">

# Build

```bash
go build
```

# Usage

```
> ./CeRTSearcH -h
Usage of ./CeRTSearcH:
  -batchSize int
        Number of certificate records to process per batch (default 100000)
  -deduplicate
        Report first record only for (pre)certificate pairs [note: ~4x slower]
  -endID int
        crt.sh ID to stop at (default 9223372036854775807)
  -logLevel string
        Logging verbosity [debug, info, error, fatal] (default "debug")
  -q string
        Search term [use % for wildcard matching] (default "%")
  -sanType string
        Subject Alternative Name attributes to search [NONE, ANY, rfc822Name, dNSName, iPAddress] (default "dNSName")
  -startID int
        crt.sh ID to start from [-1 = use max(ID)+1] (default -1)
  -subjectType string
        Subject DN attributes to search [NONE, ANY, <OID>] (default "NONE")
  -unexpiredOnly
        Ignore expired certificates
```
