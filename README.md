<img src="certsearch.svg" width="200">

# Overview

CeRTSearcH uses the crt.sh database to handle two use cases for which the https://crt.sh/ web interface is not well suited:
1. Very large result sets. e.g., all dNSName values that match %.com
2. Delta searches. i.e., what's new since I last searched?

The https://crt.sh/ web interface relies on [Full Text Search](https://www.postgresql.org/docs/current/textsearch.html) indexes to perform a single SQL query over the entire corpus of certificates; in contrast, CeRTSearcH performs multiple sequential SQL queries over adjacent and relatively small ranges of crt.sh IDs.

Given the huge number of certificates known to crt.sh, CeRTSearcH can be expected to take a minimum of several days to search the entire database starting at `-startID 1`. Parallel processing of multiple ranges of crt.sh IDs would be faster, but since it would work the database harder it is deliberately not supported by CeRTSearcH; this is because crt.sh:5432 is a finite resource that is shared between many users.

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
        Report first crt.sh record only for (pre)certificate pairs [note: ~4x slower]
  -endID int
        crt.sh ID to stop at (default 9223372036854775807)
  -logLevel string
        Logging verbosity [debug, info, error, fatal] (default "debug")
  -q string
        Search term [use % for wildcard matching] (default "%")
  -sanType string
        Subject Alternative Name attributes to search [NONE, ANY, rfc822Name, dNSName, iPAddress] (default "dNSName")
  -showSQLOnly
        Show the SQL query that would be used, then exit
  -sort
        Guarantee results are ordered by crt.sh ID
  -startID int
        crt.sh ID to start from [-1 = stream new records, starting at max(ID)+1] (default -1)
  -subjectType string
        Subject DN attributes to search [NONE, ANY, <OID>] (default "NONE")
  -unexpiredOnly
        Ignore expired certificates
  -uniq
        Remove duplicate results (e.g., identical CN and dNSName in the same certificate)
```
