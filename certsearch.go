// CeRTSearcH
//

package main

import (
	"context"
	"flag"
	"math"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/sirupsen/logrus"
)

func main() {
	// Configure graceful shutdown capabilities.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Define and parse flags.
	var endID int64
	var startID int64
	var batchSize int64
	var unexpiredOnly bool
	var deduplicate bool
	var q string
	var logLevel string
	flag.Int64Var(&endID, "endID", math.MaxInt64, "crt.sh ID to stop at")
	flag.Int64Var(&startID, "startID", -1, "crt.sh ID to start from (-1 = Use max(ID)+1)")
	flag.Int64Var(&batchSize, "batchSize", 100000, "Number of certificates to process per batch")
	flag.BoolVar(&unexpiredOnly, "unexpiredOnly", false, "Ignore expired certificates")
	flag.BoolVar(&deduplicate, "deduplicate", false, "Report first record only for (pre)certificate pairs (Note: ~4x slower)")
	flag.StringVar(&q, "q", "", "Search term (%=wildcard)")
	flag.StringVar(&logLevel, "logLevel", "debug", "Logrus log level [debug, info, error, fatal]")
	flag.Parse()

	// Configure logrus.
	var level logrus.Level
	var err error
	if level, err = logrus.ParseLevel(logLevel); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Fatal("Could not parse log level")
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.JSONFormatter{})

	// Parse the connect string URI.
	var pgxConfig *pgx.ConnConfig
	if pgxConfig, err = pgx.ParseConfig("postgresql:///certwatch?host=crt.sh&port=5432&application_name=CeRTSearcH&user=guest&statement_cache_mode=describe"); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Fatal("Could not parse connect string URI")
	}

	// Connect to crt.sh:5432.
	var crtsh *pgx.Conn
	if crtsh, err = pgx.ConnectConfig(context.Background(), pgxConfig); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Fatal("Could not connect to crt.sh:5432")
	}
	defer crtsh.Close(context.Background())

	// Construct the query.
	query := `
SELECT c.ID, encode(x509_altnames_raw.RAW_VALUE, 'escape'::text), x509_notAfter(c.CERTIFICATE)
	FROM certificate c, x509_altnames_raw(c.CERTIFICATE)
	WHERE c.ID BETWEEN $1 AND $2
		AND x509_altnames_raw.TYPE_NUM = 2
		AND encode(x509_altnames_raw.RAW_VALUE, 'escape'::text) ILIKE $3` // "TYPE_NUM = 2" means SAN:dNSName.
	if unexpiredOnly {
		query += `
		AND x509_notAfter(c.CERTIFICATE) > now() AT TIME ZONE 'UTC'`
	}
	if deduplicate {
		query += `
		AND NOT EXISTS (
			SELECT 1
				FROM certificate c2
				WHERE x509_serialNumber(c2.CERTIFICATE) = x509_serialNumber(c.CERTIFICATE)
					AND c2.ISSUER_CA_ID = c.ISSUER_CA_ID
					AND c2.ID < c.ID
					AND x509_tbscert_strip_ct_ext(c2.CERTIFICATE) = x509_tbscert_strip_ct_ext(c.CERTIFICATE)
				LIMIT 1
		)`
	}

	// Main loop: repeatedly run the query to search batches of certificate records.
	maxCertificateID := int64(-1)
	var thisBatchSize int64
	var sleepFor time.Duration
for_loop:
	for i := startID; i < endID; i += thisBatchSize {
		if sleepFor > 0 {
			logrus.WithFields(logrus.Fields{"sleep_for": sleepFor}).Debug("Sleeping")
		}

		select {
		case <-time.After(sleepFor):
		case <-ctx.Done():
			logrus.WithFields(logrus.Fields{"last": i - 1}).Debug("Interrupted")
			break for_loop
		}

		sleepFor = time.Second * 15

		if maxCertificateID <= i {
			// Get the latest certificate ID.
			if err = crtsh.QueryRow(context.Background(), "SELECT max(ID) FROM certificate").Scan(&maxCertificateID); err != nil {
				logrus.WithFields(logrus.Fields{"err": err}).Error("Could not obtain latest ID")
				continue
			} else {
				logrus.WithFields(logrus.Fields{"latest_id": maxCertificateID}).Debug("Obtained latest ID")
			}

			if i == -1 {
				startID = maxCertificateID + 1
				i = startID
			}
			if maxCertificateID > endID {
				maxCertificateID = endID
			}
		}

		if thisBatchSize = maxCertificateID - i + 1; thisBatchSize >= batchSize {
			thisBatchSize = batchSize // Enforce the maximum batch size.
			sleepFor = 0              // No need to sleep after this batch.
		} else if thisBatchSize <= 0 {
			logrus.Debug("No more certificates available yet")
			continue
		}

		logrus.WithFields(logrus.Fields{"first": i, "last": i + thisBatchSize - 1}).Debug("Batch start")

		// Get batch of results.
		var rows pgx.Rows
		if rows, err = crtsh.Query(context.Background(), query, i, i+thisBatchSize-1, q); err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Error("Could not obtain batch of results")
			continue
		}
		defer rows.Close()

		// Process results.
		var n int64
		var certificateID int64
		var dNSName string
		var notAfter time.Time
		for rows.Next() {
			if err = rows.Scan(&certificateID, &dNSName, &notAfter); err != nil {
				logrus.WithFields(logrus.Fields{"err": err}).Error("Could not scan result")
				break for_loop
			}

			logrus.WithFields(logrus.Fields{"certificate_id": certificateID, "dns_name": dNSName, "not_after": notAfter}).Info("Record found")
		}

		logrus.WithFields(logrus.Fields{"first": i, "last": i + thisBatchSize - 1, "count": n}).Debug("Batch end")
	}
}
