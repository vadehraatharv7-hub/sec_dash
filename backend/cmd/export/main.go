// Command export dumps every collection of the SecDash database to
// newline-delimited extended JSON (one file per collection, gzip-compressed).
//
//	export -env /path/to/.env -out ./export
//
// Account credentials and signing secrets (dash_users, dash_settings) are skipped
// unless named explicitly with -include.
package main

import (
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func retry(n int, fn func() error) error {
	var err error
	for i := 0; i < n; i++ {
		if err = fn(); err == nil {
			return nil
		}
		time.Sleep(time.Duration(i+1) * 2 * time.Second) // Cosmos DB throttles with 429s
	}
	return err
}

func main() {
	envFile := flag.String("env", "", "optional .env file providing MONGO_URI")
	out := flag.String("out", "export", "output directory")
	dbName := flag.String("db", "honeypot_db", "database name")
	include := flag.String("include", "", "comma-separated collections to export even if normally skipped")
	flag.Parse()
	if *envFile != "" {
		if err := godotenv.Load(*envFile); err != nil {
			log.Fatalf("loading %s: %v", *envFile, err)
		}
	}
	uri := os.Getenv("MONGO_URI")
	if uri == "" {
		log.Fatal("MONGO_URI is not set")
	}
	skip := map[string]bool{"dash_users": true, "dash_settings": true}
	for _, c := range strings.Split(*include, ",") {
		delete(skip, strings.TrimSpace(c))
	}

	ctx := context.Background()
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	client, err := mongo.Connect(cctx, options.Client().ApplyURI(uri))
	cancel()
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Disconnect(ctx)
	db := client.Database(*dbName)

	var names []string
	if err := retry(4, func() (e error) { names, e = db.ListCollectionNames(ctx, bson.M{}); return }); err != nil {
		log.Fatalf("listing collections: %v", err)
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		log.Fatal(err)
	}

	for _, name := range names {
		if skip[name] || strings.HasPrefix(name, "system.") {
			fmt.Printf("%-16s skipped\n", name)
			continue
		}
		n, err := dump(ctx, db.Collection(name), filepath.Join(*out, name+".ndjson.gz"))
		if err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		fmt.Printf("%-16s %d documents\n", name, n)
	}
}

// dump pages through a collection by _id so a throttled request only retries one page.
func dump(ctx context.Context, c *mongo.Collection, path string) (int, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()

	total := 0
	// Small collections may mix _id types (ObjectId and string), which _id paging would
	// skip, so they are read in one query.
	var count int64
	_ = retry(4, func() (e error) { count, e = c.EstimatedDocumentCount(ctx); return })
	if count <= 5000 {
		var docs []bson.M
		err := retry(6, func() error {
			cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			cur, err := c.Find(cctx, bson.M{})
			if err != nil {
				return err
			}
			defer cur.Close(cctx)
			docs = docs[:0]
			return cur.All(cctx, &docs)
		})
		if err != nil {
			return 0, err
		}
		for _, d := range docs {
			b, err := bson.MarshalExtJSON(d, false, false)
			if err != nil {
				return total, err
			}
			gz.Write(b)
			gz.Write([]byte("\n"))
			total++
		}
		return total, nil
	}
	var last interface{}
	for {
		filter := bson.M{}
		if last != nil {
			filter["_id"] = bson.M{"$gt": last}
		}
		var docs []bson.M
		err := retry(6, func() error {
			cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			cur, err := c.Find(cctx, filter, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}).SetLimit(1000))
			if err != nil {
				return err
			}
			defer cur.Close(cctx)
			docs = docs[:0]
			return cur.All(cctx, &docs)
		})
		if err != nil {
			return total, err
		}
		if len(docs) == 0 {
			return total, nil
		}
		for _, d := range docs {
			b, err := bson.MarshalExtJSON(d, false, false)
			if err != nil {
				return total, err
			}
			gz.Write(b)
			gz.Write([]byte("\n"))
			total++
		}
		last = docs[len(docs)-1]["_id"]
		if last == nil {
			return total, fmt.Errorf("document without _id")
		}
	}
}
