// Command dedupe finds events stored more than once and (only with -apply) deletes
// the extra copies. Earlier versions re-inserted whole batches when the database
// throttled a request, which duplicated rows.
//
//	dedupe -file logs.ndjson.gz                 # analyse an export, changes nothing
//	dedupe -env /path/.env                      # dry run against the database
//	dedupe -env /path/.env -apply               # delete the extra copies
//
// The copy with the oldest _id is kept. Duplicates are detected with the same
// content fingerprint the server uses.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"sec_dash/backend/internal/ingest"
	"sec_dash/backend/internal/model"
)

type doc struct {
	ID interface{}
	FP string
}

func toDoc(raw bson.M) (doc, bool) {
	b, err := bson.Marshal(raw)
	if err != nil {
		return doc{}, false
	}
	var s model.Stored
	if err := bson.Unmarshal(b, &s); err != nil || s.EventID == "" {
		return doc{}, false
	}
	return doc{ID: raw["_id"], FP: ingest.FromStored(&s).Fingerprint()}, true
}

// extras returns the _ids to delete: every copy except the first of each fingerprint.
func extras(docs []doc) (ids []interface{}, groups int) {
	seen := map[string]bool{}
	dupGroup := map[string]bool{}
	for _, d := range docs {
		if seen[d.FP] {
			ids = append(ids, d.ID)
			if !dupGroup[d.FP] {
				dupGroup[d.FP] = true
				groups++
			}
			continue
		}
		seen[d.FP] = true
	}
	return
}

func main() {
	file := flag.String("file", "", "analyse an exported logs.ndjson.gz instead of the database")
	envFile := flag.String("env", "", ".env file providing MONGO_URI")
	apply := flag.Bool("apply", false, "delete the duplicate rows (default: dry run)")
	flag.Parse()

	var docs []doc
	var client *mongo.Client
	var coll *mongo.Collection
	ctx := context.Background()

	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			log.Fatal(err)
		}
		sc := bufio.NewScanner(gz)
		sc.Buffer(make([]byte, 1<<20), 8<<20)
		for sc.Scan() {
			var raw bson.M
			if err := bson.UnmarshalExtJSON(sc.Bytes(), false, &raw); err != nil {
				continue
			}
			if d, ok := toDoc(raw); ok {
				docs = append(docs, d)
			}
		}
		if *apply {
			log.Fatal("-apply only works against the database, not an export file")
		}
	} else {
		if *envFile != "" {
			if err := godotenv.Load(*envFile); err != nil {
				log.Fatal(err)
			}
		}
		uri := os.Getenv("MONGO_URI")
		if uri == "" {
			log.Fatal("MONGO_URI is not set")
		}
		var err error
		client, err = mongo.Connect(ctx, options.Client().ApplyURI(uri))
		if err != nil {
			log.Fatal(err)
		}
		defer client.Disconnect(ctx)
		coll = client.Database("honeypot_db").Collection("logs")
		cur, err := coll.Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}).SetBatchSize(1000))
		if err != nil {
			log.Fatal(err)
		}
		for cur.Next(ctx) {
			var raw bson.M
			if cur.Decode(&raw) == nil {
				if d, ok := toDoc(raw); ok {
					docs = append(docs, d)
				}
			}
		}
		if err := cur.Err(); err != nil {
			log.Fatal(err)
		}
	}

	ids, groups := extras(docs)
	fmt.Printf("%d events read, %d duplicate copies in %d groups\n", len(docs), len(ids), groups)
	if len(ids) == 0 || !*apply {
		if len(ids) > 0 {
			fmt.Println("dry run: nothing deleted (use -apply to delete)")
		}
		return
	}
	deleted := 0
	for i := 0; i < len(ids); i += 100 {
		end := i + 100
		if end > len(ids) {
			end = len(ids)
		}
		var res *mongo.DeleteResult
		var err error
		for try := 0; try < 6; try++ {
			res, err = coll.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids[i:end]}})
			if err == nil {
				break
			}
			time.Sleep(time.Duration(try+1) * 2 * time.Second) // Cosmos DB throttling
		}
		if err != nil {
			log.Fatalf("delete failed after %d rows: %v", deleted, err)
		}
		deleted += int(res.DeletedCount)
	}
	fmt.Printf("deleted %d duplicate rows\n", deleted)
}
