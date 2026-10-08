package main

import (
	"context"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	uri := os.Getenv("MONGO_URI")
	client, _ := mongo.Connect(context.Background(), options.Client().ApplyURI(uri))
	col := client.Database("honeypot_db").Collection("logs")

	filter := bson.M{"sensor_id": bson.M{"$exists": false}}
	update := bson.M{"$set": bson.M{"sensor_id": "vm-honeypot"}}

	res, err := col.UpdateMany(context.Background(), filter, update)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Updated %d documents via exists false", res.ModifiedCount)

    filter2 := bson.M{"sensor_id": ""}
	res2, _ := col.UpdateMany(context.Background(), filter2, update)
	log.Printf("Updated %d documents via empty string", res2.ModifiedCount)
}
