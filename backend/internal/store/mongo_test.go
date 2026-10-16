package store

import (
	"errors"
	"testing"

	"go.mongodb.org/mongo-driver/mongo"
)

func TestOnlyDuplicates(t *testing.T) {
	dup := mongo.BulkWriteException{WriteErrors: []mongo.BulkWriteError{{WriteError: mongo.WriteError{Code: 11000}}}}
	mixed := mongo.BulkWriteException{WriteErrors: []mongo.BulkWriteError{
		{WriteError: mongo.WriteError{Code: 11000}}, {WriteError: mongo.WriteError{Code: 16500}}}}
	if !onlyDuplicates(dup) {
		t.Error("all duplicate-key errors mean the rows already exist")
	}
	if onlyDuplicates(mixed) {
		t.Error("a throttled (16500) row still has to be retried")
	}
	if onlyDuplicates(errors.New("network")) {
		t.Error("non-bulk errors are not duplicates")
	}
}
