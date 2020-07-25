package helper

import (
	"context"
	"fmt"
	"github.com/DimitrenkoDA/auth-service-go/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"log"
	"os"
)

func ConnectionDB() (*mongo.Client, error){
	mongoURL := "mongodb://localhost:27017,127.0.0.1:27017/?replicaSet=rs0"

	if uri := os.Getenv("MONGODB_URI"); len(uri) > 0 {
		mongoURL = fmt.Sprintf("%s?retryWrites=false", uri)
	}

	clientOptions := options.Client().ApplyURI(mongoURL)

	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Connected to MongoDB!")

	err = client.Ping(context.TODO(), readpref.Primary())
	if err != nil {
		log.Fatal(err)
	}

	return client, err
}

func PrepareWorkplace() error{

	client, err := ConnectionDB()
	if err != nil {
		log.Fatal(err)
	}

	database := client.Database("auth-service-go")
	collection := database.Collection("tokens")

	var example models.Token

	insertResult, err := collection.InsertOne(context.TODO(), example)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(insertResult.InsertedID)

	filter := bson.M{"_id": insertResult.InsertedID}

	removeResult, err := collection.DeleteOne(context.TODO(), filter)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(removeResult.DeletedCount)

	return err
}

func DisconnectionDB(client mongo.Client) error{
	err := client.Disconnect(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	return err
}

