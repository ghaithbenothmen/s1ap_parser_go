// Package db provides MongoDB connectivity and operations for S1AP analyzer
package db

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Connect établit une connexion à MongoDB et renvoie un handle vers la collection spécifiée.
// Si la connexion échoue, il logue une erreur et renvoie nil.
func Connect(uri, dbName, collectionName string) *mongo.Collection {
	log.Printf("Connecting to MongoDB at %s...", uri)

	// Créer un client avec les options spécifiées.
	clientOptions := options.Client().ApplyURI(uri)

	// Utiliser un contexte avec un timeout pour la tentative de connexion.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connexion à MongoDB.
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Printf("ERROR: Failed to create MongoDB client: %v", err)
		return nil
	}

	// Vérifier que la connexion a été établie avec succès.
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Printf("ERROR: Failed to connect to MongoDB: %v", err)
		return nil
	}

	log.Println("Successfully connected to MongoDB!")
	collection := client.Database(dbName).Collection(collectionName)

	// Créer des index pour optimiser les requêtes de session
	CreateSessionIndexes(collection)

	return collection
}

// CreateSessionIndexes crée les index nécessaires pour optimiser les requêtes de session UE
func CreateSessionIndexes(collection *mongo.Collection) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Index pour eNB_UE_S1AP_ID (clé principale pour identifier les sessions)
	enbIndex := mongo.IndexModel{
		Keys:    bson.D{{"enb_ue_s1ap_id", 1}},
		Options: options.Index().SetName("enb_ue_s1ap_id_index"),
	}

	// Index composé pour eNB_UE_S1AP_ID + MME_UE_S1AP_ID
	compositeIndex := mongo.IndexModel{
		Keys: bson.D{
			{"enb_ue_s1ap_id", 1},
			{"mme_ue_s1ap_id", 1},
		},
		Options: options.Index().SetName("ue_identifiers_index"),
	}

	// Index pour session_id
	sessionIndex := mongo.IndexModel{
		Keys:    bson.D{{"session_id", 1}},
		Options: options.Index().SetName("session_id_index").SetUnique(true),
	}

	// Index pour timestamp (pour requêtes temporelles)
	timestampIndex := mongo.IndexModel{
		Keys:    bson.D{{"creation_timestamp", -1}},
		Options: options.Index().SetName("creation_timestamp_index"),
	}

	// Index pour statut
	statusIndex := mongo.IndexModel{
		Keys:    bson.D{{"status", 1}},
		Options: options.Index().SetName("status_index"),
	}

	indexes := []mongo.IndexModel{enbIndex, compositeIndex, sessionIndex, timestampIndex, statusIndex}

	_, err := collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		log.Printf("WARNING: Failed to create indexes: %v", err)
	} else {
		log.Println("MongoDB indexes created successfully")
	}
}
