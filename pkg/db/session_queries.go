// Package db provides MongoDB session query utilities for S1AP analyzer
package db

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// UeSessionSummary représente un résumé de session UE
type UeSessionSummary struct {
	SessionID         string         `bson:"session_id"`
	MmeUeS1apID       int64          `bson:"mme_ue_s1ap_id,omitempty"`
	EnbUeS1apID       int64          `bson:"enb_ue_s1ap_id"`
	Status            string         `bson:"status"`
	CreationTimestamp time.Time      `bson:"creation_timestamp"`
	LastUpdate        time.Time      `bson:"last_update"`
	MessageCount      int            `bson:"message_count"`
	ProcedureStats    map[string]int `bson:"procedure_stats,omitempty"`
	FirstProcedure    string         `bson:"first_procedure,omitempty"`
	LastProcedure     string         `bson:"last_procedure,omitempty"`
	Duration          time.Duration  `bson:"-"` // Calculé dynamiquement
}

// SessionQueryOptions options pour les requêtes de session
type SessionQueryOptions struct {
	EnbID     *int64
	MmeID     *int64
	Status    string
	Limit     int64
	Skip      int64
	SortBy    string // "creation_timestamp", "last_update", "message_count"
	SortOrder int    // 1 pour croissant, -1 pour décroissant
}

// FindSessionsByEnbID trouve toutes les sessions d'un eNB spécifique
func FindSessionsByEnbID(collection *mongo.Collection, enbID int64, limit int64) ([]UeSessionSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	filter := bson.M{"enb_ue_s1ap_id": enbID}
	opts := options.Find().SetLimit(limit).SetSort(bson.M{"creation_timestamp": -1})

	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var sessions []UeSessionSummary
	for cursor.Next(ctx) {
		var session UeSessionSummary
		if err := cursor.Decode(&session); err != nil {
			continue
		}
		session.Duration = session.LastUpdate.Sub(session.CreationTimestamp)
		sessions = append(sessions, session)
	}

	return sessions, cursor.Err()
}

// FindActiveSessionsByEnbID trouve les sessions actives d'un eNB
func FindActiveSessionsByEnbID(collection *mongo.Collection, enbID int64) ([]UeSessionSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	filter := bson.M{
		"enb_ue_s1ap_id": enbID,
		"status":         "active",
	}
	opts := options.Find().SetSort(bson.M{"creation_timestamp": -1})

	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var sessions []UeSessionSummary
	for cursor.Next(ctx) {
		var session UeSessionSummary
		if err := cursor.Decode(&session); err != nil {
			continue
		}
		session.Duration = session.LastUpdate.Sub(session.CreationTimestamp)
		sessions = append(sessions, session)
	}

	return sessions, cursor.Err()
}

// FindSessionByUeIDs trouve une session spécifique par eNB et MME IDs
func FindSessionByUeIDs(collection *mongo.Collection, enbID, mmeID int64) (*UeSessionSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{
		"enb_ue_s1ap_id": enbID,
		"mme_ue_s1ap_id": mmeID,
	}

	var session UeSessionSummary
	err := collection.FindOne(ctx, filter).Decode(&session)
	if err != nil {
		return nil, err
	}

	session.Duration = session.LastUpdate.Sub(session.CreationTimestamp)
	return &session, nil
}

// GetSessionStatistics retourne des statistiques globales des sessions
func GetSessionStatistics(collection *mongo.Collection) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pipeline := []bson.M{
		{
			"$group": bson.M{
				"_id":                      nil,
				"total_sessions":           bson.M{"$sum": 1},
				"active_sessions":          bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$status", "active"}}, 1, 0}}},
				"released_sessions":        bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$status", "released"}}, 1, 0}}},
				"total_messages":           bson.M{"$sum": "$message_count"},
				"avg_messages_per_session": bson.M{"$avg": "$message_count"},
				"max_messages_per_session": bson.M{"$max": "$message_count"},
				"min_messages_per_session": bson.M{"$min": "$message_count"},
			},
		},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var result []map[string]interface{}
	if err := cursor.All(ctx, &result); err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return map[string]interface{}{
			"total_sessions":    0,
			"active_sessions":   0,
			"released_sessions": 0,
			"total_messages":    0,
		}, nil
	}

	return result[0], nil
}

// GetTopProceduresByEnbID retourne les procédures les plus fréquentes pour un eNB
func GetTopProceduresByEnbID(collection *mongo.Collection, enbID int64, limit int) ([]bson.M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pipeline := []bson.M{
		{"$match": bson.M{"enb_ue_s1ap_id": enbID}},
		{"$unwind": "$messages"},
		{
			"$group": bson.M{
				"_id":   "$messages.procedure_name",
				"count": bson.M{"$sum": 1},
			},
		},
		{"$sort": bson.M{"count": -1}},
		{"$limit": limit},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []bson.M
	return results, cursor.All(ctx, &results)
}

// FindSessionsWithQuery trouve des sessions selon des critères personnalisés
func FindSessionsWithQuery(collection *mongo.Collection, opts SessionQueryOptions) ([]UeSessionSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Construire le filtre
	filter := bson.M{}

	if opts.EnbID != nil {
		filter["enb_ue_s1ap_id"] = *opts.EnbID
	}

	if opts.MmeID != nil {
		filter["mme_ue_s1ap_id"] = *opts.MmeID
	}

	if opts.Status != "" {
		filter["status"] = opts.Status
	}

	// Options de requête
	findOpts := options.Find()

	if opts.Limit > 0 {
		findOpts.SetLimit(opts.Limit)
	}

	if opts.Skip > 0 {
		findOpts.SetSkip(opts.Skip)
	}

	// Tri
	sortField := "creation_timestamp"
	if opts.SortBy != "" {
		sortField = opts.SortBy
	}

	sortOrder := -1 // décroissant par défaut
	if opts.SortOrder != 0 {
		sortOrder = opts.SortOrder
	}

	findOpts.SetSort(bson.M{sortField: sortOrder})

	cursor, err := collection.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var sessions []UeSessionSummary
	for cursor.Next(ctx) {
		var session UeSessionSummary
		if err := cursor.Decode(&session); err != nil {
			continue
		}
		session.Duration = session.LastUpdate.Sub(session.CreationTimestamp)
		sessions = append(sessions, session)
	}

	return sessions, cursor.Err()
}
