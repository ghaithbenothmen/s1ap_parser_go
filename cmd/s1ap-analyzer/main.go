// Package main provides a comprehensive S1AP protocol analyzer for PCAP files.
//
// This tool analyzes S1AP (S1 Application Protocol) messages from PCAP files,
// providing detailed information about procedure types, message counts, and statistics.
//
// Usage:
//   s1ap-analyzer [options] <pcap-file>
//
// Options:
//   -format string    Output format: detailed, simple, json (default "simple")
//   -limit int        Limit number of packets to analyze (default: all)
//   -stats           Show statistics summary only
//   -debug           Enable debug output for troubleshooting
//   -help            Show this help message
//
// Examples:
//   s1ap-analyzer capture.pcap
//   s1ap-analyzer -format detailed -limit 1000 capture.pcap
//   s1ap-analyzer -stats capture.pcap
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/coreswitch/coreswitch/pkg/s1ap"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"github.com/coreswitch/coreswitch/pkg/db"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// OutputFormat represents the different output formats supported
type OutputFormat string

const (
	FormatSimple   OutputFormat = "simple"
	FormatDetailed OutputFormat = "detailed"
	FormatJSON     OutputFormat = "json"
)

// Config holds the application configuration
type Config struct {
	PcapFile        string
	Format          OutputFormat
	Limit           int
	StatsOnly       bool
	Debug           bool
	ShowHelp        bool
	MongoStore      bool   
	MongoURI        string 
	MongoDB         string 
	MongoCollection string 
	SessionsFile    string // Path to store completed sessions JSON file
}

// S1APMessage represents a parsed S1AP message
type S1APMessage struct {
	PacketNumber   int                          `json:"packet_number"`
	Timestamp      time.Time                    `json:"timestamp"`
	SrcIP          string                       `json:"src_ip"`
	DstIP          string                       `json:"dst_ip"`
	PDUType        string                       `json:"pdu_type"`
	PDUTypeCode    int                          `json:"pdu_type_code"`
	ProcedureName  string                       `json:"procedure_name"`
	ProcedureCode  int                          `json:"procedure_code"`
	Criticality    string                       `json:"criticality"`
	MessageIndex   int                          `json:"message_index,omitempty"`
	TotalMessages  int                          `json:"total_messages,omitempty"`
	IEs            []*s1ap.InformationElement   `json:"information_elements,omitempty"`
}

// Statistics holds analysis statistics
type Statistics struct {
	TotalFrames      int                `json:"total_frames"`
	S1APFrames       int                `json:"s1ap_frames"`
	SuccessfulDecodes int               `json:"successful_decodes"`
	FailedDecodes    int                `json:"failed_decodes"`
	ProcedureStats   map[string]int     `json:"procedure_stats"`
	ProcessingTime   time.Duration      `json:"processing_time"`
	StartTime        time.Time          `json:"start_time"`
	EndTime          time.Time          `json:"end_time"`
	CompletedSessions int               `json:"completed_sessions"`
}

// UeSessionDocument représente une session UE dans MongoDB
type UeSessionDocument struct {
	SessionID         string          `bson:"session_id"` // Format: "enbID_mmeID" ou "enbID_temp" si mmeID pas encore connu
	MmeUeS1apID       int64           `bson:"mme_ue_s1ap_id,omitempty"`
	EnbUeS1apID       int64           `bson:"enb_ue_s1ap_id"` // Toujours présent dès le début
	SrcIP             string          `bson:"src_ip"`
	DstIP             string          `bson:"dst_ip"`
	Status            string          `bson:"status"` // "active", "released", "error"
	CreationTimestamp time.Time       `bson:"creation_timestamp"`
	LastUpdate        time.Time       `bson:"last_update"`
	MessageCount      int             `bson:"message_count"` // Compteur de messages dans la session
	Messages          []*S1APMessage  `bson:"messages"`
	
	// Statistiques de session
	ProcedureStats    map[string]int  `bson:"procedure_stats,omitempty"` // Compteur par type de procédure
	FirstProcedure    string          `bson:"first_procedure,omitempty"`
	LastProcedure     string          `bson:"last_procedure,omitempty"`
}

func main() {
	config := parseFlags()
	
	if config.ShowHelp {
		flag.Usage()
		os.Exit(0)
	}

	if config.PcapFile == "" {
		fmt.Fprintf(os.Stderr, "Error: PCAP file is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	analyzer := NewAnalyzer(config)
	if err := analyzer.Run(); err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}
}

func parseFlags() *Config {
	config := &Config{}
	
	flag.StringVar((*string)(&config.Format), "format", "simple", "Output format: simple, detailed, json")
	flag.IntVar(&config.Limit, "limit", 0, "Limit number of packets to analyze (0 = no limit)")
	flag.BoolVar(&config.StatsOnly, "stats", false, "Show statistics summary only")
	flag.BoolVar(&config.Debug, "debug", false, "Enable debug output")
	flag.BoolVar(&config.ShowHelp, "help", false, "Show help message")

	// AJOUTÉ : Drapeaux pour la configuration de MongoDB
	flag.BoolVar(&config.MongoStore, "mongo-store", false, "Enable storing results in MongoDB")
	flag.StringVar(&config.MongoURI, "mongo-uri", "mongodb://10.200.0.21:27017", "MongoDB connection URI")
	flag.StringVar(&config.MongoDB, "mongo-db", "s1ap_db", "MongoDB database name")
	flag.StringVar(&config.MongoCollection, "mongo-collection", "messages", "MongoDB collection name for S1AP messages")
	flag.StringVar(&config.SessionsFile, "sessions-file", "completed_sessions.json", "Path to store completed sessions JSON file")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "S1AP Protocol Analyzer\n")
		fmt.Fprintf(os.Stderr, "======================\n\n")
		fmt.Fprintf(os.Stderr, "A professional tool for analyzing S1AP messages in PCAP files.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <pcap-file>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s capture.pcap\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -format detailed -limit 1000 capture.pcap\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -stats capture.pcap\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "\nMongoDB Options:\n")
		fmt.Fprintf(os.Stderr, "  -mongo-store\n\tEnable storing results in MongoDB.\n")
		fmt.Fprintf(os.Stderr, "  -mongo-uri string\n\tMongoDB connection URI. (default \"mongodb://10.200.0.21:27017\")\n")
		fmt.Fprintf(os.Stderr, "  -mongo-db string\n\tMongoDB database name. (default \"s1ap_db\")\n")
		fmt.Fprintf(os.Stderr, "  -mongo-collection string\n\tMongoDB collection name. (default \"messages\")\n")
		fmt.Fprintf(os.Stderr, "  -sessions-file string\n\tPath to store completed sessions JSON file. (default \"completed_sessions.json\")\n")
	}
	
	flag.Parse()
	
	if flag.NArg() > 0 {
		config.PcapFile = flag.Arg(0)
	}
	
	return config
}

// Analyzer handles the S1AP analysis process
type Analyzer struct {
	config *Config
	stats  *Statistics
	mongoCollection *mongo.Collection 
	sessionsFileMutex sync.Mutex // Protects concurrent access to sessions file
	activeSessionHandlers sync.WaitGroup // Tracks active session completion handlers
}

// NewAnalyzer creates a new analyzer instance
func NewAnalyzer(config *Config) *Analyzer {
	analyzer := &Analyzer{
		config: config,
		stats: &Statistics{
			ProcedureStats: make(map[string]int),
			StartTime:      time.Now(),
		},
	}

	// Configuration MongoDB
	if config.MongoStore {
		collection := db.Connect(config.MongoURI, config.MongoDB, config.MongoCollection)
		if collection == nil {
			log.Fatal("Could not establish MongoDB connection. Aborting.")
		}
		analyzer.mongoCollection = collection
		log.Printf("INFO: MongoDB storage enabled - DB: %s, Collection: %s", config.MongoDB, config.MongoCollection)
		log.Printf("INFO: Completed sessions will be saved to: %s", config.SessionsFile)
		
		// Initialiser le fichier de sessions si nécessaire
		analyzer.initializeSessionsFile()
	}

	return analyzer
}

// initializeSessionsFile crée le fichier de sessions s'il n'existe pas
func (a *Analyzer) initializeSessionsFile() {
	if _, err := os.Stat(a.config.SessionsFile); os.IsNotExist(err) {
		// Créer un fichier JSON vide avec un tableau
		emptyArray := []interface{}{}
		data, err := json.MarshalIndent(emptyArray, "", "  ")
		if err != nil {
			log.Printf("WARN: Failed to initialize sessions file: %v", err)
			return
		}
		
		if err := os.WriteFile(a.config.SessionsFile, data, 0644); err != nil {
			log.Printf("WARN: Failed to create sessions file: %v", err)
		} else {
			log.Printf("INFO: Created new sessions file: %s", a.config.SessionsFile)
		}
	} else {
		log.Printf("INFO: Using existing sessions file: %s", a.config.SessionsFile)
	}
}


// Run executes the analysis
func (a *Analyzer) Run() error {
	defer func() {
		// Attendre que tous les gestionnaires de session se terminent
		if a.config.MongoStore {
			log.Printf("INFO: Waiting for session completion handlers to finish...")
			a.activeSessionHandlers.Wait()
		}
		
		a.stats.EndTime = time.Now()
		a.stats.ProcessingTime = a.stats.EndTime.Sub(a.stats.StartTime)
	}()

	if !a.config.StatsOnly && a.config.Format != FormatJSON {
		a.printHeader()
	}

	handle, err := pcap.OpenOffline(a.config.PcapFile)
	if err != nil {
		return fmt.Errorf("failed to open PCAP file: %w", err)
	}
	defer handle.Close()

	var processedMessages []*S1APMessage
	if a.config.MongoStore {
		// Si mongo est activé, nous traitons et stockons en temps réel
		if err := a.analyzeAndStorePackets(handle); err != nil {
			return fmt.Errorf("packet analysis and storage failed: %w", err)
		}
		// Pour l'affichage final, nous laissons la slice vide pour l'instant.
		// On pourrait la remplir si nécessaire, mais l'objectif principal est le stockage.
	} else {
		// Comportement original si mongo n'est pas activé
		processedMessages, err = a.analyzePackets(handle)
		if err != nil {
			return fmt.Errorf("packet analysis failed: %w", err)
		}
	}

	return a.outputResults(processedMessages)
}

func (a *Analyzer) extractUeIdentifiers(msg *S1APMessage) (mmeID, enbID int64) {
	mmeID, enbID = -1, -1 // Valeurs par défaut si non trouvés

	for _, ie := range msg.IEs {
		switch ie.ID {
		case 0: // id_MME_UE_S1AP_ID
			if val, ok := ie.Value.(int32); ok {
				mmeID = int64(val)
			} else if val, ok := ie.Value.(int64); ok {
				mmeID = val
			} else if val, ok := ie.Value.(int); ok {
				mmeID = int64(val)
			} else if ie.RawValue != "" && ie.RawValue != "Binary data not extracted" && ie.RawValue != "Fallback placeholder" {
				if parsedVal, err := strconv.ParseInt(ie.RawValue, 10, 64); err == nil {
					mmeID = parsedVal
				}
			}
		case 8: // id_eNB_UE_S1AP_ID
			if val, ok := ie.Value.(int32); ok {
				enbID = int64(val)
			} else if val, ok := ie.Value.(int64); ok {
				enbID = val
			} else if val, ok := ie.Value.(int); ok {
				enbID = int64(val)
			} else if ie.RawValue != "" && ie.RawValue != "Binary data not extracted" && ie.RawValue != "Fallback placeholder" {
				if parsedVal, err := strconv.ParseInt(ie.RawValue, 10, 64); err == nil {
					enbID = parsedVal
				}
			}
		}
	}
	
	// Debug pour tous les messages qui ont des identifiants UE
	if (mmeID != -1 || enbID != -1) && a.config.Debug {
		log.Printf("DEBUG: %s - MME_UE_S1AP_ID: %d, eNB_UE_S1AP_ID: %d (Total IEs: %d)", 
			msg.ProcedureName, mmeID, enbID, len(msg.IEs))
		for i, ie := range msg.IEs {
			log.Printf("DEBUG: IE[%d] - ID: %d, Name: %s, Value: %v (type: %T), RawValue: %s", 
				i, ie.ID, ie.Name, ie.Value, ie.Value, ie.RawValue)
		}
	}

	return mmeID, enbID
}

// handlePagingMessage traite les messages de paging qui peuvent contenir des identifiants UE
func (a *Analyzer) handlePagingMessage(msg *S1APMessage) error {
	// Dans Paging, les identifiants UE peuvent être dans UEPagingID ou S-TMSI
	var ueIdentifier string

	for _, ie := range msg.IEs {
		switch ie.ID {
		case 43: // id_UEPagingID
			if ie.RawValue != "" {
				ueIdentifier = ie.RawValue
			}
		case 96: // id_S_TMSI
			if ie.RawValue != "" {
				ueIdentifier = ie.RawValue
			}
		case 89: // id_MMEname (peut aider à identifier la source)
			// Pour information additionnelle
		}
	}

	if ueIdentifier != "" && a.config.Debug {
		log.Printf("DEBUG: Paging message with UE identifier: %s (Packet %d)", ueIdentifier, msg.PacketNumber)
	}

	// Pour l'instant, on ne les ajoute pas aux sessions UE car ils n'ont pas d'eNB_UE_S1AP_ID
	// mais on pourrait les traiter séparément ou les ajouter à une collection de messages généraux
	return nil
}

// handleDownlinkNASTransport traite les messages DownlinkNASTransport qui devraient avoir des identifiants UE
func (a *Analyzer) handleDownlinkNASTransport(msg *S1APMessage) error {
	// DownlinkNASTransport devrait normalement avoir MME_UE_S1AP_ID et eNB_UE_S1AP_ID
	// Si ils ne sont pas détectés, c'est peut-être un problème d'extraction
	
	if a.config.Debug {
		log.Printf("DEBUG: DownlinkNASTransport IEs analysis:")
		for i, ie := range msg.IEs {
			log.Printf("DEBUG: IE[%d] - ID: %d, Name: %s, Value: %v, RawValue: %s", 
				i, ie.ID, ie.Name, ie.Value, ie.RawValue)
		}
	}

	// Essayer d'extraire des identifiants avec une logique plus permissive
	mmeID, enbID := a.extractUeIdentifiersExtended(msg)
	
	if enbID != -1 {
		return a.addMessageToSession(msg, mmeID, enbID)
	}

	return nil
}

// handleMessageWithAlternativeIdentifiers essaie d'extraire des identifiants alternatifs
func (a *Analyzer) handleMessageWithAlternativeIdentifiers(msg *S1APMessage) error {
	// Essayer d'extraire des identifiants avec une logique étendue
	mmeID, enbID := a.extractUeIdentifiersExtended(msg)
	
	if enbID != -1 {
		return a.addMessageToSession(msg, mmeID, enbID)
	}
	
	// Si pas d'identifiants trouvés, debug et ignorer
	if a.config.Debug {
		log.Printf("DEBUG: No UE identifiers found for %s (Packet %d)", msg.ProcedureName, msg.PacketNumber)
	}
	
	return nil
}

// extractUeIdentifiersExtended utilise une logique plus permissive pour extraire les identifiants UE
func (a *Analyzer) extractUeIdentifiersExtended(msg *S1APMessage) (mmeID, enbID int64) {
	mmeID, enbID = -1, -1

	for _, ie := range msg.IEs {
		switch ie.ID {
		case 0: // id_MME_UE_S1AP_ID
			if val, ok := ie.Value.(int32); ok {
				mmeID = int64(val)
			} else if val, ok := ie.Value.(int64); ok {
				mmeID = val
			} else if val, ok := ie.Value.(int); ok {
				mmeID = int64(val)
			} else if ie.RawValue != "" && ie.RawValue != "Binary data not extracted" && ie.RawValue != "Fallback placeholder" {
				if parsedVal, err := strconv.ParseInt(ie.RawValue, 10, 64); err == nil {
					mmeID = parsedVal
				}
			}
		case 8: // id_eNB_UE_S1AP_ID
			if val, ok := ie.Value.(int32); ok {
				enbID = int64(val)
			} else if val, ok := ie.Value.(int64); ok {
				enbID = val
			} else if val, ok := ie.Value.(int); ok {
				enbID = int64(val)
			} else if ie.RawValue != "" && ie.RawValue != "Binary data not extracted" && ie.RawValue != "Fallback placeholder" {
				if parsedVal, err := strconv.ParseInt(ie.RawValue, 10, 64); err == nil {
					enbID = parsedVal
				}
			}
		}
		
		// Pour debug - montrer tous les IEs potentiels
		if a.config.Debug && (ie.ID == 0 || ie.ID == 8) {
			log.Printf("DEBUG: Extended extraction - IE ID: %d, Name: %s, Value: %v (type: %T), RawValue: %s", 
				ie.ID, ie.Name, ie.Value, ie.Value, ie.RawValue)
		}
	}

	return mmeID, enbID
}

// processAndStoreMessage traite et stocke un message S1AP dans MongoDB
// avec gestion des sessions UE basée sur eNB_UE_S1AP_ID
func (a *Analyzer) processAndStoreMessage(msg *S1APMessage) error {
	if a.mongoCollection == nil {
		return nil // Ne rien faire si MongoDB n'est pas configuré
	}

	mmeID, enbID := a.extractUeIdentifiers(msg)

	// Debug pour voir tous les messages traités
	if a.config.Debug {
		log.Printf("DEBUG: Processing message - Packet: %d, Procedure: %s, MME_ID: %d, eNB_ID: %d, SrcIP: %s, DstIP: %s", 
			msg.PacketNumber, msg.ProcedureName, mmeID, enbID, msg.SrcIP, msg.DstIP)
	}

	// Messages qui appartiennent à une session UE spécifique (ont un eNB_UE_S1AP_ID)
	if enbID != -1 {
		// Pour UEContextReleaseComplete, finaliser la session après l'ajout
		if msg.ProcedureName == "UEContextReleaseComplete" {
			// Ajouter le message à la session avant de la finaliser
			if err := a.addMessageToSession(msg, mmeID, enbID); err != nil {
				log.Printf("WARN: Failed to add UEContextReleaseComplete to session: %v", err)
			}
			
			// Finaliser la session
			log.Printf("INFO: UEContextReleaseComplete détecté - finalisation de la session (MME: %d, eNB: %d)", mmeID, enbID)
			a.activeSessionHandlers.Add(1)
			go func() {
				defer a.activeSessionHandlers.Done()
				time.Sleep(100 * time.Millisecond)
				if err := a.handleCompletedSession(mmeID, enbID); err != nil {
					log.Printf("ERROR: Failed to handle completed session: %v", err)
				}
			}()
			return nil
		}

		// Pour tous les autres messages UE-spécifiques, les ajouter à la session
		return a.addMessageToSession(msg, mmeID, enbID)
	}

	// Messages généraux (sans eNB_UE_S1AP_ID) - les traiter différemment selon le type
	switch msg.ProcedureName {
	case "Paging":
		// Paging peut contenir des identifiants UE dans d'autres IEs
		return a.handlePagingMessage(msg)
	case "DownlinkNASTransport":
		// DownlinkNASTransport devrait normalement avoir des identifiants UE
		if a.config.Debug {
			log.Printf("DEBUG: DownlinkNASTransport sans eNB_UE_S1AP_ID - possibles identifiants alternatifs à extraire (Packet %d)", msg.PacketNumber)
		}
		return a.handleDownlinkNASTransport(msg)
	case "S1Setup", "Reset", "ErrorIndication", "OverloadStart", "OverloadStop":
		// Messages de gestion générale - pas liés à des sessions UE spécifiques
		if a.config.Debug {
			log.Printf("DEBUG: Message de gestion générale ignoré pour sessions UE (Packet %d, Proc: %s)", msg.PacketNumber, msg.ProcedureName)
		}
		return nil
	default:
		// Autres messages - essayer d'extraire des identifiants alternatifs
		if a.config.Debug {
			log.Printf("DEBUG: Message sans eNB_UE_S1AP_ID (Packet %d, Proc: %s) - recherche d'identifiants alternatifs", msg.PacketNumber, msg.ProcedureName)
		}
		return a.handleMessageWithAlternativeIdentifiers(msg)
	}
}

// addMessageToSession ajoute un message à une session existante ou en crée une nouvelle
func (a *Analyzer) addMessageToSession(msg *S1APMessage, mmeID, enbID int64) error {
	// Créer un ID de session. Si mmeID n'est pas encore là, on utilise une valeur temporaire.
	sessionID := a.generateSessionID(mmeID, enbID)
	
	// Le filtre pour trouver le document de la session
	filter := bson.M{"enb_ue_s1ap_id": enbID}
	
	// Si on a un mmeID dans ce message et qu'il n'est pas -1, on peut être plus spécifique
	if mmeID != -1 {
		filter = bson.M{
			"$or": []bson.M{
				{"enb_ue_s1ap_id": enbID, "mme_ue_s1ap_id": mmeID},
				{"enb_ue_s1ap_id": enbID, "mme_ue_s1ap_id": bson.M{"$exists": false}},
				{"enb_ue_s1ap_id": enbID, "session_id": bson.M{"$regex": fmt.Sprintf("^enb_%d_temp", enbID)}},
			},
		}
	}

	// Préparer les mises à jour
	now := time.Now()

	// La mise à jour principale
	update := bson.M{
		"$push": bson.M{"messages": msg},
		"$set": bson.M{
			"last_update":    now,
			"session_id":     sessionID,
			"last_procedure": msg.ProcedureName,
		},
		"$inc": bson.M{
			"message_count": 1,
			"procedure_stats." + msg.ProcedureName: 1,
		},
		"$setOnInsert": bson.M{
			"enb_ue_s1ap_id":     enbID,
			"creation_timestamp": now,
			"status":             "active",
			"src_ip":             msg.SrcIP,
			"dst_ip":             msg.DstIP,
			"first_procedure":    msg.ProcedureName,
		},
	}

	// Si mmeID est présent dans ce paquet, on l'ajoute à la clause $set
	if mmeID != -1 {
		update["$set"].(bson.M)["mme_ue_s1ap_id"] = mmeID
	}

	opts := options.Update().SetUpsert(true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := a.mongoCollection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("mongodb update failed: %w", err)
	}

	if result.UpsertedID != nil {
		log.Printf("INFO: Nouvelle session UE créée - SessionID: %s (eNB: %d, MME: %d, Proc: %s)", 
			sessionID, enbID, mmeID, msg.ProcedureName)
	} else if result.ModifiedCount > 0 {
		if a.config.Debug {
			log.Printf("DEBUG: Session UE mise à jour - SessionID: %s (Proc: %s)", sessionID, msg.ProcedureName)
		}
	}

	return nil
}

// generateSessionID génère un identifiant unique pour la session
func (a *Analyzer) generateSessionID(mmeID, enbID int64) string {
	if mmeID != -1 && enbID != -1 {
		return fmt.Sprintf("enb_%d_mme_%d", enbID, mmeID)
	}
	// Si mmeID n'est pas encore connu, utiliser seulement l'eNB ID
	if enbID != -1 {
		return fmt.Sprintf("enb_%d_temp", enbID)
	}
	// Cas d'urgence - ne devrait normalement pas arriver
	return fmt.Sprintf("unknown_%d", time.Now().UnixNano()%10000)
}

// isSessionEndingProcedure détermine si une procédure termine une session UE
func (a *Analyzer) isSessionEndingProcedure(procedureName string) bool {
	// La session se termine définitivement avec UEContextReleaseComplete
	return procedureName == "UEContextReleaseComplete"
}

// handleCompletedSession gère la finalisation d'une session UE :
// 1. Récupère la session complète de MongoDB
// 2. La sauvegarde dans le fichier sessions.json
// 3. La supprime de MongoDB
func (a *Analyzer) handleCompletedSession(mmeID, enbID int64) error {
	if a.mongoCollection == nil {
		return nil // Ne rien faire si MongoDB n'est pas configuré
	}

	// Créer le filtre pour trouver la session
	filter := bson.M{"enb_ue_s1ap_id": enbID}
	if mmeID != -1 {
		filter["mme_ue_s1ap_id"] = mmeID
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Récupérer la session complète de MongoDB
	var session UeSessionDocument
	err := a.mongoCollection.FindOne(ctx, filter).Decode(&session)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			log.Printf("WARN: Session not found for completion (eNB: %d, MME: %d)", enbID, mmeID)
			return nil
		}
		return fmt.Errorf("failed to retrieve session for completion: %w", err)
	}

	// Marquer la session comme terminée
	session.Status = "completed"
	session.LastUpdate = time.Now()

	// 2. Sauvegarder la session dans le fichier JSON
	if err := a.appendSessionToFile(&session); err != nil {
		log.Printf("ERROR: Failed to save completed session to file: %v", err)
		// Ne pas arrêter le processus, mais continuer avec la suppression MongoDB
	} else {
		log.Printf("INFO: Session completed and saved to file - SessionID: %s (eNB: %d, MME: %d, Messages: %d)", 
			session.SessionID, session.EnbUeS1apID, session.MmeUeS1apID, session.MessageCount)
		// Incrémenter le compteur de sessions terminées
		a.stats.CompletedSessions++
	}

	// 3. Supprimer la session de MongoDB
	deleteResult, err := a.mongoCollection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete completed session from MongoDB: %w", err)
	}

	if deleteResult.DeletedCount > 0 {
		log.Printf("INFO: Completed session removed from MongoDB - SessionID: %s", session.SessionID)
	} else {
		log.Printf("WARN: No session was deleted from MongoDB for SessionID: %s", session.SessionID)
	}

	return nil
}

// appendSessionToFile ajoute une session terminée au fichier JSON
func (a *Analyzer) appendSessionToFile(session *UeSessionDocument) error {
	a.sessionsFileMutex.Lock()
	defer a.sessionsFileMutex.Unlock()

	var sessions []*UeSessionDocument

	// Lire le fichier existant s'il existe
	if data, err := os.ReadFile(a.config.SessionsFile); err == nil {
		if err := json.Unmarshal(data, &sessions); err != nil {
			log.Printf("WARN: Failed to parse existing sessions file, creating new one: %v", err)
			sessions = []*UeSessionDocument{}
		}
	}

	// Ajouter la nouvelle session
	sessions = append(sessions, session)

	// Réécrire le fichier avec la nouvelle session
	data, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sessions to JSON: %w", err)
	}

	if err := os.WriteFile(a.config.SessionsFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write sessions file: %w", err)
	}

	return nil
}

// handleCompletedSessionByEnbID gère la finalisation d'une session UE en utilisant seulement l'eNB ID
func (a *Analyzer) handleCompletedSessionByEnbID(enbID int64) error {
	if a.mongoCollection == nil {
		return nil
	}

	// Chercher la session par eNB_UE_S1AP_ID seulement
	filter := bson.M{"enb_ue_s1ap_id": enbID}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Récupérer la session complète de MongoDB
	var session UeSessionDocument
	err := a.mongoCollection.FindOne(ctx, filter).Decode(&session)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			log.Printf("WARN: Session not found for completion by eNB ID (eNB: %d)", enbID)
			return nil
		}
		return fmt.Errorf("failed to retrieve session for completion: %w", err)
	}

	// Marquer la session comme terminée
	session.Status = "completed"
	session.LastUpdate = time.Now()

	// Sauvegarder la session dans le fichier JSON
	if err := a.appendSessionToFile(&session); err != nil {
		log.Printf("ERROR: Failed to save completed session to file: %v", err)
	} else {
		log.Printf("INFO: Session completed and saved to file - SessionID: %s (eNB: %d, MME: %d, Messages: %d)", 
			session.SessionID, session.EnbUeS1apID, session.MmeUeS1apID, session.MessageCount)
		a.stats.CompletedSessions++
	}

	// Supprimer la session de MongoDB
	deleteResult, err := a.mongoCollection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete completed session from MongoDB: %w", err)
	}

	if deleteResult.DeletedCount > 0 {
		log.Printf("INFO: Completed session removed from MongoDB - SessionID: %s", session.SessionID)
	} else {
		log.Printf("WARN: No session was deleted from MongoDB for SessionID: %s", session.SessionID)
	}

	return nil
}




func (a *Analyzer) printHeader() {
	fmt.Printf("🔍 S1AP Protocol Analyzer\n")
	fmt.Printf("==========================\n")
	fmt.Printf("📁 File: %s\n", a.config.PcapFile)
	fmt.Printf("📋 Format: %s\n", a.config.Format)
	if a.config.Limit > 0 {
		fmt.Printf("🔢 Limit: %d packets\n", a.config.Limit)
	}
	fmt.Printf("⏰ Started: %s\n\n", a.stats.StartTime.Format("2006-01-02 15:04:05"))
}

func (a *Analyzer) analyzePackets(handle *pcap.Handle) ([]*S1APMessage, error) {
	var messages []*S1APMessage
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		a.stats.TotalFrames++
		
		if a.config.Limit > 0 && a.stats.TotalFrames > a.config.Limit {
			break
		}

		s1apMessages := a.extractS1APMessages(packet)
		if len(s1apMessages) > 0 {
			a.stats.S1APFrames++
			messages = append(messages, s1apMessages...)
		}
	}

	return messages, nil
}

func (a *Analyzer) analyzeAndStorePackets(handle *pcap.Handle) error {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		a.stats.TotalFrames++

		if a.config.Limit > 0 && a.stats.TotalFrames > a.config.Limit {
			break
		}

		s1apMessages := a.extractS1APMessages(packet)
		if len(s1apMessages) > 0 {
			a.stats.S1APFrames++
			for _, msg := range s1apMessages {
				// La logique principale est ici !
				if err := a.processAndStoreMessage(msg); err != nil {
					// Logguer l'erreur mais continuer l'analyse
					log.Printf("WARN: Failed to store message for packet %d: %v", msg.PacketNumber, err)
				}
			}
		}
	}
	return nil
}

func (a *Analyzer) extractS1APMessages(packet gopacket.Packet) []*S1APMessage {
	// First try to extract SCTP layer
	sctpLayer := packet.Layer(layers.LayerTypeSCTP)
	var payload []byte
	
	if sctpLayer != nil {
		sctp := sctpLayer.(*layers.SCTP)
		payload = sctp.LayerPayload()
	} else {
		// Fallback: check if this could be S1AP over IP (sometimes SCTP detection fails)
		// S1AP typically uses port 36412
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			if tcp.SrcPort == 36412 || tcp.DstPort == 36412 {
				payload = tcp.LayerPayload()
			}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			if udp.SrcPort == 36412 || udp.DstPort == 36412 {
				payload = udp.LayerPayload()
			}
		}
		
		// Last resort: check application data in any IP packet on port 36412
		if len(payload) == 0 {
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				// Try to extract from application layer
				if appLayer := packet.ApplicationLayer(); appLayer != nil {
					payload = appLayer.Payload()
				}
			}
		}
	}
	
	if len(payload) == 0 {
		return nil
	}

	// Extract S1AP data from payload
	s1apData := a.extractS1APFromSCTP(payload)
	if len(s1apData) == 0 {
		return nil
	}

	// Split into individual S1AP messages
	messagePayloads := a.splitS1APMessages(s1apData)
	var messages []*S1APMessage

	for i, msgPayload := range messagePayloads {
		message := a.parseS1APMessage(packet, msgPayload, i+1, len(messagePayloads))
		if message != nil {
			messages = append(messages, message)
			a.stats.SuccessfulDecodes++
			a.stats.ProcedureStats[message.ProcedureName]++
		} else {
			a.stats.FailedDecodes++
		}
	}

	return messages
}

func (a *Analyzer) extractS1APFromSCTP(payload []byte) []byte {
	// SCTP DATA chunk format: 
	// Type (1) + Flags (1) + Length (2) + TSN (4) + Stream ID (2) + Stream Seq (2) + Protocol ID (4) + Data...
	// For S1AP, we expect Protocol ID = 18 (S1AP) in bytes 12-15
	
	if len(payload) < 16 {
		return nil
	}
	
	// Check if this looks like an SCTP DATA chunk with S1AP
	if payload[0] == 0x00 && payload[1] == 0x03 {
		// This is an SCTP DATA chunk, S1AP data starts at offset 16
		if len(payload) > 16 {
			s1apData := payload[16:]
			// Now check if this looks like S1AP
			if len(s1apData) >= 3 && a.isLikelyS1AP(s1apData) {
				return s1apData
			}
		}
	}
	
	// Fallback: look for S1AP patterns anywhere in the payload
	for i := 0; i < len(payload)-8; i++ {
		firstByte := payload[i]
		if (firstByte == 0x00 || firstByte == 0x20 || firstByte == 0x40) && i+8 < len(payload) {
			if a.isLikelyS1AP(payload[i:]) {
				return payload[i:]
			}
		}
	}
	
	return nil
}

func (a *Analyzer) isLikelyS1AP(data []byte) bool {
	if len(data) < 3 {
		return false
	}

	// Check for valid S1AP PDU types (based on ASN.1 CHOICE)
	firstByte := data[0]
	if firstByte != 0x00 && firstByte != 0x20 && firstByte != 0x40 {
		return false
	}

	// Check procedure code range (0-66 are known S1AP procedures)
	procedureCode := int(data[1])
	if procedureCode < 0 || procedureCode > 66 {
		return false
	}

	// Basic APER validation
	if len(data) < 8 {
		return false
	}

	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (a *Analyzer) splitS1APMessages(data []byte) [][]byte {
	var messages [][]byte
	
	// For now, return single message - can be enhanced for multi-message parsing
	if len(data) > 0 {
		messages = append(messages, data)
	}
	
	return messages
}

func (a *Analyzer) parseS1APMessage(packet gopacket.Packet, payload []byte, msgIndex, totalMsgs int) *S1APMessage {
	// Try to decode with S1AP library
	decodedPDU, msgType, err := s1ap.Decode(payload)
	if err != nil {
		if a.config.Debug {
			log.Printf("S1AP decode failed: %v", err)
		}
		return nil
	}
	defer s1ap.Free(decodedPDU)

	// Extract real procedure code from payload
	realProcCode := s1ap.ExtractProcedureCode(payload)
	
	// Get specific message name based on message type and procedure code
	procedureName := s1ap.GetMessageName(msgType, realProcCode)

	if a.config.Debug {
		log.Printf("DEBUG: parseS1APMessage - procedureName: %s, msgType: %d, realProcCode: %d", procedureName, msgType, realProcCode)
	}

	// Get IP information
	srcIP, dstIP := a.extractIPInfo(packet)

	// Analyze PDU type
	pduType, pduTypeCode := a.analyzePDUType(payload)

	// Extract IEs from the decoded PDU
	if a.config.Debug {
		log.Printf("DEBUG: About to call ExtractAllIEs for procedureName: %s", procedureName)
	}
	ies := s1ap.ExtractAllIEs(decodedPDU, msgType, realProcCode)
	
	// Special handling for UEContextReleaseComplete - try to extract IEs using C handler
	if procedureName == "UEContextReleaseComplete" && (len(ies) == 0 || !hasValidUEIdentifiers(ies)) {
		if a.config.Debug {
			log.Printf("DEBUG: Using C handler for UEContextReleaseComplete IE extraction")
		}
		
		// Try to extract using the C handler
		if mmeID, enbID, err := s1ap.UEContextReleaseCompleteHandle(decodedPDU); err == nil {
			// Create IEs manually from the extracted values
			if mmeID != -1 {
				ies = append(ies, &s1ap.InformationElement{
					ID:          0,
					Name:        "id_MME_UE_S1AP_ID",
					Criticality: "reject",
					Value:       mmeID,
					RawValue:    fmt.Sprintf("%d", mmeID),
				})
			}
			if enbID != -1 {
				ies = append(ies, &s1ap.InformationElement{
					ID:          8,
					Name:        "id_eNB_UE_S1AP_ID",
					Criticality: "reject",
					Value:       enbID,
					RawValue:    fmt.Sprintf("%d", enbID),
				})
			}
			if a.config.Debug {
				log.Printf("DEBUG: Extracted from C handler - MME: %d, eNB: %d", mmeID, enbID)
			}
		}
	}

	message := &S1APMessage{
		PacketNumber:  a.stats.TotalFrames,
		Timestamp:     packet.Metadata().Timestamp,
		SrcIP:         srcIP,
		DstIP:         dstIP,
		PDUType:       pduType,
		PDUTypeCode:   pduTypeCode,
		ProcedureName: procedureName,
		ProcedureCode: realProcCode,
		Criticality:   "ignore", // Default - can be enhanced
		IEs:           ies,
	}

	if totalMsgs > 1 {
		message.MessageIndex = msgIndex
		message.TotalMessages = totalMsgs
	}

	return message
}

// Helper function to check if IEs contain valid UE identifiers
func hasValidUEIdentifiers(ies []*s1ap.InformationElement) bool {
	hasMME := false
	hasENB := false
	
	for _, ie := range ies {
		if ie.ID == 0 && ie.Value != nil && ie.Value != "Not decoded" && ie.Value != "Extraction failed" {
			hasMME = true
		}
		if ie.ID == 8 && ie.Value != nil && ie.Value != "Not decoded" && ie.Value != "Extraction failed" {
			hasENB = true
		}
	}
	
	return hasMME && hasENB
}

func (a *Analyzer) extractIPInfo(packet gopacket.Packet) (string, string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		return ip.SrcIP.String(), ip.DstIP.String()
	}
	return "unknown", "unknown"
}

func (a *Analyzer) analyzePDUType(payload []byte) (string, int) {
	if len(payload) == 0 {
		return "unknown", -1
	}

	switch payload[0] {
	case 0x00:
		return "initiatingMessage", 0
	case 0x20:
		return "successfulOutcome", 1
	case 0x40:
		return "unsuccessfulOutcome", 2
	default:
		return "unknown", -1
	}
}

func (a *Analyzer) outputResults(messages []*S1APMessage) error {
	switch a.config.Format {
	case FormatJSON:
		return a.outputJSON(messages)
	case FormatDetailed:
		return a.outputDetailed(messages)
	default:
		return a.outputSimple(messages)
	}
}

func (a *Analyzer) outputSimple(messages []*S1APMessage) error {
	if a.config.StatsOnly {
		return a.outputStats()
	}

	for _, msg := range messages {
		tsFloat := float64(msg.Timestamp.UnixNano()) / 1e9
		fmt.Printf("packet_number: %d\n", msg.PacketNumber)
		fmt.Printf("timestamp: %.6f\n", tsFloat)
		fmt.Printf("timestamp_human: %s\n", msg.Timestamp.Format("2006-01-02 15:04:05.000"))
		fmt.Printf("src_ip: %s\n", msg.SrcIP)
		fmt.Printf("dst_ip: %s\n", msg.DstIP)
		fmt.Printf("s1ap_pdu:\n")
		fmt.Printf("  type: %s\n", msg.PDUType)
		fmt.Printf("  type_code: %d\n", msg.PDUTypeCode)
		fmt.Printf("procedure:\n")
		fmt.Printf("  name: %s\n", msg.ProcedureName)
		fmt.Printf("  code: %d\n", msg.ProcedureCode)
		fmt.Printf("  criticality: %s\n", msg.Criticality)
		
		// Display Information Elements
		if len(msg.IEs) > 0 {
			fmt.Printf("information_elements:\n")
			for _, ie := range msg.IEs {
				fmt.Printf("  - id: %d\n", ie.ID)
				fmt.Printf("    name: %s\n", ie.Name)
				fmt.Printf("    criticality: %s\n", ie.Criticality)
				if ie.Value != nil {
					fmt.Printf("    value: %v\n", ie.Value)
				}
				if ie.RawValue != "" {
					fmt.Printf("    raw_value: %s\n", ie.RawValue)
				}
			}
		}
		fmt.Println()
	}

	return a.outputStats()
}

func (a *Analyzer) outputDetailed(messages []*S1APMessage) error {
	// Similar to simple but with more technical details
	return a.outputSimple(messages)
}

func (a *Analyzer) outputJSON(messages []*S1APMessage) error {
	result := struct {
		Messages   []*S1APMessage `json:"messages"`
		Statistics *Statistics    `json:"statistics"`
	}{
		Messages:   messages,
		Statistics: a.stats,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func (a *Analyzer) outputStats() error {
	fmt.Printf("\n📊 ANALYSIS SUMMARY\n")
	fmt.Printf("==================\n")
	fmt.Printf("Total frames processed: %d\n", a.stats.TotalFrames)
	fmt.Printf("S1AP frames found: %d\n", a.stats.S1APFrames)
	fmt.Printf("Successful decodes: %d\n", a.stats.SuccessfulDecodes)
	fmt.Printf("Failed decodes: %d\n", a.stats.FailedDecodes)
	
	if a.stats.SuccessfulDecodes > 0 {
		successRate := float64(a.stats.SuccessfulDecodes) / float64(a.stats.S1APFrames) * 100
		fmt.Printf("Success rate: %.1f%%\n", successRate)
	}
	
	if a.config.MongoStore {
		fmt.Printf("Completed sessions: %d\n", a.stats.CompletedSessions)
		if a.stats.CompletedSessions > 0 {
			fmt.Printf("Sessions file: %s\n", a.config.SessionsFile)
		}
	}
	
	fmt.Printf("Processing time: %v\n\n", a.stats.ProcessingTime)

	if len(a.stats.ProcedureStats) > 0 {
		fmt.Printf("📈 PROCEDURE STATISTICS\n")
		fmt.Printf("======================\n")
		
		// Sort procedures by count
		type procStat struct {
			name  string
			count int
		}
		var procs []procStat
		for name, count := range a.stats.ProcedureStats {
			procs = append(procs, procStat{name, count})
		}
		sort.Slice(procs, func(i, j int) bool {
			return procs[i].count > procs[j].count
		})

		for _, proc := range procs {
			percentage := float64(proc.count) / float64(a.stats.SuccessfulDecodes) * 100
			fmt.Printf("%-25s: %6d (%5.1f%%)\n", proc.name, proc.count, percentage)
		}
	}

	return nil
}
