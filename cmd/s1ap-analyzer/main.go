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
	}

	return analyzer
}


// Run executes the analysis
func (a *Analyzer) Run() error {
	defer func() {
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

func extractUeIdentifiers(msg *S1APMessage) (mmeID, enbID int64) {
	mmeID, enbID = -1, -1 // Valeurs par défaut si non trouvés

	for _, ie := range msg.IEs {
		switch ie.ID {
		case 0: // id_MME_UE_S1AP_ID
			if val, ok := ie.Value.(int32); ok {
				mmeID = int64(val)
			}
		case 8: // id_eNB_UE_S1AP_ID
			if val, ok := ie.Value.(int32); ok {
				enbID = int64(val)
			}
		}
	}
	return
}

// processAndStoreMessage traite et stocke un message S1AP dans MongoDB
// avec gestion des sessions UE basée sur eNB_UE_S1AP_ID
func (a *Analyzer) processAndStoreMessage(msg *S1APMessage) error {
	if a.mongoCollection == nil {
		return nil // Ne rien faire si MongoDB n'est pas configuré
	}

	mmeID, enbID := extractUeIdentifiers(msg)

	// Un identifiant eNB est presque toujours présent pour les messages liés à l'UE.
	if enbID == -1 {
		// Ce message n'est probablement pas lié à une session UE spécifique (ex: S1Setup)
		// On pourrait le stocker dans une autre collection ou l'ignorer pour le contexte de session.
		if a.config.Debug {
			log.Printf("DEBUG: Message sans eNB_UE_S1AP_ID, ignoré pour le stockage de session (Packet %d, Proc: %s)", msg.PacketNumber, msg.ProcedureName)
		}
		return nil
	}

	// Créer un ID de session. Si mmeID n'est pas encore là, on utilise une valeur temporaire.
	sessionID := a.generateSessionID(mmeID, enbID)
	
	// Le filtre pour trouver le document de la session
	// Stratégie: chercher d'abord par eNB_UE_S1AP_ID, puis affiner si nécessaire
	filter := bson.M{"enb_ue_s1ap_id": enbID}
	
	// Si on a un mmeID dans ce message et qu'il n'est pas -1, on peut être plus spécifique
	if mmeID != -1 {
		// Chercher une session avec cette combinaison eNB+MME ou une session avec seulement eNB
		filter = bson.M{
			"$or": []bson.M{
				{"enb_ue_s1ap_id": enbID, "mme_ue_s1ap_id": mmeID},
				{"enb_ue_s1ap_id": enbID, "mme_ue_s1ap_id": bson.M{"$exists": false}},
			},
		}
	}

	// Préparer les mises à jour
	now := time.Now()

	// La mise à jour principale
	update := bson.M{
		"$push": bson.M{"messages": msg}, // Ajoute le message au tableau
		"$set": bson.M{
			"last_update":    now,
			"session_id":     sessionID,
			"last_procedure": msg.ProcedureName,
		},
		"$inc": bson.M{
			"message_count": 1,
			"procedure_stats." + msg.ProcedureName: 1,
		},
		"$setOnInsert": bson.M{ // Champs à définir uniquement lors de la création
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

	// Déterminer si la session est terminée
	if a.isSessionEndingProcedure(msg.ProcedureName) {
		update["$set"].(bson.M)["status"] = "released"
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
	if mmeID != -1 {
		return fmt.Sprintf("enb_%d_mme_%d", enbID, mmeID)
	}
	// Si mmeID n'est pas encore connu, utiliser un ID temporaire
	return fmt.Sprintf("enb_%d_temp_%d", enbID, time.Now().UnixNano()%10000)
}

// isSessionEndingProcedure détermine si une procédure termine une session UE
func (a *Analyzer) isSessionEndingProcedure(procedureName string) bool {
	endingProcedures := []string{
		"UEContextReleaseComplete",
		"UEContextReleaseCommand", 
		"Reset",
		"ErrorIndication", // Dans certains cas
	}
	
	for _, proc := range endingProcedures {
		if proc == procedureName {
			return true
		}
	}
	return false
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
	procedureName := s1ap.GetProcedureName(realProcCode)

	// Get IP information
	srcIP, dstIP := a.extractIPInfo(packet)

	// Analyze PDU type
	pduType, pduTypeCode := a.analyzePDUType(payload)

	// Extract IEs from the decoded PDU
	ies := s1ap.ExtractAllIEs(decodedPDU, msgType)

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
