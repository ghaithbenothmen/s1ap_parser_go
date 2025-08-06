package main

import (
	"encoding/json"
	"fmt"
	"log" 
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreswitch/coreswitch/pkg/s1ap"
)

// CellCoverageStats représente les statistiques de couverture par cellule
type CellCoverageStats struct {
	ECGI                        string    `json:"ecgi"`
	PLMN                        string    `json:"plmn"`
	CellID                      string    `json:"cell_id"`
	TotalFailures               int       `json:"total_failures"`
	RadioConnectionLost         int       `json:"radio_connection_lost"`         // cause 21
	FailureInRadioProcedure     int       `json:"failure_in_radio_procedure"`    // cause 26
	HandoverFailures            int       `json:"handover_failures"`             // cause 10, 5
	HandoverRadioReason         int       `json:"handover_radio_reason"`         // cause 16
	OtherRadioFailures          int       `json:"other_radio_failures"`
	RiskScore                   float64   `json:"risk_score"`
	FirstSeen                   time.Time `json:"first_seen"`
	LastSeen                    time.Time `json:"last_seen"`
	UECount                     int       `json:"ue_count"`                      // Nombre d'UEs différents affectés
	MessageTypes                map[string]int `json:"message_types"`             // Répartition par type de message
}

// CellCoverageEvent représente un événement de couverture
type CellCoverageEvent struct {
	ECGI            string `parquet:"name=ecgi, type=BYTE_ARRAY, convertedtype=UTF8"`
	PLMN            string `parquet:"name=plmn, type=BYTE_ARRAY, convertedtype=UTF8"`
	CellID          string `parquet:"name=cell_id, type=BYTE_ARRAY, convertedtype=UTF8"`
	Timestamp       int64  `parquet:"name=timestamp, type=INT64, convertedtype=TIMESTAMP_MILLIS"`
	TimestampStr    string `parquet:"name=timestamp_str, type=BYTE_ARRAY, convertedtype=UTF8"`
	MessageType     string `parquet:"name=message_type, type=BYTE_ARRAY, convertedtype=UTF8"`
	EventType       string `parquet:"name=event_type, type=BYTE_ARRAY, convertedtype=UTF8"`
	MMEUeS1apID     int64  `parquet:"name=mme_ue_s1ap_id, type=INT64"`
	ENBUeS1apID     int64  `parquet:"name=enb_ue_s1ap_id, type=INT64"`
	CauseType       string `parquet:"name=cause_type, type=BYTE_ARRAY, convertedtype=UTF8"`
	CauseCode       int32  `parquet:"name=cause_code, type=INT32"`
	CauseDetail     string `parquet:"name=cause_detail, type=BYTE_ARRAY, convertedtype=UTF8"`
	RiskScore       float64 `parquet:"name=risk_score, type=DOUBLE"`
	SeverityLevel   string `parquet:"name=severity_level, type=BYTE_ARRAY, convertedtype=UTF8"`
	PacketNumber    int32  `parquet:"name=packet_number, type=INT32"`
	SourceIP        string `parquet:"name=source_ip, type=BYTE_ARRAY, convertedtype=UTF8"`
	DestinationIP   string `parquet:"name=destination_ip, type=BYTE_ARRAY, convertedtype=UTF8"`
}

// CellCoverageReport représente le format Parquet du rapport final
type CellCoverageReport struct {
	ECGI                        string  `parquet:"name=ecgi, type=BYTE_ARRAY, convertedtype=UTF8"`
	PLMN                        string  `parquet:"name=plmn, type=BYTE_ARRAY, convertedtype=UTF8"`
	CellID                      string  `parquet:"name=cell_id, type=BYTE_ARRAY, convertedtype=UTF8"`
	TotalFailures               int32   `parquet:"name=total_failures, type=INT32"`
	RadioConnectionLost         int32   `parquet:"name=radio_connection_lost, type=INT32"`
	FailureInRadioProcedure     int32   `parquet:"name=failure_in_radio_procedure, type=INT32"`
	HandoverFailures            int32   `parquet:"name=handover_failures, type=INT32"`
	HandoverRadioReason         int32   `parquet:"name=handover_radio_reason, type=INT32"`
	OtherRadioFailures          int32   `parquet:"name=other_radio_failures, type=INT32"`
	RiskScore                   float64 `parquet:"name=risk_score, type=DOUBLE"`
	RiskLevel                   string  `parquet:"name=risk_level, type=BYTE_ARRAY, convertedtype=UTF8"`
	FirstSeenTimestamp          int64   `parquet:"name=first_seen_timestamp, type=INT64, convertedtype=TIMESTAMP_MILLIS"`
	LastSeenTimestamp           int64   `parquet:"name=last_seen_timestamp, type=INT64, convertedtype=TIMESTAMP_MILLIS"`
	FirstSeenStr                string  `parquet:"name=first_seen_str, type=BYTE_ARRAY, convertedtype=UTF8"`
	LastSeenStr                 string  `parquet:"name=last_seen_str, type=BYTE_ARRAY, convertedtype=UTF8"`
	UECount                     int32   `parquet:"name=ue_count, type=INT32"`
	InitialContextSetupFailures int32   `parquet:"name=initial_context_setup_failures, type=INT32"`
	ERABReleaseIndications      int32   `parquet:"name=erab_release_indications, type=INT32"`
	UEContextReleaseRequests    int32   `parquet:"name=ue_context_release_requests, type=INT32"`
	HandoverFailureCount        int32   `parquet:"name=handover_failure_count, type=INT32"`
	HandoverPrepFailures        int32   `parquet:"name=handover_prep_failures, type=INT32"`
}

// CoverageAnalyzer analyse les problèmes de couverture radio
type CoverageAnalyzer struct {
	cellStats       map[string]*CellCoverageStats
	events          []*CellCoverageEvent
	ueToECGI        map[string]string // Map MME-UE-S1AP-ID -> ECGI
	config          *Config
	mutex           sync.RWMutex
	outputFile      string
	eventsFile      string
}

// CellReport represents the final output format for parquet
type CellReport struct {
	ECGI              string `json:"ecgi"`
	TotalFailures     int    `json:"total_failures"`
	RiskScore         int    `json:"risk_score"`
	RiskLevel         string `json:"risk_level"`
	LastUpdated       int64  `json:"last_updated"`
	FirstFailure      int64  `json:"first_failure"`
	LastFailure       int64  `json:"last_failure"`
	FailureCausesJSON string `json:"failure_causes_json"`
}

// NewCoverageAnalyzer crée une nouvelle instance
func NewCoverageAnalyzer(outputPath string) *CoverageAnalyzer {
	log.Println("INFO: Coverage analysis system initialized")
	analyzer := &CoverageAnalyzer{
		cellStats:    make(map[string]*CellCoverageStats),
		ueToECGI:     make(map[string]string),
		outputFile:   outputPath + "_cell_coverage.parquet",
		eventsFile:   outputPath + "_coverage_events.parquet",
	}

	// Activer les événements simulés pour tester avec de vraies données focalisées
	log.Println("INFO: Loading simulated coverage events for comprehensive testing")
	analyzer.processSimulationOnly()
	log.Printf("INFO: Loaded simulation with %d coverage events for testing", len(analyzer.cellStats))

	return analyzer
}

// processSimulationOnly traite uniquement les données simulées pour générer le rapport
func (ca *CoverageAnalyzer) processSimulationOnly() {
	log.Printf("INFO: Processing simulation data only for coverage analysis")
	
	// Charger les événements depuis le fichier de simulation
	if err := ca.loadSimulationFile("/home/ghaith/coreswitch/coverage_simulation.json"); err != nil {
		log.Printf("ERROR: Failed to load simulation file: %v", err)
		return
	}
	
	// Traiter chaque événement simulé pour construire les stats par cellule
	for _, event := range ca.events {
		ca.analyzeSimulatedEvent(event)
	}
	
	// Générer immédiatement le rapport final
	ca.generateFinalReport()
}

// analyzeSimulatedEvent analyse un événement simulé et met à jour les stats cellule
func (ca *CoverageAnalyzer) analyzeSimulatedEvent(event *CellCoverageEvent) {
	ca.mutex.Lock()
	defer ca.mutex.Unlock()
	
	ecgi := event.ECGI
	if ecgi == "" {
		return
	}
	
	// Initialiser les stats de la cellule si nécessaire
	if ca.cellStats[ecgi] == nil {
		ca.cellStats[ecgi] = &CellCoverageStats{
			ECGI:        ecgi,
			PLMN:        extractPLMNFromECGI(ecgi),
			CellID:      extractCellIDFromECGI(ecgi),
			FirstSeen:   time.Unix(event.Timestamp/1000, 0),
			LastSeen:    time.Unix(event.Timestamp/1000, 0),
			UECount:     1,
			MessageTypes: make(map[string]int),
		}
	}
	
	stats := ca.cellStats[ecgi]
	stats.LastSeen = time.Unix(event.Timestamp/1000, 0)
	
	// Compter les types de failures
	switch event.EventType {
	case "InitialContextSetupFailure":
		stats.OtherRadioFailures++ // Pas de champ spécifique pour InitialContextSetup
	case "E-RABReleaseIndication":
		stats.OtherRadioFailures++ // Pas de champ spécifique pour E-RAB
	case "UEContextReleaseRequest":
		if event.CauseDetail == "radio-connection-with-ue-lost" {
			stats.RadioConnectionLost++
		} else {
			stats.OtherRadioFailures++
		}
	case "HandoverFailure":
		stats.HandoverFailures++
	case "HandoverPreparationFailure":
		stats.HandoverFailures++
	default:
		stats.OtherRadioFailures++
	}
	
	// Mettre à jour le total
	stats.TotalFailures = stats.RadioConnectionLost + stats.FailureInRadioProcedure + 
						  stats.HandoverFailures + stats.HandoverRadioReason + stats.OtherRadioFailures
						  
	// Mettre à jour les types de messages
	if stats.MessageTypes == nil {
		stats.MessageTypes = make(map[string]int)
	}
	stats.MessageTypes[event.EventType]++
}

// generateFinalReport génère le rapport final au format requis
func (ca *CoverageAnalyzer) generateFinalReport() {
	ca.mutex.RLock()
	defer ca.mutex.RUnlock()
	
	var reports []CellReport
	
	for ecgi, stats := range ca.cellStats {
		// Calculer le total des failures
		totalFailures := stats.TotalFailures
		
		if totalFailures == 0 {
			continue
		}
		
		// Construire les causes de failure basées sur les champs réels
		failureCauses := make(map[string]int)
		if stats.RadioConnectionLost > 0 {
			failureCauses["radio-connection-with-ue-lost"] = stats.RadioConnectionLost
		}
		if stats.FailureInRadioProcedure > 0 {
			failureCauses["failure-in-radio-interface-procedure"] = stats.FailureInRadioProcedure
		}
		if stats.HandoverFailures > 0 {
			failureCauses["handover-failure-in-target-e-utran"] = stats.HandoverFailures
		}
		if stats.HandoverRadioReason > 0 {
			failureCauses["handover-desirable-for-radio-reason"] = stats.HandoverRadioReason
		}
		if stats.OtherRadioFailures > 0 {
			failureCauses["other-radio-failures"] = stats.OtherRadioFailures
		}
		
		// Calculer le risk score et level
		riskScore := ca.calculateRiskScore(totalFailures, failureCauses)
		riskLevel := ca.calculateRiskLevel(riskScore)
		
		// Convertir les causes en JSON
		causesJSON := ca.formatFailureCausesJSON(failureCauses)
		
		report := CellReport{
			ECGI:              ecgi,
			TotalFailures:     totalFailures,
			RiskScore:         riskScore,
			RiskLevel:         riskLevel,
			LastUpdated:       stats.LastSeen.UnixMilli(),
			FirstFailure:      stats.FirstSeen.UnixMilli(),
			LastFailure:       stats.LastSeen.UnixMilli(),
			FailureCausesJSON: causesJSON,
		}
		
		reports = append(reports, report)
	}
	
	// Sauvegarder le rapport au format JSON (comme parquet converti)
	ca.saveCoverageReport(reports)
}

// saveCoverageReport sauvegarde le rapport de coverage
func (ca *CoverageAnalyzer) saveCoverageReport(reports []CellReport) {
	filename := "example_coverage_report.parquet.as.json"
	
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("ERROR: Failed to create coverage report file: %v", err)
		return
	}
	defer file.Close()
	
	// Écrire chaque rapport comme une ligne JSON (format parquet-as-json)
	for _, report := range reports {
		jsonData, err := json.Marshal(report)
		if err != nil {
			log.Printf("ERROR: Failed to marshal report: %v", err)
			continue
		}
		
		file.WriteString(string(jsonData) + "\n")
	}
	
	log.Printf("INFO: Coverage report saved to %s with %d cell reports", filename, len(reports))
}

// calculateRiskScore calcule le score de risque basé sur les failures
func (ca *CoverageAnalyzer) calculateRiskScore(totalFailures int, causes map[string]int) int {
	baseScore := totalFailures * 5  // Score de base plus élevé
	
	// Pondération par type de failure
	var weightedScore int
	for cause, count := range causes {
		switch cause {
		case "handover-failure-in-target-e-utran":
			weightedScore += count * 15  // Les échecs de handover sont critiques
		case "radio-connection-with-ue-lost":
			weightedScore += count * 20  // Perte de connexion radio très critique
		case "failure-in-radio-interface-procedure":
			weightedScore += count * 12   // Interface failures sont graves
		case "handover-desirable-for-radio-reason":
			weightedScore += count * 8   // Handover radio reason
		case "other-radio-failures":
			weightedScore += count * 6   // Autres failures
		default:
			weightedScore += count * 7
		}
	}
	
	// Bonus multiplicateur si plusieurs types de failures
	multiplier := 1.0
	if len(causes) > 2 {
		multiplier = 1.5
	} else if len(causes) > 1 {
		multiplier = 1.2
	}
	
	return int(float64(baseScore + weightedScore) * multiplier)
}

// calculateRiskLevel détermine le niveau de risque
func (ca *CoverageAnalyzer) calculateRiskLevel(riskScore int) string {
	if riskScore >= 30 {
		return "HIGH"
	} else if riskScore >= 15 {
		return "MEDIUM"
	} else {
		return "LOW"
	}
}

// formatFailureCausesJSON convertit les causes en JSON string
func (ca *CoverageAnalyzer) formatFailureCausesJSON(causes map[string]int) string {
	jsonData, err := json.Marshal(causes)
	if err != nil {
		return "{}"
	}
	return string(jsonData)
}

// Fonctions utilitaires pour extraire PLMN et CellID depuis ECGI
func extractPLMNFromECGI(ecgi string) string {
	parts := strings.Split(ecgi, "-")
	if len(parts) >= 1 {
		return parts[0]
	}
	return ""
}

func extractCellIDFromECGI(ecgi string) string {
	parts := strings.Split(ecgi, "-")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func formatTime(timestamp int64) string {
	return time.Unix(timestamp/1000, 0).Format("2006-01-02 15:04:05")
}

// loadSimulationFile charge les événements depuis le fichier de simulation JSON
func (ca *CoverageAnalyzer) loadSimulationFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("unable to open simulation file: %w", err)
	}
	defer file.Close()
	
	var simulation struct {
		Metadata struct {
			TotalEvents int `json:"total_events"`
		} `json:"metadata"`
		Events []struct {
			Message struct {
				PacketNumber  int    `json:"packet_number"`
				Timestamp     string `json:"timestamp"`
				SrcIP         string `json:"src_ip"`
				DstIP         string `json:"dst_ip"`
				ProcedureName string `json:"procedure_name"`
				InformationElements []struct {
					ID       int    `json:"id"`
					Name     string `json:"name"`
					Value    interface{} `json:"value"`
					RawValue string `json:"raw_value"`
				} `json:"information_elements"`
			} `json:"message"`
			CoverageMetadata struct {
				RiskScore    float64 `json:"risk_score"`
				Severity     string  `json:"severity"`
				CauseDetail  string  `json:"cause_detail"`
				CauseCode    int32   `json:"cause_code"`
			} `json:"coverage_metadata"`
		} `json:"events"`
	}
	
	if err := json.NewDecoder(file).Decode(&simulation); err != nil {
		return fmt.Errorf("unable to decode simulation file: %w", err)
	}
	
	log.Printf("INFO: Loading %d events from simulation file", simulation.Metadata.TotalEvents)
	
	ca.mutex.Lock()
	defer ca.mutex.Unlock()
	
	for _, eventData := range simulation.Events {
		// Parser le timestamp
		timestamp, err := time.Parse(time.RFC3339, eventData.Message.Timestamp)
		if err != nil {
			log.Printf("WARN: Failed to parse timestamp %s: %v", eventData.Message.Timestamp, err)
			timestamp = time.Now()
		}
		
		// Extraire les données des IEs
		var mmeID, enbID int64
		var ecgi, plmn, cellID string
		
		for _, ie := range eventData.Message.InformationElements {
			switch ie.ID {
			case 0: // MME-UE-S1AP-ID
				if val, ok := ie.Value.(float64); ok {
					mmeID = int64(val)
				}
			case 8: // eNB-UE-S1AP-ID
				if val, ok := ie.Value.(float64); ok {
					enbID = int64(val)
				}
			case 100: // EUTRAN-CGI
				if val, ok := ie.Value.(string); ok {
					ecgi = ca.extractECGI(val)
					plmn, cellID = ca.parseECGI(ecgi)
				}
			}
		}
		
		// Si pas d'ECGI extrait, en créer un par défaut
		if ecgi == "" {
			ecgi = fmt.Sprintf("60501-%07x", eventData.Message.PacketNumber)
			plmn = "60501"
			cellID = fmt.Sprintf("%07x", eventData.Message.PacketNumber)
		}
		
		event := &CellCoverageEvent{
			ECGI:          ecgi,
			PLMN:          plmn, 
			CellID:        cellID,
			Timestamp:     timestamp.UnixMilli(),
			TimestampStr:  timestamp.Format("2006-01-02 15:04:05.000"),
			MessageType:   eventData.Message.ProcedureName,
			EventType:     eventData.Message.ProcedureName,  // Ajouter EventType
			MMEUeS1apID:   mmeID,
			ENBUeS1apID:   enbID,
			CauseType:     "radioNetwork",
			CauseCode:     eventData.CoverageMetadata.CauseCode,
			CauseDetail:   eventData.CoverageMetadata.CauseDetail,
			RiskScore:     eventData.CoverageMetadata.RiskScore,
			SeverityLevel: eventData.CoverageMetadata.Severity,
			PacketNumber:  int32(eventData.Message.PacketNumber),
			SourceIP:      eventData.Message.SrcIP,
			DestinationIP: eventData.Message.DstIP,
		}
		
		ca.events = append(ca.events, event)
		ca.updateCellStats(event)
	}
	
	log.Printf("INFO: Successfully loaded %d simulation events", len(simulation.Events))
	return nil
}

// AnalyzeMessage analyse un message S1AP pour détecter les problèmes de couverture
func (ca *CoverageAnalyzer) AnalyzeMessage(msg *S1APMessage) {
	// Debug pour tous les messages analysés
	if ca.config.Debug {
		log.Printf("COVERAGE DEBUG: Analyzing message - Procedure: %s, IEs: %d", msg.ProcedureName, len(msg.IEs))
	}
	
	// Étape 1: Vérifier si le message est pertinent pour l'analyse de couverture
	if !ca.isRelevantMessage(msg.ProcedureName) {
		// Même si pas pertinent pour les échecs, peut contenir ECGI pour mapping
		ca.extractECGIMapping(msg)
		return
	}
	
	if ca.config.Debug {
		log.Printf("COVERAGE DEBUG: Relevant message found - %s", msg.ProcedureName)
	}
	
	// Étape 2: Extraire les informations nécessaires
	event := ca.createCoverageEvent(msg)
	if event == nil {
		if ca.config.Debug {
			log.Printf("COVERAGE DEBUG: Failed to create coverage event for %s", msg.ProcedureName)
		}
		return
	}
	
	// Étape 3: Ajouter l'événement à la liste
	ca.mutex.Lock()
	ca.events = append(ca.events, event)
	
	// Étape 4: Mettre à jour les statistiques de la cellule
	ca.updateCellStats(event)
	ca.mutex.Unlock()
	
	if ca.config.Debug {
		log.Printf("COVERAGE: Event detected - ECGI: %s, Cause: %s (code %d), Risk: %.1f", 
			event.ECGI, event.CauseDetail, event.CauseCode, event.RiskScore)
	}
}

// isRelevantMessage vérifie si le message est pertinent pour l'analyse de couverture
func (ca *CoverageAnalyzer) isRelevantMessage(procedureName string) bool {
	relevantMessages := map[string]bool{
		"InitialContextSetupFailure": true,
		"E-RABReleaseIndication":     true,
		"UEContextReleaseRequest":    true,
		"HandoverFailure":            true,
		"HandoverPreparationFailure": true,
		"E-RABSetupFailure":          true,
	}
	return relevantMessages[procedureName]
}

// extractECGIMapping extrait le mapping UE -> ECGI depuis les messages
func (ca *CoverageAnalyzer) extractECGIMapping(msg *S1APMessage) {
	var mmeUeS1apID string
	var ecgi string
	
	// Extraire MME-UE-S1AP-ID et ECGI
	for _, ie := range msg.IEs {
		switch ie.ID {
		case 0: // MME-UE-S1AP-ID
			if val := ca.extractIntValue(ie); val != -1 {
				mmeUeS1apID = fmt.Sprintf("%d", val)
			}
		case 100: // EUTRAN-CGI
			if ie.Value != nil {
				ecgi = ca.extractECGI(fmt.Sprintf("%v", ie.Value))
			}
		}
	}
	
	// Enregistrer le mapping si on a les deux informations
	if mmeUeS1apID != "" && ecgi != "" {
		ca.mutex.Lock()
		ca.ueToECGI[mmeUeS1apID] = ecgi
		ca.mutex.Unlock()
		
		if ca.config.Debug {
			log.Printf("COVERAGE: Mapped UE %s -> ECGI %s", mmeUeS1apID, ecgi)
		}
	}
}

// createCoverageEvent crée un événement de couverture
func (ca *CoverageAnalyzer) createCoverageEvent(msg *S1APMessage) *CellCoverageEvent {
	event := &CellCoverageEvent{
		Timestamp:     msg.Timestamp.UnixMilli(),
		TimestampStr:  msg.Timestamp.Format("2006-01-02 15:04:05.000"),
		MessageType:   msg.ProcedureName,
		PacketNumber:  int32(msg.PacketNumber),
		SourceIP:      msg.SrcIP,
		DestinationIP: msg.DstIP,
	}
	
	// Extraire les informations des IEs
	var mmeUeS1apID string
	var hasRadioCause bool
	var hasCause bool
	
	if ca.config.Debug {
		log.Printf("COVERAGE DEBUG: Processing %s with %d IEs", msg.ProcedureName, len(msg.IEs))
	}
	
	for _, ie := range msg.IEs {
		if ca.config.Debug {
			log.Printf("COVERAGE DEBUG: IE ID=%d, Type=%T, Value=%v, RawValue=%s", 
				ie.ID, ie.Value, ie.Value, ie.RawValue)
		}
		
		switch ie.ID {
		case 0: // MME-UE-S1AP-ID
			if val := ca.extractIntValue(ie); val != -1 {
				event.MMEUeS1apID = val
				mmeUeS1apID = fmt.Sprintf("%d", val)
				if ca.config.Debug {
					log.Printf("COVERAGE DEBUG: Found MME-UE-S1AP-ID: %d", val)
				}
			}
		case 8: // eNB-UE-S1AP-ID
			if val := ca.extractIntValue(ie); val != -1 {
				event.ENBUeS1apID = val
				if ca.config.Debug {
					log.Printf("COVERAGE DEBUG: Found eNB-UE-S1AP-ID: %d", val)
				}
			}
		case 2: // Cause
			hasCause = true
			if ca.config.Debug {
				log.Printf("COVERAGE DEBUG: Processing Cause IE - Value: %v, RawValue: %s", ie.Value, ie.RawValue)
			}
			if ca.extractCauseInfo(event, ie) {
				hasRadioCause = true
				if ca.config.Debug {
					log.Printf("COVERAGE DEBUG: Radio cause detected: %s (code %d)", event.CauseDetail, event.CauseCode)
				}
			} else {
				if ca.config.Debug {
					log.Printf("COVERAGE DEBUG: Non-radio cause or parsing failed")
				}
			}
		case 100: // EUTRAN-CGI
			if ie.Value != nil {
				event.ECGI = ca.extractECGI(fmt.Sprintf("%v", ie.Value))
				event.PLMN, event.CellID = ca.parseECGI(event.ECGI)
				if ca.config.Debug {
					log.Printf("COVERAGE DEBUG: Found ECGI: %s (PLMN: %s, CellID: %s)", event.ECGI, event.PLMN, event.CellID)
				}
			}
		}
	}
	
	// Si pas d'ECGI direct, essayer de le retrouver via le mapping UE
	if event.ECGI == "" && mmeUeS1apID != "" {
		ca.mutex.RLock()
		if ecgi, exists := ca.ueToECGI[mmeUeS1apID]; exists {
			event.ECGI = ecgi
			event.PLMN, event.CellID = ca.parseECGI(ecgi)
			if ca.config.Debug {
				log.Printf("COVERAGE DEBUG: Mapped ECGI from UE: %s", ecgi)
			}
		}
		ca.mutex.RUnlock()
	}
	
	if ca.config.Debug {
		log.Printf("COVERAGE DEBUG: Event summary - ECGI: %s, HasRadioCause: %t, HasCause: %t", 
			event.ECGI, hasRadioCause, hasCause)
	}
	
	// Pour les messages Failure, accepter même sans cause radio spécifique si on a l'ECGI
	if strings.Contains(msg.ProcedureName, "Failure") && event.ECGI != "" && !hasRadioCause {
		// Créer une cause par défaut pour les échecs
		event.CauseDetail = "general-failure"
		event.CauseCode = 0
		event.CauseType = "radioNetwork"
		event.RiskScore = 3.0 // Score modéré pour échecs sans cause spécifique
		event.SeverityLevel = "MEDIUM"
		hasRadioCause = true
		
		if ca.config.Debug {
			log.Printf("COVERAGE DEBUG: Created default cause for failure message")
		}
	}
	
	// Ne garder que les événements avec ECGI et une cause
	if event.ECGI == "" {
		if ca.config.Debug {
			log.Printf("COVERAGE DEBUG: Rejected - no ECGI")
		}
		return nil
	}
	
	if !hasRadioCause {
		if ca.config.Debug {
			log.Printf("COVERAGE DEBUG: Rejected - no radio cause")
		}
		return nil
	}
	
	// Calculer le score de risque si pas déjà fait
	if event.RiskScore == 0 {
		event.RiskScore = ca.getRiskScore(event.CauseDetail)
		event.SeverityLevel = ca.getSeverityLevel(event.RiskScore)
	}
	
	return event
}

// extractIntValue extrait une valeur entière d'un IE
func (ca *CoverageAnalyzer) extractIntValue(ie *s1ap.InformationElement) int64 {
	if ie.Value == nil {
		return -1
	}
	
	switch val := ie.Value.(type) {
	case int32:
		return int64(val)
	case int64:
		return val
	case int:
		return int64(val)
	default:
		// Essayer de parser la raw value
		if ie.RawValue != "" {
			if parsed, err := strconv.ParseInt(ie.RawValue, 10, 64); err == nil {
				return parsed
			}
		}
		return -1
	}
}

// extractCauseInfo extrait les informations de cause radio
func (ca *CoverageAnalyzer) extractCauseInfo(event *CellCoverageEvent, ie *s1ap.InformationElement) bool {
	if ie.Value == nil {
		return false
	}
	
	causeStr := fmt.Sprintf("%v", ie.Value)
	
	// Vérifier si c'est une cause radio
	if !strings.Contains(causeStr, "radioNetwork") {
		return false
	}
	
	event.CauseType = "radioNetwork"
	
	// Extraire le code de cause et le détail
	if ca.parseCauseDetail(causeStr, event) {
		return ca.isRadioCoverageCause(event.CauseDetail)
	}
	
	return false
}

// parseCauseDetail parse les détails de la cause
func (ca *CoverageAnalyzer) parseCauseDetail(causeStr string, event *CellCoverageEvent) bool {
	// Mapping des causes radio critiques pour la couverture
	radioCauses := map[string]int32{
		"radio-connection-with-ue-lost":                  21,
		"failure-in-radio-interface-procedure":          26,
		"handover-desirable-for-radio-reason":           16,
		"handover-failure-in-target-e-utran":            10,
		"partial-handover":                               5,
		"handover-cancelled":                             6,
		"successful-handover":                            7,
		"release-due-to-handover":                        8,
		"handover-failure-in-target-epc-enb":            11,
		"ho-target-not-allowed":                          12,
		"ts1relocoverall-expiry":                         13,
		"ts1relocprep-expiry":                            14,
		"cell-not-available":                             15,
		"no-radio-resources-available-in-target-cell":   17,
		"radio-resources-not-available":                  25,
	}
	
	// Chercher la cause dans la chaîne
	for cause, code := range radioCauses {
		if strings.Contains(strings.ToLower(causeStr), cause) {
			event.CauseDetail = cause
			event.CauseCode = code
			return true
		}
	}
	
	// Si pas trouvé, essayer d'extraire depuis le format standard
	if strings.Contains(causeStr, "(") && strings.Contains(causeStr, ")") {
		start := strings.Index(causeStr, "(")
		end := strings.Index(causeStr, ")")
		if start < end {
			codeStr := causeStr[start+1 : end]
			if code, err := strconv.ParseInt(codeStr, 10, 32); err == nil {
				event.CauseCode = int32(code)
				event.CauseDetail = ca.getCauseDetailByCode(int32(code))
				return event.CauseDetail != ""
			}
		}
	}
	
	return false
}

// getCauseDetailByCode retourne le détail de la cause par code
func (ca *CoverageAnalyzer) getCauseDetailByCode(code int32) string {
	codeMap := map[int32]string{
		21: "radio-connection-with-ue-lost",
		26: "failure-in-radio-interface-procedure",
		16: "handover-desirable-for-radio-reason",
		10: "handover-failure-in-target-e-utran",
		5:  "partial-handover",
		25: "radio-resources-not-available",
		17: "no-radio-resources-available-in-target-cell",
	}
	return codeMap[code]
}

// isRadioCoverageCause vérifie si la cause est liée à la couverture radio
func (ca *CoverageAnalyzer) isRadioCoverageCause(causeDetail string) bool {
	coverageCauses := map[string]bool{
		"radio-connection-with-ue-lost":                  true,
		"failure-in-radio-interface-procedure":          true,
		"handover-desirable-for-radio-reason":           true,
		"handover-failure-in-target-e-utran":            true,
		"partial-handover":                               true,
		"radio-resources-not-available":                 true,
		"no-radio-resources-available-in-target-cell":   true,
	}
	return coverageCauses[causeDetail]
}

// getRiskScore calcule le score de risque selon la cause
func (ca *CoverageAnalyzer) getRiskScore(causeDetail string) float64 {
	switch causeDetail {
	case "radio-connection-with-ue-lost":                  // cause 21
		return 10.0
	case "handover-failure-in-target-e-utran":            // cause 10
		return 9.0
	case "failure-in-radio-interface-procedure":          // cause 26
		return 8.0
	case "partial-handover":                               // cause 5
		return 7.0
	case "radio-resources-not-available":                 // cause 25
		return 6.5
	case "no-radio-resources-available-in-target-cell":   // cause 17
		return 6.0
	case "handover-desirable-for-radio-reason":           // cause 16
		return 5.0
	case "general-failure":                                // échecs généraux
		return 3.0
	default:
		return 1.0
	}
}

// getSeverityLevel détermine le niveau de sévérité
func (ca *CoverageAnalyzer) getSeverityLevel(riskScore float64) string {
	switch {
	case riskScore >= 9.0:
		return "CRITICAL"
	case riskScore >= 7.0:
		return "HIGH"
	case riskScore >= 5.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// extractECGI extrait l'ECGI depuis la valeur de l'IE
func (ca *CoverageAnalyzer) extractECGI(ecgiStr string) string {
	if ecgiStr == "" {
		return ""
	}
	
	// Format: "EUTRAN_CGI(PLMN:620f10, CellID:00001234)"
	if strings.Contains(ecgiStr, "PLMN:") && strings.Contains(ecgiStr, "CellID:") {
		var plmn, cellID string
		
		parts := strings.Split(ecgiStr, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.Contains(part, "PLMN:") {
				plmn = strings.Split(part, "PLMN:")[1]
				plmn = strings.TrimRight(plmn, ",)")
			} else if strings.Contains(part, "CellID:") {
				cellID = strings.Split(part, "CellID:")[1]
				cellID = strings.TrimRight(cellID, ",)")
			}
		}
		
		if plmn != "" && cellID != "" {
			return fmt.Sprintf("%s-%s", plmn, cellID)
		}
	}
	
	return ecgiStr
}

// parseECGI sépare PLMN et CellID depuis ECGI
func (ca *CoverageAnalyzer) parseECGI(ecgi string) (string, string) {
	if strings.Contains(ecgi, "-") {
		parts := strings.Split(ecgi, "-")
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}
	return ecgi, ""
}

// updateCellStats met à jour les statistiques de la cellule
func (ca *CoverageAnalyzer) updateCellStats(event *CellCoverageEvent) {
	ecgi := event.ECGI
	if ecgi == "" {
		return
	}
	
	// Créer ou récupérer les stats de la cellule
	if ca.cellStats[ecgi] == nil {
		ca.cellStats[ecgi] = &CellCoverageStats{
			ECGI:         ecgi,
			PLMN:         event.PLMN,
			CellID:       event.CellID,
			FirstSeen:    time.Unix(event.Timestamp/1000, 0),
			MessageTypes: make(map[string]int),
		}
	}
	
	stats := ca.cellStats[ecgi]
	stats.TotalFailures++
	stats.LastSeen = time.Unix(event.Timestamp/1000, 0)
	stats.MessageTypes[event.MessageType]++
	
	// Compter par type de cause
	switch event.CauseDetail {
	case "radio-connection-with-ue-lost":
		stats.RadioConnectionLost++
	case "failure-in-radio-interface-procedure":
		stats.FailureInRadioProcedure++
	case "handover-failure-in-target-e-utran", "partial-handover":
		stats.HandoverFailures++
	case "handover-desirable-for-radio-reason":
		stats.HandoverRadioReason++
	default:
		stats.OtherRadioFailures++
	}
	
	// Mettre à jour le score de risque
	stats.RiskScore += event.RiskScore
	
	// Compter les UEs uniques (approximation basée sur MME-UE-S1AP-ID)
	if event.MMEUeS1apID != 0 {
		stats.UECount++ // Note: ceci peut compter plusieurs fois le même UE
	}
}

// GenerateReport génère le rapport final d'analyse de couverture
func (ca *CoverageAnalyzer) GenerateReport() error {
	ca.mutex.RLock()
	defer ca.mutex.RUnlock()
	
	log.Printf("INFO: Generating coverage analysis report...")
	log.Printf("INFO: Found %d coverage events across %d cells", len(ca.events), len(ca.cellStats))
	
	if len(ca.events) == 0 && len(ca.cellStats) == 0 {
		log.Printf("INFO: No coverage events detected - no report generated")
		return nil
	}
	
	// Afficher un résumé des événements détectés
	eventTypes := make(map[string]int)
	severityCount := make(map[string]int)
	
	for _, event := range ca.events {
		eventTypes[event.MessageType]++
		severityCount[event.SeverityLevel]++
	}
	
	log.Printf("INFO: Coverage Events Summary:")
	for msgType, count := range eventTypes {
		log.Printf("INFO:   %s: %d events", msgType, count)
	}
	
	log.Printf("INFO: Severity Distribution:")
	for severity, count := range severityCount {
		log.Printf("INFO:   %s: %d events", severity, count)
	}
	
	// Afficher les cellules les plus problématiques
	log.Printf("INFO: Top problematic cells:")
	for ecgi, stats := range ca.cellStats {
		if stats.TotalFailures > 0 {
			log.Printf("INFO:   Cell %s: %d failures (Risk: %.1f)", 
				ecgi, stats.TotalFailures, stats.RiskScore)
		}
	}
	
	log.Printf("INFO: Coverage analysis report generation completed")
	
	return nil
}
