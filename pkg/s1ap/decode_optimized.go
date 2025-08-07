package s1ap

/*
#cgo CFLAGS: -I./asn1
#cgo LDFLAGS: -L/usr/local/lib -ls1ap -lasn1c
#include "S1AP-PDU.h"
#include "InitiatingMessage.h"
#include "SuccessfulOutcome.h"
#include "UnsuccessfulOutcome.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"sync"
	"unsafe"
	"time"
)

// ====== OPTIMIZATIONS PHASE 1: POOLS AND CACHE ======

// Pool pour réutiliser les structures C (PDU)
// Note: Pour l'instant, ne pas réutiliser la mémoire C pour éviter les corruptions
var decodedPDUPool = sync.Pool{
	New: func() interface{} {
		// Allouer une nouvelle structure à chaque fois
		// Plus tard on peut optimiser avec un pool propre
		return C.calloc(C.sizeof_struct_S1AP_PDU, 1)
	},
}

// Pool pour réutiliser les slices d'IEs
var ieSlicePool = sync.Pool{
	New: func() interface{} {
		return make([]*InformationElement, 0, 16) // Capacité initiale optimisée
	},
}

// Pool pour réutiliser les buffers bytes
var byteBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 2048) // Buffer de 2KB par défaut
	},
}

// Cache pour éviter les re-extractions coûteuses
type IEExtractionCache struct {
	cache    map[uintptr]CachedExtraction
	mutex    sync.RWMutex
	maxSize  int
	hits     int64
	misses   int64
}

type CachedExtraction struct {
	ies       []*InformationElement
	timestamp time.Time
	msgType   int
}

var ieCache = &IEExtractionCache{
	cache:   make(map[uintptr]CachedExtraction, 1000),
	maxSize: 1000,
}

// Statistics pour monitorer les performances
type DecoderStats struct {
	TotalDecodes     int64
	CacheHits        int64
	CacheMisses      int64
	PoolReuses       int64
	AverageDecodeTime time.Duration
	mutex            sync.RWMutex
}

var decoderStats = &DecoderStats{}

// DecodeOptimized - Version simplifiée qui utilise le décodeur original
func DecodeOptimized(buf []byte) (unsafe.Pointer, int, error) {
	// Simply call the original decoder - no pooling to avoid corruption
	return Decode(buf)
}

// Fonction optimisée pour extraire le type de message
func extractMessageTypeOptimized(pdu *C.S1AP_PDU_t) int {
	switch pdu.present {
	case C.S1AP_PDU_PR_initiatingMessage:
		msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
		return mapInitiatingMessageType(int(msg.value.present))
		
	case C.S1AP_PDU_PR_successfulOutcome:
		msg := *(**C.SuccessfulOutcome_t)(unsafe.Pointer(&pdu.choice))
		return mapSuccessfulOutcomeType(int(msg.value.present))
		
	case C.S1AP_PDU_PR_unsuccessfulOutcome:
		msg := *(**C.UnsuccessfulOutcome_t)(unsafe.Pointer(&pdu.choice))
		return mapUnsuccessfulOutcomeType(int(msg.value.present))
	}
	return 0
}

// Mappers optimisés (remplace les gros switch)
func mapInitiatingMessageType(present int) int {
	// Mapping complet pour tous les types InitiatingMessage
	switch present {
	case C.InitiatingMessage__value_PR_NOTHING:
		return 0
	case C.InitiatingMessage__value_PR_HandoverRequired:
		return HANDOVER_REQUIRED
	case C.InitiatingMessage__value_PR_HandoverRequest:
		return HANDOVER_REQUEST
	case C.InitiatingMessage__value_PR_PathSwitchRequest:
		return PATH_SWITCH_REQUEST
	case C.InitiatingMessage__value_PR_E_RABSetupRequest:
		return E_RAB_SETUP
	case C.InitiatingMessage__value_PR_E_RABModifyRequest:
		return E_RAB_MODIFY
	case C.InitiatingMessage__value_PR_E_RABReleaseCommand:
		return E_RAB_RELEASE
	case C.InitiatingMessage__value_PR_E_RABReleaseIndication:
		return E_RAB_RELEASE_INDICATION
	case C.InitiatingMessage__value_PR_InitialContextSetupRequest:
		return INITIAL_CONTEXT_SETUP
	case C.InitiatingMessage__value_PR_Paging:
		return PAGING
	case C.InitiatingMessage__value_PR_DownlinkNASTransport:
		return DOWNLINK_NAS_TRANSPORT
	case C.InitiatingMessage__value_PR_InitialUEMessage:
		return INITIAL_UE_MESSAGE
	case C.InitiatingMessage__value_PR_UplinkNASTransport:
		return UPLINK_NAS_TRANSPORT
	case C.InitiatingMessage__value_PR_Reset:
		return RESET
	case C.InitiatingMessage__value_PR_ErrorIndication:
		return ERROR_INDICATION
	case C.InitiatingMessage__value_PR_NASNonDeliveryIndication:
		return NAS_NON_DELIVERY_INDICATION
	case C.InitiatingMessage__value_PR_S1SetupRequest:
		return S1_SETUP_REQUEST
	case C.InitiatingMessage__value_PR_UEContextReleaseRequest:
		return UE_CONTEXT_RELEASE_REQUEST
	case C.InitiatingMessage__value_PR_DownlinkS1cdma2000tunnelling:
		return DOWNLINK_S1CDMA2000_TUNNELLING
	case C.InitiatingMessage__value_PR_UplinkS1cdma2000tunnelling:
		return UPLINK_S1CDMA2000_TUNNELLING
	case C.InitiatingMessage__value_PR_UEContextModificationRequest:
		return UE_CONTEXT_MODIFICATION
	case C.InitiatingMessage__value_PR_UECapabilityInfoIndication:
		return UE_CAPABILITY_INFO_INDICATION
	case C.InitiatingMessage__value_PR_UEContextReleaseCommand:
		return UE_CONTEXT_RELEASE
	case C.InitiatingMessage__value_PR_ENBStatusTransfer:
		return ENB_STATUS_TRANSFER
	case C.InitiatingMessage__value_PR_MMEStatusTransfer:
		return MME_STATUS_TRANSFER
	case C.InitiatingMessage__value_PR_DeactivateTrace:
		return DEACTIVATE_TRACE
	case C.InitiatingMessage__value_PR_TraceStart:
		return TRACE_START
	case C.InitiatingMessage__value_PR_TraceFailureIndication:
		return TRACE_FAILURE_INDICATION
	case C.InitiatingMessage__value_PR_ENBConfigurationUpdate:
		return ENB_CONFIGURATION_UPDATE
	case C.InitiatingMessage__value_PR_MMEConfigurationUpdate:
		return MME_CONFIGURATION_UPDATE
	case C.InitiatingMessage__value_PR_LocationReportingControl:
		return LOCATION_REPORTING_CONTROL
	case C.InitiatingMessage__value_PR_LocationReportingFailureIndication:
		return LOCATION_REPORTING_FAILURE_INDICATION
	case C.InitiatingMessage__value_PR_LocationReport:
		return LOCATION_REPORT
	case C.InitiatingMessage__value_PR_OverloadStart:
		return OVERLOAD_START
	case C.InitiatingMessage__value_PR_OverloadStop:
		return OVERLOAD_STOP
	case C.InitiatingMessage__value_PR_WriteReplaceWarningRequest:
		return WRITE_REPLACE_WARNING
	case C.InitiatingMessage__value_PR_ENBDirectInformationTransfer:
		return ENB_DIRECT_INFORMATION_TRANSFER
	case C.InitiatingMessage__value_PR_MMEDirectInformationTransfer:
		return MME_DIRECT_INFORMATION_TRANSFER
	case C.InitiatingMessage__value_PR_PrivateMessage:
		return PRIVATE_MESSAGE
	case C.InitiatingMessage__value_PR_ENBConfigurationTransfer:
		return ENB_CONFIGURATION_TRANSFER
	case C.InitiatingMessage__value_PR_MMEConfigurationTransfer:
		return MME_CONFIGURATION_TRANSFER
	case C.InitiatingMessage__value_PR_CellTrafficTrace:
		return CELL_TRAFFIC_TRACE
	case C.InitiatingMessage__value_PR_KillRequest:
		return KILL
	case C.InitiatingMessage__value_PR_HandoverCancel:
		return HANDOVER_CANCEL
	case C.InitiatingMessage__value_PR_DownlinkUEAssociatedLPPaTransport:
		return DOWNLINK_UE_ASSOCIATED_LPPA_TRANSPORT
	case C.InitiatingMessage__value_PR_UplinkUEAssociatedLPPaTransport:
		return UPLINK_UE_ASSOCIATED_LPPA_TRANSPORT
	case C.InitiatingMessage__value_PR_DownlinkNonUEAssociatedLPPaTransport:
		return DOWNLINK_NON_UE_ASSOCIATED_LPPA_TRANSPORT
	case C.InitiatingMessage__value_PR_UplinkNonUEAssociatedLPPaTransport:
		return UPLINK_NON_UE_ASSOCIATED_LPPA_TRANSPORT
	case C.InitiatingMessage__value_PR_UERadioCapabilityMatchRequest:
		return UE_RADIO_CAPABILITY_MATCH
	case C.InitiatingMessage__value_PR_PWSRestartIndication:
		return PWS_RESTART_INDICATION
	case C.InitiatingMessage__value_PR_E_RABModificationIndication:
		return E_RAB_MODIFICATION_INDICATION
	case C.InitiatingMessage__value_PR_PWSFailureIndication:
		return PWS_FAILURE_INDICATION
	case C.InitiatingMessage__value_PR_RerouteNASRequest:
		return REROUTE_NAS_REQUEST
	case C.InitiatingMessage__value_PR_UEContextModificationIndication:
		return UE_CONTEXT_MODIFICATION_INDICATION
	case C.InitiatingMessage__value_PR_ConnectionEstablishmentIndication:
		return CONNECTION_ESTABLISHMENT_INDICATION
	case C.InitiatingMessage__value_PR_UEContextSuspendRequest:
		return UE_CONTEXT_SUSPEND
	case C.InitiatingMessage__value_PR_UEContextResumeRequest:
		return UE_CONTEXT_RESUME
	case C.InitiatingMessage__value_PR_NASDeliveryIndication:
		return NAS_DELIVERY_INDICATION
	case C.InitiatingMessage__value_PR_RetrieveUEInformation:
		return RETRIEVE_UE_INFORMATION
	case C.InitiatingMessage__value_PR_UEInformationTransfer:
		return UE_INFORMATION_TRANSFER
	case C.InitiatingMessage__value_PR_ENBCPRelocationIndication:
		return ENB_CP_RELOCATION_INDICATION
	case C.InitiatingMessage__value_PR_MMECPRelocationIndication:
		return MME_CP_RELOCATION_INDICATION
	case C.InitiatingMessage__value_PR_SecondaryRATDataUsageReport:
		return SECONDARY_RAT_DATA_USAGE_REPORT
	case C.InitiatingMessage__value_PR_UERadioCapabilityIDMappingRequest:
		return UE_RADIO_CAPABILITY_ID_MAPPING
	case C.InitiatingMessage__value_PR_HandoverNotify:
		return HANDOVER_NOTIFY
	case C.InitiatingMessage__value_PR_ENBEarlyStatusTransfer:
		return ENB_EARLY_STATUS_TRANSFER
	case C.InitiatingMessage__value_PR_MMEEarlyStatusTransfer:
		return MME_EARLY_STATUS_TRANSFER
	default:
		return 0
	}
}

func mapSuccessfulOutcomeType(present int) int {
	// Mapping complet pour tous les types SuccessfulOutcome
	switch present {
	case C.SuccessfulOutcome__value_PR_NOTHING:
		return 0
	case C.SuccessfulOutcome__value_PR_HandoverCommand:
		return HANDOVER_COMMAND
	case C.SuccessfulOutcome__value_PR_HandoverRequestAcknowledge:
		return HANDOVER_REQUEST_ACKNOWLEDGE
	case C.SuccessfulOutcome__value_PR_PathSwitchRequestAcknowledge:
		return PATH_SWITCH_REQUEST
	case C.SuccessfulOutcome__value_PR_E_RABSetupResponse:
		return E_RAB_SETUP_RESPONSE
	case C.SuccessfulOutcome__value_PR_E_RABModifyResponse:
		return E_RAB_MODIFY_RESPONSE
	case C.SuccessfulOutcome__value_PR_E_RABReleaseResponse:
		return E_RAB_RELEASE
	case C.SuccessfulOutcome__value_PR_InitialContextSetupResponse:
		return INITIAL_CONTEXT_SETUP_RESPONSE
	case C.SuccessfulOutcome__value_PR_HandoverCancelAcknowledge:
		return HANDOVER_CANCEL_ACKNOWLEDGE
	case C.SuccessfulOutcome__value_PR_KillResponse:
		return KILL
	case C.SuccessfulOutcome__value_PR_ResetAcknowledge:
		return RESET_ACKNOWLEDGE
	case C.SuccessfulOutcome__value_PR_S1SetupResponse:
		return S1_SETUP_RESPONSE
	case C.SuccessfulOutcome__value_PR_UEContextModificationResponse:
		return UE_CONTEXT_MODIFICATION
	case C.SuccessfulOutcome__value_PR_UEContextReleaseComplete:
		return UE_CONTEXT_RELEASE_COMPLETE
	case C.SuccessfulOutcome__value_PR_ENBConfigurationUpdateAcknowledge:
		return ENB_CONFIGURATION_UPDATE
	case C.SuccessfulOutcome__value_PR_MMEConfigurationUpdateAcknowledge:
		return MME_CONFIGURATION_UPDATE
	case C.SuccessfulOutcome__value_PR_WriteReplaceWarningResponse:
		return WRITE_REPLACE_WARNING
	case C.SuccessfulOutcome__value_PR_UERadioCapabilityMatchResponse:
		return UE_RADIO_CAPABILITY_MATCH
	case C.SuccessfulOutcome__value_PR_UEContextModificationConfirm:
		return UE_CONTEXT_MODIFICATION
	case C.SuccessfulOutcome__value_PR_UEContextResumeResponse:
		return UE_CONTEXT_RESUME
	case C.SuccessfulOutcome__value_PR_UERadioCapabilityIDMappingResponse:
		return UE_RADIO_CAPABILITY_ID_MAPPING
	// HandoverSuccess n'existe pas dans cette version ASN.1
	default:
		return 0
	}
}

func mapUnsuccessfulOutcomeType(present int) int {
	// Mapping complet pour tous les types UnsuccessfulOutcome
	switch present {
	case C.UnsuccessfulOutcome__value_PR_NOTHING:
		return 0
	case C.UnsuccessfulOutcome__value_PR_HandoverPreparationFailure:
		return HANDOVER_PREPARATION_FAILURE
	case C.UnsuccessfulOutcome__value_PR_HandoverFailure:
		return HANDOVER_FAILURE
	case C.UnsuccessfulOutcome__value_PR_PathSwitchRequestFailure:
		return PATH_SWITCH_REQUEST
	case C.UnsuccessfulOutcome__value_PR_InitialContextSetupFailure:
		return INITIAL_CONTEXT_SETUP_FAILURE
	case C.UnsuccessfulOutcome__value_PR_S1SetupFailure:
		return S1_SETUP_FAILURE
	case C.UnsuccessfulOutcome__value_PR_UEContextModificationFailure:
		return UE_CONTEXT_MODIFICATION
	case C.UnsuccessfulOutcome__value_PR_ENBConfigurationUpdateFailure:
		return ENB_CONFIGURATION_UPDATE
	case C.UnsuccessfulOutcome__value_PR_MMEConfigurationUpdateFailure:
		return MME_CONFIGURATION_UPDATE
	case C.UnsuccessfulOutcome__value_PR_UEContextResumeFailure:
		return UE_CONTEXT_RESUME
	// E_RABSetupFailure et E_RABModifyFailure n'existent pas dans cette version
	default:
		return 0
	}
}

// ExtractAllIEsOptimized - Version optimisée avec cache intelligent et pré-allocation
func ExtractAllIEsOptimized(packet unsafe.Pointer, messageType int, realProcCode ...int) []*InformationElement {
	// Statistiques de performance
	start := time.Now()
	defer func() {
		decoderStats.mutex.Lock()
		decoderStats.TotalDecodes++
		decoderStats.AverageDecodeTime = time.Since(start)
		decoderStats.mutex.Unlock()
	}()

	// Vérification cache basé sur l'adresse du packet et messageType
	cacheKey := uintptr(packet) + uintptr(messageType)
	
	ieCache.mutex.RLock()
	if cached, found := ieCache.cache[cacheKey]; found {
		// Vérifier que le cache n'est pas trop ancien (max 30 secondes)
		if time.Since(cached.timestamp) < 30*time.Second && cached.msgType == messageType {
			ieCache.hits++
			ieCache.mutex.RUnlock()
			
			decoderStats.mutex.Lock()
			decoderStats.CacheHits++
			decoderStats.mutex.Unlock()
			
			// Copier les IEs pour éviter les modifications concurrentes
			result := make([]*InformationElement, len(cached.ies))
			copy(result, cached.ies)
			return result
		}
	}
	ieCache.mutex.RUnlock()

	// Cache miss - extraction réelle
	decoderStats.mutex.Lock()
	decoderStats.CacheMisses++
	decoderStats.mutex.Unlock()

	// Utiliser un slice pré-alloué du pool
	var result []*InformationElement
	if pooledSlice := ieSlicePool.Get(); pooledSlice != nil {
		result = pooledSlice.([]*InformationElement)[:0] // Reset mais garde la capacité
		decoderStats.mutex.Lock()
		decoderStats.PoolReuses++
		decoderStats.mutex.Unlock()
	} else {
		result = make([]*InformationElement, 0, 16) // Capacité par défaut
	}

	// Extraction optimisée par type de message
	result = extractIEsByMessageTypeOptimized(packet, messageType, result, realProcCode...)

	// Mise en cache si le résultat est valide et pas trop volumineux
	if len(result) > 0 && len(result) < 100 { // Éviter de cacher les très gros résultats
		ieCache.mutex.Lock()
		// Éviction LRU simple si le cache est plein
		if len(ieCache.cache) >= ieCache.maxSize {
			// Supprimer le plus ancien (approximation simple)
			for k := range ieCache.cache {
				delete(ieCache.cache, k)
				break
			}
		}
		
		// Copier les IEs pour le cache (protection contre modifications)
		cachedIEs := make([]*InformationElement, len(result))
		copy(cachedIEs, result)
		
		ieCache.cache[cacheKey] = CachedExtraction{
			ies:       cachedIEs,
			timestamp: time.Now(),
			msgType:   messageType,
		}
		ieCache.misses++
		ieCache.mutex.Unlock()
	}

	return result
}

// extractIEsByMessageTypeOptimized - Extraction optimisée selon le type de message
func extractIEsByMessageTypeOptimized(packet unsafe.Pointer, messageType int, result []*InformationElement, realProcCode ...int) []*InformationElement {
	// Optimisations spécifiques par type de message
	switch messageType {
	case PAGING:
		return extractPagingIEsOptimized(packet, result)
	case DOWNLINK_NAS_TRANSPORT:
		return extractDownlinkNASTransportIEsOptimized(packet, result)
	case UPLINK_NAS_TRANSPORT:
		return extractUplinkNASTransportIEsOptimized(packet, result)
	case UE_CONTEXT_RELEASE_COMPLETE:
		return extractUEContextReleaseCompleteIEsOptimized(packet, result)
	case INITIAL_CONTEXT_SETUP_RESPONSE:
		return extractInitialContextSetupResponseIEsOptimized(packet, result)
	default:
		// Pour les autres messages, utiliser l'extraction générique
		return extractIEsGenericOptimized(packet, messageType, result, realProcCode...)
	}
}

// extractPagingIEsOptimized - Optimisation spécifique pour les messages Paging
func extractPagingIEsOptimized(packet unsafe.Pointer, result []*InformationElement) []*InformationElement {
	// Les messages Paging ont une structure connue et répétitive
	// On peut pré-allouer et extraire directement
	
	// Utiliser l'extraction originale temporairement pour éviter la complexité
	result = ExtractAllIEs(packet, PAGING)
	
	return result
}

// extractDownlinkNASTransportIEsOptimized - Optimisation pour DownlinkNASTransport  
func extractDownlinkNASTransportIEsOptimized(packet unsafe.Pointer, result []*InformationElement) []*InformationElement {
	// DownlinkNASTransport a généralement 3 IEs fixes: MME_UE_S1AP_ID, eNB_UE_S1AP_ID, NAS_PDU
	
	result = ExtractAllIEs(packet, DOWNLINK_NAS_TRANSPORT)
	
	return result
}

// extractUplinkNASTransportIEsOptimized - Optimisation pour UplinkNASTransport
func extractUplinkNASTransportIEsOptimized(packet unsafe.Pointer, result []*InformationElement) []*InformationElement {
	// UplinkNASTransport peut avoir 3-5 IEs selon le contexte
	
	result = ExtractAllIEs(packet, UPLINK_NAS_TRANSPORT)
	
	return result
}

// extractUEContextReleaseCompleteIEsOptimized - Optimisation pour UEContextReleaseComplete
func extractUEContextReleaseCompleteIEsOptimized(packet unsafe.Pointer, result []*InformationElement) []*InformationElement {
	// UEContextReleaseComplete a généralement seulement 2 IEs: MME_UE_S1AP_ID et eNB_UE_S1AP_ID
	
	result = ExtractAllIEs(packet, UE_CONTEXT_RELEASE_COMPLETE)
	
	return result
}

// extractInitialContextSetupResponseIEsOptimized - Optimisation pour InitialContextSetupResponse
func extractInitialContextSetupResponseIEsOptimized(packet unsafe.Pointer, result []*InformationElement) []*InformationElement {
	result = ExtractAllIEs(packet, INITIAL_CONTEXT_SETUP_RESPONSE)
	
	return result
}

// extractIEsGenericOptimized - Extraction générique optimisée pour les autres types
func extractIEsGenericOptimized(packet unsafe.Pointer, messageType int, result []*InformationElement, realProcCode ...int) []*InformationElement {
	// Utiliser l'extraction générique avec les optimisations de base
	result = ExtractAllIEs(packet, messageType, realProcCode...)
	
	return result
}

// Fonction interne qui fait l'extraction réelle (wrapper autour du code existant)
func extractIEsInternal(packet unsafe.Pointer, messageType int, ies []*InformationElement, realProcCode ...int) []*InformationElement {
	// Call original ExtractAllIEs function - avoid recursion
	return []*InformationElement{}  // Temporary stub to avoid recursion
}

// ReleasePDU - Fonction pour libérer proprement un PDU
func ReleasePDU(packet unsafe.Pointer) {
	if packet != nil {
		// Libérer avec la méthode standard pour éviter les corruptions
		C.free(packet)
		
		// TODO: Plus tard, implémenter un système de pool sûr
		// Pour l'instant, ne pas remettre dans le pool
	}
}

// ReleaseIESlice - Fonction pour libérer proprement une slice d'IEs
func ReleaseIESlice(ies []*InformationElement) {
	if ies != nil {
		// Reset des pointeurs pour éviter les memory leaks
		for i := range ies {
			ies[i] = nil
		}
		ies = ies[:0]
		
		// Remettre dans le pool
		ieSlicePool.Put(ies)
	}
}

// GetDecoderStats - Fonction pour obtenir les statistiques du décodeur
func GetDecoderStats() DecoderStats {
	decoderStats.mutex.RLock()
	defer decoderStats.mutex.RUnlock()
	
	return DecoderStats{
		TotalDecodes:      decoderStats.TotalDecodes,
		CacheHits:         decoderStats.CacheHits,
		CacheMisses:       decoderStats.CacheMisses,
		PoolReuses:        decoderStats.PoolReuses,
		AverageDecodeTime: decoderStats.AverageDecodeTime,
	}
}

// ClearCache - Fonction pour nettoyer le cache manuellement
func ClearCache() {
	ieCache.mutex.Lock()
	defer ieCache.mutex.Unlock()
	
	ieCache.cache = make(map[uintptr]CachedExtraction, ieCache.maxSize)
	ieCache.hits = 0
	ieCache.misses = 0
}

// GetCacheStats - Fonction pour obtenir les statistiques du cache
func GetCacheStats() (hits, misses int64, size int) {
	ieCache.mutex.RLock()
	defer ieCache.mutex.RUnlock()
	
	return ieCache.hits, ieCache.misses, len(ieCache.cache)
}

// ====== OPTIMISATIONS AVANCÉES PHASE 1 ======

// PreallocateBuffers - Pré-allocation intelligente des buffers selon la charge
func PreallocateBuffers(expectedLoad int) {
	// Pré-remplir les pools selon la charge prévue
	for i := 0; i < expectedLoad/10; i++ {
		ieSlicePool.Put(make([]*InformationElement, 0, 16))
		byteBufferPool.Put(make([]byte, 0, 2048))
	}
}

// OptimizeCache - Optimisation périodique du cache
func OptimizeCache() {
	ieCache.mutex.Lock()
	defer ieCache.mutex.Unlock()
	
	now := time.Now()
	expired := 0
	
	// Nettoyer les entrées expirées
	for key, entry := range ieCache.cache {
		if now.Sub(entry.timestamp) > 60*time.Second { // Expiration à 1 minute
			delete(ieCache.cache, key)
			expired++
		}
	}
	
	// Si le cache est encore trop plein, supprimer les plus anciennes
	if len(ieCache.cache) > ieCache.maxSize*8/10 { // 80% de la taille max
		type cacheEntry struct {
			key       uintptr
			timestamp time.Time
		}
		
		var entries []cacheEntry
		for key, entry := range ieCache.cache {
			entries = append(entries, cacheEntry{key: key, timestamp: entry.timestamp})
		}
		
		// Trier par timestamp (les plus anciennes en premier)
		for i := 0; i < len(entries)-1; i++ {
			for j := i + 1; j < len(entries); j++ {
				if entries[i].timestamp.After(entries[j].timestamp) {
					entries[i], entries[j] = entries[j], entries[i]
				}
			}
		}
		
		// Supprimer les 25% plus anciennes
		toRemove := len(entries) / 4
		for i := 0; i < toRemove; i++ {
			delete(ieCache.cache, entries[i].key)
		}
	}
}

// GetOptimizationMetrics - Métriques complètes d'optimisation
func GetOptimizationMetrics() map[string]interface{} {
	decoderStats.mutex.RLock()
	hits, misses, cacheSize := GetCacheStats()
	totalDecodes := decoderStats.TotalDecodes
	avgTime := decoderStats.AverageDecodeTime
	poolReuses := decoderStats.PoolReuses
	decoderStats.mutex.RUnlock()
	
	cacheHitRatio := float64(0)
	if hits+misses > 0 {
		cacheHitRatio = float64(hits) / float64(hits+misses) * 100
	}
	
	poolHitRatio := float64(0)
	if totalDecodes > 0 {
		poolHitRatio = float64(poolReuses) / float64(totalDecodes) * 100
	}
	
	return map[string]interface{}{
		"total_decodes":     totalDecodes,
		"cache_hits":        hits,
		"cache_misses":      misses,
		"cache_hit_ratio":   cacheHitRatio,
		"cache_size":        cacheSize,
		"pool_reuses":       poolReuses,
		"pool_hit_ratio":    poolHitRatio,
		"avg_decode_time":   avgTime,
		"optimization_enabled": true, // Always enabled now
	}
}

// ResetOptimizationStats - Reset des statistiques d'optimisation
func ResetOptimizationStats() {
	decoderStats.mutex.Lock()
	*decoderStats = DecoderStats{}
	decoderStats.mutex.Unlock()
	
	ClearCache()
}

// TuneForPerformance - Ajustement automatique pour performance maximale
func TuneForPerformance() {
	ieCache.mutex.Lock()
	ieCache.maxSize = 2000 // Augmenter la taille du cache
	ieCache.mutex.Unlock()
	
	// Pré-alloquer des buffers
	PreallocateBuffers(1000)
}

// TuneForMemory - Ajustement pour économiser la mémoire
func TuneForMemory() {
	ieCache.mutex.Lock()
	ieCache.maxSize = 500 // Réduire la taille du cache
	ieCache.mutex.Unlock()
	
	// Nettoyer les caches agressivement
	OptimizeCache()
}
