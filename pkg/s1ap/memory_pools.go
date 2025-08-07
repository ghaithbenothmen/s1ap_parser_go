package s1ap

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// MemoryPools gère tous les pools mémoire pour optimiser les allocations
type MemoryPools struct {
	// Pool pour les messages S1AP
	messagePool sync.Pool
	
	// Pool pour les slices d'IEs
	ieSlicePool sync.Pool
	
	// Pool pour les buffers bytes
	byteBufferPool sync.Pool
	
	// Pool pour les wrappers PDU (attention: pas les pointeurs C directement)
	pduWrapperPool sync.Pool
	
	// Statistiques de performance
	stats PoolStats
	mutex sync.RWMutex
}

// PoolStats contient les statistiques détaillées des pools
type PoolStats struct {
	// Compteurs de Get/Put
	MessageGets    int64
	MessagePuts    int64
	IESliceGets    int64
	IESlicePuts    int64
	ByteBufferGets int64
	ByteBufferPuts int64
	PDUGets        int64
	PDUPuts        int64
	
	// Métriques de performance
	MemorySaved    int64 // Estimation des bytes économisés
	AllocationTime int64 // Temps total d'allocation économisé (ns)
}

// PDUWrapper encapsule un pointeur PDU C avec métadonnées
type PDUWrapper struct {
	Ptr         unsafe.Pointer
	IsUsed      bool
	AllocTime   int64 // Timestamp d'allocation
	UseCount    int   // Nombre d'utilisations
}

// Pool global unique pour toute l'application
var globalPools *MemoryPools

// Initialisation des pools au démarrage
func init() {
	initializePools()
}

// initializePools configure tous les pools avec leurs stratégies d'allocation
func initializePools() {
	globalPools = &MemoryPools{}
	
	// Pool pour les messages S1AP - objets lourds réutilisables
	globalPools.messagePool.New = func() interface{} {
		// Retourner une map générique pour compatibilité avec différents types de messages
		msg := make(map[string]interface{})
		msg["ies"] = make([]*InformationElement, 0, 15) // Pré-allocation optimisée
		atomic.AddInt64(&globalPools.stats.MessageGets, 1)
		return msg
	}
	
	// Pool pour les slices d'IEs - optimisé pour les tailles communes
	globalPools.ieSlicePool.New = func() interface{} {
		slice := make([]*InformationElement, 0, 25) // Capacité généreuse
		atomic.AddInt64(&globalPools.stats.IESliceGets, 1)
		return slice
	}
	
	// Pool pour les buffers bytes - plusieurs tailles prédéfinies
	globalPools.byteBufferPool.New = func() interface{} {
		buffer := make([]byte, 0, 4096) // Buffer de 4KB par défaut
		atomic.AddInt64(&globalPools.stats.ByteBufferGets, 1)
		return buffer
	}
	
	// Pool pour les wrappers PDU C (pas les pointeurs C directement)
	globalPools.pduWrapperPool.New = func() interface{} {
		wrapper := &PDUWrapper{
			Ptr:       nil,
			IsUsed:    false,
			AllocTime: 0,
			UseCount:  0,
		}
		atomic.AddInt64(&globalPools.stats.PDUGets, 1)
		return wrapper
	}
	
	log.Printf("INFO: Memory pools initialized")
}

// GetMessage obtient un message pré-alloué du pool
func GetMessage() interface{} {
	return globalPools.messagePool.Get()
}

// PutMessage remet un message dans le pool pour réutilisation
func PutMessage(msg interface{}) {
	if msg == nil {
		return
	}
	
	// Reset des champs si c'est une map
	if m, ok := msg.(map[string]interface{}); ok {
		for key := range m {
			delete(m, key)
		}
		m["ies"] = make([]*InformationElement, 0, 15)
	}
	
	globalPools.messagePool.Put(msg)
	atomic.AddInt64(&globalPools.stats.MessagePuts, 1)
}

// GetIESlice obtient une slice d'IEs pré-allouée du pool
func GetIESlice() []*InformationElement {
	slice := globalPools.ieSlicePool.Get().([]*InformationElement)
	
	// Reset la longueur mais garde la capacité
	slice = slice[:0]
	
	// Estimation de mémoire économisée
	atomic.AddInt64(&globalPools.stats.MemorySaved, int64(cap(slice))*int64(unsafe.Sizeof((*InformationElement)(nil))))
	
	return slice
}

// PutIESlice remet une slice d'IEs dans le pool
func PutIESlice(slice []*InformationElement) {
	if slice == nil {
		return
	}
	
	// Nettoyer toutes les références
	for i := range slice {
		slice[i] = nil
	}
	
	// Réutiliser seulement si pas trop grande (prévenir l'inflation mémoire)
	if cap(slice) <= 100 {
		atomic.AddInt64(&globalPools.stats.IESlicePuts, 1)
		globalPools.ieSlicePool.Put(slice)
	}
}

// GetByteBuffer obtient un buffer bytes optimisé du pool
func GetByteBuffer(minSize int) []byte {
	buffer := globalPools.byteBufferPool.Get().([]byte)
	
	// Redimensionner si nécessaire
	if cap(buffer) < minSize {
		// Allouer un nouveau buffer plus grand
		buffer = make([]byte, 0, nextPowerOfTwo(minSize))
	} else {
		// Reset la longueur
		buffer = buffer[:0]
	}
	
	// Estimation de mémoire économisée
	atomic.AddInt64(&globalPools.stats.MemorySaved, int64(cap(buffer)))
	
	return buffer
}

// PutByteBuffer remet un buffer dans le pool
func PutByteBuffer(buffer []byte) {
	if buffer == nil {
		return
	}
	
	// Réutiliser seulement si pas trop grand (limite à 16KB)
	if cap(buffer) <= 16384 {
		atomic.AddInt64(&globalPools.stats.ByteBufferPuts, 1)
		globalPools.byteBufferPool.Put(buffer)
	}
}

// GetPDUWrapper obtient un wrapper pour PDU C (pas le pointeur C directement)
func GetPDUWrapper() *PDUWrapper {
	wrapper := globalPools.pduWrapperPool.Get().(*PDUWrapper)
	
	// Reset du wrapper
	wrapper.Ptr = nil
	wrapper.IsUsed = false
	wrapper.AllocTime = time.Now().UnixNano()
	wrapper.UseCount = 0
	
	return wrapper
}

// PutPDUWrapper remet un wrapper PDU dans le pool
func PutPDUWrapper(wrapper *PDUWrapper) {
	if wrapper == nil {
		return
	}
	
	// IMPORTANT: S'assurer que le pointeur C est libéré avant remise en pool
	if wrapper.Ptr != nil {
		Free(wrapper.Ptr) // Libérer le pointeur C
		wrapper.Ptr = nil
	}
	
	wrapper.IsUsed = false
	wrapper.UseCount++
	
	atomic.AddInt64(&globalPools.stats.PDUPuts, 1)
	globalPools.pduWrapperPool.Put(wrapper)
}

// nextPowerOfTwo retourne la prochaine puissance de 2 >= n
func nextPowerOfTwo(n int) int {
	if n <= 0 {
		return 1
	}
	
	// Algorithme bit manipulation pour puissance de 2
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n++
	
	return n
}

// GetPoolStats retourne les statistiques complètes des pools
func GetPoolStats() PoolStats {
	return PoolStats{
		MessageGets:    atomic.LoadInt64(&globalPools.stats.MessageGets),
		MessagePuts:    atomic.LoadInt64(&globalPools.stats.MessagePuts),
		IESliceGets:    atomic.LoadInt64(&globalPools.stats.IESliceGets),
		IESlicePuts:    atomic.LoadInt64(&globalPools.stats.IESlicePuts),
		ByteBufferGets: atomic.LoadInt64(&globalPools.stats.ByteBufferGets),
		ByteBufferPuts: atomic.LoadInt64(&globalPools.stats.ByteBufferPuts),
		PDUGets:        atomic.LoadInt64(&globalPools.stats.PDUGets),
		PDUPuts:        atomic.LoadInt64(&globalPools.stats.PDUPuts),
		MemorySaved:    atomic.LoadInt64(&globalPools.stats.MemorySaved),
		AllocationTime: atomic.LoadInt64(&globalPools.stats.AllocationTime),
	}
}

// GetPoolEfficiency calcule l'efficacité des pools (ratio Put/Get)
func GetPoolEfficiency() map[string]float64 {
	stats := GetPoolStats()
	
	efficiency := make(map[string]float64)
	
	if stats.MessageGets > 0 {
		efficiency["messages"] = float64(stats.MessagePuts) / float64(stats.MessageGets) * 100
	}
	
	if stats.IESliceGets > 0 {
		efficiency["ie_slices"] = float64(stats.IESlicePuts) / float64(stats.IESliceGets) * 100
	}
	
	if stats.ByteBufferGets > 0 {
		efficiency["byte_buffers"] = float64(stats.ByteBufferPuts) / float64(stats.ByteBufferGets) * 100
	}
	
	if stats.PDUGets > 0 {
		efficiency["pdu_wrappers"] = float64(stats.PDUPuts) / float64(stats.PDUGets) * 100
	}
	
	return efficiency
}

// ResetPoolStats remet à zéro toutes les statistiques
func ResetPoolStats() {
	atomic.StoreInt64(&globalPools.stats.MessageGets, 0)
	atomic.StoreInt64(&globalPools.stats.MessagePuts, 0)
	atomic.StoreInt64(&globalPools.stats.IESliceGets, 0)
	atomic.StoreInt64(&globalPools.stats.IESlicePuts, 0)
	atomic.StoreInt64(&globalPools.stats.ByteBufferGets, 0)
	atomic.StoreInt64(&globalPools.stats.ByteBufferPuts, 0)
	atomic.StoreInt64(&globalPools.stats.PDUGets, 0)
	atomic.StoreInt64(&globalPools.stats.PDUPuts, 0)
	atomic.StoreInt64(&globalPools.stats.MemorySaved, 0)
	atomic.StoreInt64(&globalPools.stats.AllocationTime, 0)
}

// WarmupPools pré-alloue des objets dans les pools pour des performances optimales
func WarmupPools(messageCount, ieSliceCount, bufferCount int) {
	log.Printf("INFO: Warming up memory pools...")
	
	// Pré-allouer des messages
	messages := make([]interface{}, messageCount)
	for i := 0; i < messageCount; i++ {
		messages[i] = GetMessage()
	}
	for _, msg := range messages {
		PutMessage(msg)
	}
	
	// Pré-allouer des slices d'IEs
	ieSlices := make([]([]*InformationElement), ieSliceCount)
	for i := 0; i < ieSliceCount; i++ {
		ieSlices[i] = GetIESlice()
	}
	for _, slice := range ieSlices {
		PutIESlice(slice)
	}
	
	// Pré-allouer des buffers
	buffers := make([][]byte, bufferCount)
	for i := 0; i < bufferCount; i++ {
		buffers[i] = GetByteBuffer(1024)
	}
	for _, buffer := range buffers {
		PutByteBuffer(buffer)
	}
	
	log.Printf("INFO: Memory pools warmed up - %d messages, %d IE slices, %d buffers", 
		messageCount, ieSliceCount, bufferCount)
}

// GetPoolReport génère un rapport détaillé des pools
func GetPoolReport() map[string]interface{} {
	stats := GetPoolStats()
	efficiency := GetPoolEfficiency()
	
	return map[string]interface{}{
		"statistics": map[string]interface{}{
			"message_gets":     stats.MessageGets,
			"message_puts":     stats.MessagePuts,
			"ie_slice_gets":    stats.IESliceGets,
			"ie_slice_puts":    stats.IESlicePuts,
			"byte_buffer_gets": stats.ByteBufferGets,
			"byte_buffer_puts": stats.ByteBufferPuts,
			"pdu_gets":         stats.PDUGets,
			"pdu_puts":         stats.PDUPuts,
		},
		"efficiency": efficiency,
		"memory_saved_mb": float64(stats.MemorySaved) / 1024 / 1024,
		"active_objects": map[string]int64{
			"messages":     stats.MessageGets - stats.MessagePuts,
			"ie_slices":    stats.IESliceGets - stats.IESlicePuts,
			"byte_buffers": stats.ByteBufferGets - stats.ByteBufferPuts,
			"pdu_wrappers": stats.PDUGets - stats.PDUPuts,
		},
	}
}
