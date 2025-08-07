package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// AsyncSessionHandler gère les sessions de manière asynchrone pour optimiser les performances
type AsyncSessionHandler struct {
	analyzer      *Analyzer
	sessionQueue  chan SessionTask
	workerCount   int
	workers       sync.WaitGroup
	done          chan struct{}
	
	// Statistiques de performance
	totalProcessed int64
	totalErrors    int64
	totalQueued    int64
	processingTime int64 // en nanosecondes
	mutex          sync.RWMutex
}

// SessionTask représente une tâche de session à traiter de manière asynchrone
type SessionTask struct {
	TaskType     string             // "complete", "update", "stmsi", "create"
	SessionID    string
	MmeID        int64
	EnbID        int64
	Message      *S1APMessage
	Timestamp    time.Time
	RetryCount   int
	Priority     TaskPriority       // HIGH, MEDIUM, LOW
	Context      context.Context
}

// TaskPriority définit la priorité des tâches
type TaskPriority int

const (
	LOW_PRIORITY TaskPriority = iota
	MEDIUM_PRIORITY
	HIGH_PRIORITY
)

// NewAsyncSessionHandler crée un nouveau handler asynchrone
func NewAsyncSessionHandler(analyzer *Analyzer, workerCount int, queueSize int) *AsyncSessionHandler {
	handler := &AsyncSessionHandler{
		analyzer:     analyzer,
		sessionQueue: make(chan SessionTask, queueSize),
		workerCount:  workerCount,
		done:        make(chan struct{}),
	}
	
	// Démarrer les workers
	for i := 0; i < workerCount; i++ {
		handler.workers.Add(1)
		go handler.sessionWorker(i)
	}
	
	// Démarrer le monitoring des performances
	go handler.performanceMonitor()
	
	log.Printf("INFO: AsyncSessionHandler started with %d workers (queue size: %d)", 
		workerCount, queueSize)
	
	return handler
}

// sessionWorker traite les tâches de session en arrière-plan
func (h *AsyncSessionHandler) sessionWorker(workerID int) {
	defer h.workers.Done()
	
	log.Printf("INFO: Session worker %d started", workerID)
	
	for {
		select {
		case task := <-h.sessionQueue:
			start := time.Now()
			
			if err := h.processSessionTask(task, workerID); err != nil {
				atomic.AddInt64(&h.totalErrors, 1)
				
				// Logique de retry pour les échecs
				if task.RetryCount < 3 {
					task.RetryCount++
					// Délai exponentiel pour les retries
					retryDelay := time.Duration(task.RetryCount*task.RetryCount) * 100 * time.Millisecond
					time.AfterFunc(retryDelay, func() {
						select {
						case h.sessionQueue <- task:
							log.Printf("DEBUG: Worker %d retrying task (attempt %d)", workerID, task.RetryCount)
						default:
							log.Printf("WARN: Worker %d failed to retry task - queue full", workerID)
						}
					})
				} else {
					log.Printf("ERROR: Worker %d failed task after 3 retries: %v", workerID, err)
				}
			} else {
				atomic.AddInt64(&h.totalProcessed, 1)
			}
			
			// Enregistrer le temps de traitement
			duration := time.Since(start).Nanoseconds()
			atomic.AddInt64(&h.processingTime, duration)
			
		case <-h.done:
			log.Printf("INFO: Session worker %d shutting down", workerID)
			return
		}
	}
}

// processSessionTask traite une tâche spécifique
func (h *AsyncSessionHandler) processSessionTask(task SessionTask, workerID int) error {
	start := time.Now()
	
	// Vérifier le timeout du contexte si fourni
	if task.Context != nil {
		select {
		case <-task.Context.Done():
			return fmt.Errorf("task cancelled: %v", task.Context.Err())
		default:
		}
	}
	
	switch task.TaskType {
	case "complete":
		err := h.analyzer.handleCompletedSession(task.MmeID, task.EnbID)
		if h.analyzer.config.Debug && time.Since(start) > 200*time.Millisecond {
			log.Printf("DEBUG: Worker %d slow session completion: %v (MME: %d, eNB: %d)", 
				workerID, time.Since(start), task.MmeID, task.EnbID)
		}
		return err
		
	case "update":
		err := h.analyzer.addMessageToSession(task.Message, task.MmeID, task.EnbID)
		if h.analyzer.config.Debug && time.Since(start) > 100*time.Millisecond {
			log.Printf("DEBUG: Worker %d slow session update: %v (Proc: %s)", 
				workerID, time.Since(start), task.Message.ProcedureName)
		}
		return err
		
	case "stmsi":
		h.analyzer.extractAndStoreSTMSI(task.Message, task.SessionID)
		return nil
		
	case "create":
		err := h.analyzer.addMessageToSession(task.Message, task.MmeID, task.EnbID)
		if h.analyzer.config.Debug {
			log.Printf("DEBUG: Worker %d created new session in %v (SessionID: %s)", 
				workerID, time.Since(start), task.SessionID)
		}
		return err
		
	default:
		return fmt.Errorf("unknown task type: %s", task.TaskType)
	}
}

// SubmitSessionCompletion soumet une tâche de finalisation de session
func (h *AsyncSessionHandler) SubmitSessionCompletion(mmeID, enbID int64) error {
	task := SessionTask{
		TaskType:  "complete",
		MmeID:     mmeID,
		EnbID:     enbID,
		Timestamp: time.Now(),
		Priority:  HIGH_PRIORITY, // Les finalisations sont prioritaires
		Context:   context.WithValue(context.Background(), "task", "completion"),
	}
	
	return h.submitTask(task)
}

// SubmitSessionUpdate soumet une tâche de mise à jour de session
func (h *AsyncSessionHandler) SubmitSessionUpdate(msg *S1APMessage, mmeID, enbID int64) error {
	task := SessionTask{
		TaskType:  "update",
		Message:   msg,
		MmeID:     mmeID,
		EnbID:     enbID,
		Timestamp: time.Now(),
		Priority:  MEDIUM_PRIORITY,
		Context:   context.WithValue(context.Background(), "task", "update"),
	}
	
	return h.submitTask(task)
}

// SubmitSTMSITask soumet une tâche d'extraction S-TMSI
func (h *AsyncSessionHandler) SubmitSTMSITask(msg *S1APMessage, sessionID string) error {
	task := SessionTask{
		TaskType:  "stmsi",
		Message:   msg,
		SessionID: sessionID,
		Timestamp: time.Now(),
		Priority:  LOW_PRIORITY,
		Context:   context.WithValue(context.Background(), "task", "stmsi"),
	}
	
	return h.submitTask(task)
}

// submitTask soumet une tâche en gérant la saturation de la queue
func (h *AsyncSessionHandler) submitTask(task SessionTask) error {
	atomic.AddInt64(&h.totalQueued, 1)
	
	select {
	case h.sessionQueue <- task:
		return nil
	case <-time.After(50 * time.Millisecond): // Timeout pour éviter les blocages
		return fmt.Errorf("session queue saturated - dropping %s task", task.TaskType)
	}
}

// GetStats retourne les statistiques du handler
func (h *AsyncSessionHandler) GetStats() (processed, errors, queued int64, avgProcessingTime time.Duration, queueLen int) {
	processed = atomic.LoadInt64(&h.totalProcessed)
	errors = atomic.LoadInt64(&h.totalErrors)
	queued = atomic.LoadInt64(&h.totalQueued)
	
	processingTimeNs := atomic.LoadInt64(&h.processingTime)
	if processed > 0 {
		avgProcessingTime = time.Duration(processingTimeNs / processed)
	}
	
	queueLen = len(h.sessionQueue)
	
	return
}

// performanceMonitor surveille les performances en arrière-plan
func (h *AsyncSessionHandler) performanceMonitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	var lastProcessed int64
	var lastErrors int64
	
	for {
		select {
		case <-ticker.C:
			processed, errors, _, avgTime, queueLen := h.GetStats()
			
			// Calculer le débit
			throughput := processed - lastProcessed
			newErrors := errors - lastErrors
			
			log.Printf("INFO: AsyncSessionHandler stats - Throughput: %d/30s, Queue: %d/%d, Avg time: %v, Errors: %d", 
				throughput, queueLen, cap(h.sessionQueue), avgTime, newErrors)
			
			// Alertes de performance
			if queueLen > cap(h.sessionQueue)*8/10 { // 80% plein
				log.Printf("WARN: Session queue is %d%% full (%d/%d)", 
					queueLen*100/cap(h.sessionQueue), queueLen, cap(h.sessionQueue))
			}
			
			if avgTime > 500*time.Millisecond {
				log.Printf("WARN: High average processing time: %v", avgTime)
			}
			
			lastProcessed = processed
			lastErrors = errors
			
		case <-h.done:
			return
		}
	}
}

// GetQueueStatus retourne le statut détaillé de la queue
func (h *AsyncSessionHandler) GetQueueStatus() map[string]interface{} {
	processed, errors, queued, avgTime, queueLen := h.GetStats()
	
	return map[string]interface{}{
		"total_processed":      processed,
		"total_errors":         errors,
		"total_queued":         queued,
		"avg_processing_time":  avgTime,
		"current_queue_length": queueLen,
		"queue_capacity":       cap(h.sessionQueue),
		"queue_utilization":    float64(queueLen) / float64(cap(h.sessionQueue)) * 100,
		"worker_count":         h.workerCount,
		"error_rate":           float64(errors) / float64(queued) * 100,
	}
}

// Close arrête proprement le handler
func (h *AsyncSessionHandler) Close() {
	log.Printf("INFO: Shutting down AsyncSessionHandler...")
	
	// Arrêter l'acceptation de nouvelles tâches
	close(h.done)
	
	// Attendre que tous les workers finissent leurs tâches courantes
	log.Printf("INFO: Waiting for %d session workers to finish...", h.workerCount)
	h.workers.Wait()
	
	// Traiter les tâches restantes de manière synchrone
	remaining := len(h.sessionQueue)
	if remaining > 0 {
		log.Printf("INFO: Processing %d remaining tasks synchronously...", remaining)
		for len(h.sessionQueue) > 0 {
			task := <-h.sessionQueue
			if err := h.processSessionTask(task, -1); err != nil {
				log.Printf("ERROR: Failed to process remaining task: %v", err)
			}
		}
	}
	
	// Fermer la queue
	close(h.sessionQueue)
	
	// Afficher les statistiques finales
	processed, errors, queued, avgTime, _ := h.GetStats()
	log.Printf("INFO: AsyncSessionHandler shutdown complete - Processed: %d, Errors: %d, Queued: %d, Avg time: %v", 
		processed, errors, queued, avgTime)
}

// Shutdown est un alias pour Close pour compatibilité avec cleanup.go
func (h *AsyncSessionHandler) Shutdown() {
	h.Close()
}
