package main

import (
	"log"
	"time"
	"context"

	"github.com/coreswitch/coreswitch/pkg/s1ap"
)

// Shutdown gracefully shuts down all optimization systems
func (a *Analyzer) Shutdown() {
	log.Printf("INFO: Starting graceful shutdown of analyzer...")

	// 1. Arrêter l'async handler pour éviter de nouvelles tâches
	if a.asyncHandler != nil {
		log.Printf("INFO: Shutting down async session handler...")
		a.asyncHandler.Shutdown()
		a.asyncHandler = nil
		log.Printf("INFO: Async session handler shutdown complete")
	}

	// 2. Forcer le flush du batch writer et l'arrêter
	if a.batchWriter != nil {
		log.Printf("INFO: Shutting down batch MongoDB writer...")
		a.batchWriter.Shutdown()
		
		// Afficher les statistiques finales du batch writer
		totalOps, totalBatches, totalErrors, avgBatchSize, currentBuffer := a.batchWriter.GetStats()
		log.Printf("INFO: Batch writer stats - Operations: %d, Batches: %d, Errors: %d, Avg size: %.1f, Buffer: %d", 
			totalOps, totalBatches, totalErrors, avgBatchSize, currentBuffer)
		
		a.batchWriter = nil
		log.Printf("INFO: Batch MongoDB writer shutdown complete")
	}

	// 3. Attendre que toutes les sessions actives se terminent
	log.Printf("INFO: Waiting for active session handlers to complete...")
	a.activeSessionHandlers.Wait()
	log.Printf("INFO: All session handlers completed")

	// 4. Cleanup des memory pools
	log.Printf("INFO: Cleaning up memory pools...")
	poolStats := s1ap.GetPoolStats()
	totalGets := poolStats.MessageGets + poolStats.IESliceGets + poolStats.ByteBufferGets + poolStats.PDUGets
	totalPuts := poolStats.MessagePuts + poolStats.IESlicePuts + poolStats.ByteBufferPuts + poolStats.PDUPuts
	log.Printf("INFO: Memory pool stats - Total gets: %d, Total puts: %d, Memory saved: %d bytes", 
		totalGets, totalPuts, poolStats.MemorySaved)
	log.Printf("INFO: Memory pools cleanup complete")

	// 5. Fermer la connexion MongoDB si ouverte
	if a.mongoClient != nil {
		log.Printf("INFO: Closing MongoDB connection...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if err := a.mongoClient.Disconnect(ctx); err != nil {
			log.Printf("WARN: Error closing MongoDB connection: %v", err)
		} else {
			log.Printf("INFO: MongoDB connection closed")
		}
		a.mongoClient = nil
		a.mongoCollection = nil
	}

	// 6. Afficher les statistiques finales
	a.printFinalStats()

	log.Printf("INFO: Analyzer shutdown complete")
}

// printFinalStats affiche les statistiques finales du traitement
func (a *Analyzer) printFinalStats() {
	log.Printf("📊 Final Processing Statistics:")
	log.Printf("   Total frames: %d", a.stats.TotalFrames)
	log.Printf("   S1AP frames: %d", a.stats.S1APFrames)
	log.Printf("   Successful decodes: %d", a.stats.SuccessfulDecodes)
	log.Printf("   Failed decodes: %d", a.stats.FailedDecodes)
	log.Printf("   Completed sessions: %d", a.stats.CompletedSessions)
	
	if a.stats.ProcessingTime > 0 {
		packetsPerSecond := float64(a.stats.TotalFrames) / a.stats.ProcessingTime.Seconds()
		log.Printf("   Processing rate: %.1f packets/second", packetsPerSecond)
		
		if a.stats.SuccessfulDecodes > 0 {
			messagesPerSecond := float64(a.stats.SuccessfulDecodes) / a.stats.ProcessingTime.Seconds()
			log.Printf("   Message processing rate: %.1f messages/second", messagesPerSecond)
		}
	}
	
	if a.stats.SuccessfulDecodes > 0 {
		successRate := float64(a.stats.SuccessfulDecodes) / float64(a.stats.S1APFrames) * 100
		log.Printf("   Success rate: %.1f%%", successRate)
	}
}

// Emergency shutdown - for panic recovery
func (a *Analyzer) EmergencyShutdown() {
	log.Printf("WARN: Emergency shutdown initiated!")
	
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: Panic during emergency shutdown: %v", r)
		}
	}()
	
	// Force shutdown des composants critiques seulement
	if a.batchWriter != nil {
		a.batchWriter.Shutdown()
	}
	
	if a.asyncHandler != nil {
		a.asyncHandler.Shutdown()
	}
	
	if a.mongoClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		a.mongoClient.Disconnect(ctx)
	}
	
	log.Printf("WARN: Emergency shutdown complete")
}
