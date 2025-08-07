package main

import (
	"context"
	"log"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

// BatchMongoWriter manages batch MongoDB writes for performance optimization
type BatchMongoWriter struct {
	collection    *mongo.Collection
	batchSize     int
	flushInterval time.Duration

	operations []mongo.WriteModel
	mutex      sync.Mutex
	ticker     *time.Ticker
	done       chan struct{}

	totalOps     int64
	totalBatches int64
	totalErrors  int64
	avgBatchSize float64
	statsMutex   sync.RWMutex
}

// NewBatchMongoWriter creates a new batch writer
func NewBatchMongoWriter(collection *mongo.Collection, batchSize int, flushInterval time.Duration) *BatchMongoWriter {
	writer := &BatchMongoWriter{
		collection:    collection,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		operations:    make([]mongo.WriteModel, 0, batchSize),
		done:          make(chan struct{}),
	}

	writer.ticker = time.NewTicker(flushInterval)
	go writer.periodicFlush()

	log.Printf("INFO: BatchMongoWriter initialized - batch size: %d, interval: %v", batchSize, flushInterval)
	return writer
}

// AddUpdateOperation adds an update operation to the batch
func (b *BatchMongoWriter) AddUpdateOperation(filter, update interface{}, upsert bool) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	updateModel := mongo.NewUpdateOneModel()
	updateModel.SetFilter(filter)
	updateModel.SetUpdate(update)
	updateModel.SetUpsert(upsert)

	b.operations = append(b.operations, updateModel)

	b.statsMutex.Lock()
	b.totalOps++
	b.statsMutex.Unlock()

	if len(b.operations) >= b.batchSize {
		return b.flushNow()
	}
	return nil
}

// flushNow executes all pending operations
func (b *BatchMongoWriter) flushNow() error {
	if len(b.operations) == 0 {
		return nil
	}

	opsToExecute := make([]mongo.WriteModel, len(b.operations))
	copy(opsToExecute, b.operations)
	b.operations = b.operations[:0]

	b.mutex.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := b.collection.BulkWrite(ctx, opsToExecute)

	b.mutex.Lock()

	b.statsMutex.Lock()
	b.totalBatches++
	if err != nil {
		b.totalErrors++
	} else {
		b.avgBatchSize = float64(b.totalOps) / float64(b.totalBatches)
	}
	b.statsMutex.Unlock()

	return err
}

// periodicFlush performs periodic flush in the background
func (b *BatchMongoWriter) periodicFlush() {
	for {
		select {
		case <-b.ticker.C:
			b.mutex.Lock()
			if len(b.operations) > 0 {
				b.flushNow()
			}
			b.mutex.Unlock()
		case <-b.done:
			return
		}
	}
}

// GetStats returns batch writer statistics
func (b *BatchMongoWriter) GetStats() (totalOps, totalBatches, totalErrors int64, avgBatchSize float64, currentBufferSize int) {
	b.statsMutex.RLock()
	defer b.statsMutex.RUnlock()

	b.mutex.Lock()
	currentBufferSize = len(b.operations)
	b.mutex.Unlock()

	return b.totalOps, b.totalBatches, b.totalErrors, b.avgBatchSize, currentBufferSize
}

// Shutdown stops the writer and flushes remaining operations
func (b *BatchMongoWriter) Shutdown() {
	log.Printf("INFO: Shutting down BatchMongoWriter...")

	b.ticker.Stop()
	close(b.done)

	b.mutex.Lock()
	if len(b.operations) > 0 {
		log.Printf("INFO: Final flush of %d remaining operations...", len(b.operations))
		b.flushNow()
	}
	b.mutex.Unlock()

	totalOps, totalBatches, totalErrors, avgBatchSize, _ := b.GetStats()
	log.Printf("INFO: BatchMongoWriter shutdown complete - Ops: %d, Batches: %d, Errors: %d, Avg size: %.1f",
		totalOps, totalBatches, totalErrors, avgBatchSize)
}
