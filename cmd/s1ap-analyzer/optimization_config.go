package main

import (
	"context"
	"log"
	"sync"
	"time"
)

// OptimizationStats contient les statistiques de performance des optimisations
type OptimizationStats struct {
	CacheHitRatio           float64   // Pourcentage de cache hits
	TotalPacketsProcessed   int       // Nombre total de paquets traités
	SpeedupRatio           float64   // Ratio d'accélération vs version non-optimisée
	AverageProcessingTime  time.Duration // Temps moyen de traitement par paquet
	LastUpdated            time.Time // Dernière mise à jour des stats
}

// Performance monitoring global
var (
	perfStats = OptimizationStats{
		LastUpdated: time.Now(),
	}
	perfMutex sync.RWMutex
)

// GetOptimizationStats retourne les statistiques actuelles d'optimisation
func GetOptimizationStats() OptimizationStats {
	perfMutex.RLock()
	defer perfMutex.RUnlock()
	return perfStats
}

// UpdateOptimizationStats met à jour les statistiques de performance
func UpdateOptimizationStats(packetsProcessed int, averageTime time.Duration, cacheHitRatio float64) {
	perfMutex.Lock()
	defer perfMutex.Unlock()
	
	perfStats.TotalPacketsProcessed = packetsProcessed
	perfStats.AverageProcessingTime = averageTime
	perfStats.CacheHitRatio = cacheHitRatio
	perfStats.LastUpdated = time.Now()
}

// MonitorPerformance surveille en continu les performances du système
func MonitorPerformance(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := GetOptimizationStats()
			if stats.TotalPacketsProcessed > 0 {
				log.Printf("📈 Performance stats - Packets: %d, Avg time: %v, Cache hit: %.1f%%", 
					stats.TotalPacketsProcessed, stats.AverageProcessingTime, stats.CacheHitRatio)
			}
		}
	}
}
