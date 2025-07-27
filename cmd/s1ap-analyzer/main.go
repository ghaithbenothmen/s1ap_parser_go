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
	PcapFile     string
	Format       OutputFormat
	Limit        int
	StatsOnly    bool
	Debug        bool
	ShowHelp     bool
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
}

// NewAnalyzer creates a new analyzer instance
func NewAnalyzer(config *Config) *Analyzer {
	return &Analyzer{
		config: config,
		stats: &Statistics{
			ProcedureStats: make(map[string]int),
			StartTime:      time.Now(),
		},
	}
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

	messages, err := a.analyzePackets(handle)
	if err != nil {
		return fmt.Errorf("packet analysis failed: %w", err)
	}

	return a.outputResults(messages)
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
