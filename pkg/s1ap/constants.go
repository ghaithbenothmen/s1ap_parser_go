package s1ap

// InformationElement represents a parsed S1AP IE
type InformationElement struct {
	ID          int         `json:"id"`
	Name        string      `json:"name"`
	Criticality string      `json:"criticality"`
	Value       interface{} `json:"value"`
	RawValue    string      `json:"raw_value,omitempty"`
}

// S1AP Message Types
const (
	S1_SETUP_REQUEST = iota + 1
	S1_SETUP_RESPONSE
	INITIAL_UE_MESSAGE
	UPLINK_NAS_TRANSPORT
	DOWNLINK_NAS_TRANSPORT
	PAGING
	UE_CONTEXT_RELEASE_REQUEST
	UE_CONTEXT_RELEASE
	UE_CONTEXT_MODIFICATION
	E_RAB_SETUP
	E_RAB_MODIFY
	E_RAB_RELEASE
	E_RAB_RELEASE_INDICATION
	E_RAB_MODIFICATION_INDICATION
	INITIAL_CONTEXT_SETUP
	HANDOVER_PREPARATION
	HANDOVER_RESOURCE_ALLOCATION
	HANDOVER_NOTIFICATION
	HANDOVER_CANCEL
	HANDOVER_SUCCESS
	PATH_SWITCH_REQUEST
	RESET
	ERROR_INDICATION
	NAS_NON_DELIVERY_INDICATION
	ENB_CONFIGURATION_UPDATE
	MME_CONFIGURATION_UPDATE
	LOCATION_REPORTING_CONTROL
	LOCATION_REPORTING_FAILURE_INDICATION
	LOCATION_REPORT
	OVERLOAD_START
	OVERLOAD_STOP
	WRITE_REPLACE_WARNING
	KILL
	ENB_DIRECT_INFORMATION_TRANSFER
	MME_DIRECT_INFORMATION_TRANSFER
	ENB_CONFIGURATION_TRANSFER
	MME_CONFIGURATION_TRANSFER
	PRIVATE_MESSAGE
	CELL_TRAFFIC_TRACE
	TRACE_START
	TRACE_FAILURE_INDICATION
	DEACTIVATE_TRACE
	UE_CAPABILITY_INFO_INDICATION
	ENB_STATUS_TRANSFER
	MME_STATUS_TRANSFER
	DOWNLINK_S1CDMA2000_TUNNELLING
	UPLINK_S1CDMA2000_TUNNELLING
	DOWNLINK_UE_ASSOCIATED_LPPA_TRANSPORT
	UPLINK_UE_ASSOCIATED_LPPA_TRANSPORT
	DOWNLINK_NON_UE_ASSOCIATED_LPPA_TRANSPORT
	UPLINK_NON_UE_ASSOCIATED_LPPA_TRANSPORT
	UE_RADIO_CAPABILITY_MATCH
	PWS_RESTART_INDICATION
	PWS_FAILURE_INDICATION
	REROUTE_NAS_REQUEST
	UE_CONTEXT_MODIFICATION_INDICATION
	CONNECTION_ESTABLISHMENT_INDICATION
	UE_CONTEXT_SUSPEND
	UE_CONTEXT_RESUME
	NAS_DELIVERY_INDICATION
	RETRIEVE_UE_INFORMATION
	UE_INFORMATION_TRANSFER
	ENB_CP_RELOCATION_INDICATION
	MME_CP_RELOCATION_INDICATION
	SECONDARY_RAT_DATA_USAGE_REPORT
	UE_RADIO_CAPABILITY_ID_MAPPING
	ENB_EARLY_STATUS_TRANSFER
	MME_EARLY_STATUS_TRANSFER
)

// S1AP Procedure Codes (based on the provided mapping)
var S1AP_PROCEDURE_CODES = map[int]string{
	0:  "HandoverPreparation",
	1:  "HandoverResourceAllocation", 
	2:  "HandoverNotification",
	3:  "PathSwitchRequest",
	4:  "HandoverCancel",
	5:  "E-RABSetup",
	6:  "E-RABModify",
	7:  "E-RABRelease",
	8:  "E-RABReleaseIndication",
	9:  "InitialContextSetup",
	10: "Paging",
	11: "downlinkNASTransport",
	12: "initialUEMessage",
	13: "uplinkNASTransport",
	14: "Reset",
	15: "ErrorIndication",
	16: "NASNonDeliveryIndication",
	17: "S1Setup",
	18: "UEContextReleaseRequest",
	19: "DownlinkS1cdma2000tunnelling",
	20: "UplinkS1cdma2000tunnelling",
	21: "UEContextModification",
	22: "UECapabilityInfoIndication",
	23: "UEContextRelease",
	24: "eNBStatusTransfer",
	25: "MMEStatusTransfer",
	26: "DeactivateTrace",
	27: "TraceStart",
	28: "TraceFailureIndication",
	29: "ENBConfigurationUpdate",
	30: "MMEConfigurationUpdate",
	31: "LocationReportingControl",
	32: "LocationReportingFailureIndication",
	33: "LocationReport",
	34: "OverloadStart",
	35: "OverloadStop",
	36: "WriteReplaceWarning",
	37: "eNBDirectInformationTransfer",
	38: "MMEDirectInformationTransfer",
	39: "PrivateMessage",
	40: "eNBConfigurationTransfer",
	41: "MMEConfigurationTransfer",
	42: "CellTrafficTrace",
	43: "Kill",
	44: "downlinkUEAssociatedLPPaTransport",
	45: "uplinkUEAssociatedLPPaTransport",
	46: "downlinkNonUEAssociatedLPPaTransport",
	47: "uplinkNonUEAssociatedLPPaTransport",
	48: "UERadioCapabilityMatch",
	49: "PWSRestartIndication",
	50: "E-RABModificationIndication",
	51: "PWSFailureIndication",
	52: "RerouteNASRequest",
	53: "UEContextModificationIndication",
	54: "ConnectionEstablishmentIndication",
	55: "UEContextSuspend",
	56: "UEContextResume",
	57: "NASDeliveryIndication",
	58: "RetrieveUEInformation",
	59: "UEInformationTransfer",
	60: "eNBCPRelocationIndication",
	61: "MMECPRelocationIndication",
	62: "SecondaryRATDataUsageReport",
	63: "UERadioCapabilityIDMapping",
	64: "HandoverSuccess",
	65: "eNBEarlyStatusTransfer",
	66: "MMEEarlyStatusTransfer",
}

// Function to get procedure name by code
func GetProcedureName(code int) string {
	if name, exists := S1AP_PROCEDURE_CODES[code]; exists {
		return name
	}
	return "Unknown"
}

// Function to extract real procedure code from ASN.1 structure
func ExtractProcedureCode(data []byte) int {
	// S1AP structure: [PDU_type, procedure_code, ...]
	// For initiatingMessage (0x00), procedure code is at byte 1
	if len(data) >= 2 {
		return int(data[1])
	}
	return -1
}

const (
	NAS_EPS_AUTH_RESPONSE = iota + 1
	NAS_EPS_SECURITY_MODE_COMPLETE
)
