package s1ap

// #cgo CFLAGS: -I./asn1
// #cgo LDFLAGS: -L/usr/local/lib -ls1ap -lasn1c
// #include "S1AP-PDU.h"
// #include "InitiatingMessage.h"
// #include "ProtocolIE-Field.h"
import "C"
import (
	"fmt"
	"log"
	"reflect"
	"unsafe"
)

var S1AP_PDU2StringMap = map[C.S1AP_PDU_PR]string{
	C.S1AP_PDU_PR_NOTHING:             "Nothing",
	C.S1AP_PDU_PR_initiatingMessage:   "InitiatingMessage",
	C.S1AP_PDU_PR_successfulOutcome:   "SuccessfulOutcome",
	C.S1AP_PDU_PR_unsuccessfulOutcome: "UnsuccessfulOutcome",
}

func S1AP_PDU2String(k C.S1AP_PDU_PR) string {
	if v, ok := S1AP_PDU2StringMap[k]; ok {
		return v
	} else {
		return "Unknown"
	}
}

var S1AP_Initiating2StringMap = map[C.InitiatingMessage__value_PR]string{
	C.InitiatingMessage__value_PR_NOTHING:                              "NOTHING",
	C.InitiatingMessage__value_PR_HandoverRequired:                     "HandoverRequired",
	C.InitiatingMessage__value_PR_HandoverRequest:                      "HandoverRequest",
	C.InitiatingMessage__value_PR_PathSwitchRequest:                    "PathSwitchRequest",
	C.InitiatingMessage__value_PR_E_RABSetupRequest:                    "E_RABSetupRequest",
	C.InitiatingMessage__value_PR_E_RABModifyRequest:                   "E_RABModifyRequest",
	C.InitiatingMessage__value_PR_E_RABReleaseCommand:                  "E_RABReleaseCommand",
	C.InitiatingMessage__value_PR_InitialContextSetupRequest:           "InitialContextSetupRequest",
	C.InitiatingMessage__value_PR_HandoverCancel:                       "HandoverCancel",
	C.InitiatingMessage__value_PR_KillRequest:                          "KillRequest",
	C.InitiatingMessage__value_PR_Reset:                                "Reset",
	C.InitiatingMessage__value_PR_S1SetupRequest:                       "S1SetupRequest",
	C.InitiatingMessage__value_PR_UEContextModificationRequest:         "UEContextModificationRequest",
	C.InitiatingMessage__value_PR_UEContextReleaseCommand:              "UEContextReleaseCommand",
	C.InitiatingMessage__value_PR_ENBConfigurationUpdate:               "ENBConfigurationUpdate",
	C.InitiatingMessage__value_PR_MMEConfigurationUpdate:               "MMEConfigurationUpdate",
	C.InitiatingMessage__value_PR_WriteReplaceWarningRequest:           "WriteReplaceWarningRequest",
	C.InitiatingMessage__value_PR_UERadioCapabilityMatchRequest:        "UERadioCapabilityMatchRequest",
	C.InitiatingMessage__value_PR_E_RABModificationIndication:          "E_RABModificationIndication",
	C.InitiatingMessage__value_PR_UEContextModificationIndication:      "UEContextModificationIndication",
	C.InitiatingMessage__value_PR_UEContextSuspendRequest:              "UEContextSuspendRequest",
	C.InitiatingMessage__value_PR_UEContextResumeRequest:               "UEContextResumeRequest",
	C.InitiatingMessage__value_PR_HandoverNotify:                       "HandoverNotify",
	C.InitiatingMessage__value_PR_E_RABReleaseIndication:               "E_RABReleaseIndication",
	C.InitiatingMessage__value_PR_Paging:                               "Paging",
	C.InitiatingMessage__value_PR_DownlinkNASTransport:                 "DownlinkNASTransport",
	C.InitiatingMessage__value_PR_InitialUEMessage:                     "InitialUEMessage",
	C.InitiatingMessage__value_PR_UplinkNASTransport:                   "UplinkNASTransport",
	C.InitiatingMessage__value_PR_ErrorIndication:                      "ErrorIndication",
	C.InitiatingMessage__value_PR_NASNonDeliveryIndication:             "NASNonDeliveryIndication",
	C.InitiatingMessage__value_PR_UEContextReleaseRequest:              "UEContextReleaseRequest",
	C.InitiatingMessage__value_PR_DownlinkS1cdma2000tunnelling:         "DownlinkS1cdma2000tunnelling",
	C.InitiatingMessage__value_PR_UplinkS1cdma2000tunnelling:           "UplinkS1cdma2000tunnelling",
	C.InitiatingMessage__value_PR_UECapabilityInfoIndication:           "UECapabilityInfoIndication",
	C.InitiatingMessage__value_PR_ENBStatusTransfer:                    "ENBStatusTransfer",
	C.InitiatingMessage__value_PR_MMEStatusTransfer:                    "MMEStatusTransfer",
	C.InitiatingMessage__value_PR_DeactivateTrace:                      "DeactivateTrace",
	C.InitiatingMessage__value_PR_TraceStart:                           "TraceStart",
	C.InitiatingMessage__value_PR_TraceFailureIndication:               "TraceFailureIndication",
	C.InitiatingMessage__value_PR_CellTrafficTrace:                     "CellTrafficTrace",
	C.InitiatingMessage__value_PR_LocationReportingControl:             "LocationReportingControl",
	C.InitiatingMessage__value_PR_LocationReportingFailureIndication:   "LocationReportingFailureIndication",
	C.InitiatingMessage__value_PR_LocationReport:                       "LocationReport",
	C.InitiatingMessage__value_PR_OverloadStart:                        "OverloadStart",
	C.InitiatingMessage__value_PR_OverloadStop:                         "OverloadStop",
	C.InitiatingMessage__value_PR_ENBDirectInformationTransfer:         "ENBDirectInformationTransfer",
	C.InitiatingMessage__value_PR_MMEDirectInformationTransfer:         "MMEDirectInformationTransfer",
	C.InitiatingMessage__value_PR_ENBConfigurationTransfer:             "ENBConfigurationTransfer",
	C.InitiatingMessage__value_PR_MMEConfigurationTransfer:             "MMEConfigurationTransfer",
	C.InitiatingMessage__value_PR_PrivateMessage:                       "PrivateMessage",
	C.InitiatingMessage__value_PR_DownlinkUEAssociatedLPPaTransport:    "DownlinkUEAssociatedLPPaTransport",
	C.InitiatingMessage__value_PR_UplinkUEAssociatedLPPaTransport:      "UplinkUEAssociatedLPPaTransport",
	C.InitiatingMessage__value_PR_DownlinkNonUEAssociatedLPPaTransport: "DownlinkNonUEAssociatedLPPaTransport",
	C.InitiatingMessage__value_PR_UplinkNonUEAssociatedLPPaTransport:   "UplinkNonUEAssociatedLPPaTransport",
	C.InitiatingMessage__value_PR_PWSRestartIndication:                 "PWSRestartIndication",
	C.InitiatingMessage__value_PR_RerouteNASRequest:                    "RerouteNASRequest",
	C.InitiatingMessage__value_PR_PWSFailureIndication:                 "PWSFailureIndication",
	C.InitiatingMessage__value_PR_ConnectionEstablishmentIndication:    "ConnectionEstablishmentIndication",
	C.InitiatingMessage__value_PR_NASDeliveryIndication:                "NASDeliveryIndication",
	C.InitiatingMessage__value_PR_RetrieveUEInformation:                "RetrieveUEInformation",
	C.InitiatingMessage__value_PR_UEInformationTransfer:                "UEInformationTransfer",
	C.InitiatingMessage__value_PR_ENBCPRelocationIndication:            "ENBCPRelocationIndication",
	C.InitiatingMessage__value_PR_MMECPRelocationIndication:            "MMECPRelocationIndication",
}

func S1AP_Initiating2String(k C.InitiatingMessage__value_PR) string {
	if v, ok := S1AP_Initiating2StringMap[k]; ok {
		return v
	} else {
		return "Unknown"
	}
}

func InitialUEMessageHandle(packet unsafe.Pointer) (int32, error) {
	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.InitialUEMessage_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.UplinkNASTransport_IEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	var enb_ie_s1ap_id int32

	for _, ie := range ies {
		switch ie.id {
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_ie_s1ap_id_c := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			enb_ie_s1ap_id = (int32)(*enb_ie_s1ap_id_c)
		case C.ProtocolIE_ID_id_NAS_PDU:
			//NAS_PDU = &ie->value.choice.NAS_PDU;
		case C.ProtocolIE_ID_id_TAI:
			//TAI = &ie->value.choice.TAI;
		case C.ProtocolIE_ID_id_EUTRAN_CGI:
			//EUTRAN_CGI = &ie->value.choice.EUTRAN_CGI;
		case C.ProtocolIE_ID_id_S_TMSI:
			//S_TMSI = &ie->value.choice.S_TMSI;
		default:
		}
	}
	return enb_ie_s1ap_id, nil
}

func NAS_PDU_Handle() {
}

// Enhanced handler for Paging messages
func PagingHandle(packet unsafe.Pointer) (string, error) {
	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.Paging_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.PagingIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	var pagingInfo string = "Paging Details: "

	for _, ie := range ies {
		switch ie.id {
		case C.ProtocolIE_ID_id_UEIdentityIndexValue:
			pagingInfo += "UEIdentityIndexValue found; "
		case C.ProtocolIE_ID_id_UEPagingID:
			pagingInfo += "UEPagingID found; "
		case C.ProtocolIE_ID_id_CNDomain:
			pagingInfo += "CNDomain found; "
		case C.ProtocolIE_ID_id_TAIList:
			pagingInfo += "TAIList found; "
		default:
			pagingInfo += fmt.Sprintf("Unknown IE %d; ", ie.id)
		}
	}
	return pagingInfo, nil
}

// Handler for UEContextReleaseRequest
func UEContextReleaseRequestHandle(packet unsafe.Pointer) (int32, string, error) {
	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.UEContextReleaseRequest_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.UEContextReleaseRequest_IEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	var enb_ie_s1ap_id int32
	var cause string

	for _, ie := range ies {
		switch ie.id {
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_ie_s1ap_id_c := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			enb_ie_s1ap_id = (int32)(*enb_ie_s1ap_id_c)
		case C.ProtocolIE_ID_id_Cause:
			cause = "Cause IE found"
		default:
		}
	}
	return enb_ie_s1ap_id, cause, nil
}

// Handler for E-RABSetupRequest
func ERABSetupRequestHandle(packet unsafe.Pointer) (int32, int32, error) {
	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.E_RABSetupRequest_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.E_RABSetupRequestIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	var mme_ue_s1ap_id int32
	var enb_ue_s1ap_id int32

	for _, ie := range ies {
		switch ie.id {
		case C.ProtocolIE_ID_id_MME_UE_S1AP_ID:
			mme_ue_s1ap_id_c := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			mme_ue_s1ap_id = (int32)(*mme_ue_s1ap_id_c)
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_ue_s1ap_id_c := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			enb_ue_s1ap_id = (int32)(*enb_ue_s1ap_id_c)
		default:
		}
	}
	return mme_ue_s1ap_id, enb_ue_s1ap_id, nil
}

// Handler for InitialContextSetupRequest
func InitialContextSetupRequestHandle(packet unsafe.Pointer) (int32, int32, error) {
	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.InitialContextSetupRequest_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.InitialContextSetupRequestIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	var mme_ue_s1ap_id int32
	var enb_ue_s1ap_id int32

	for _, ie := range ies {
		switch ie.id {
		case C.ProtocolIE_ID_id_MME_UE_S1AP_ID:
			mme_ue_s1ap_id_c := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			mme_ue_s1ap_id = (int32)(*mme_ue_s1ap_id_c)
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_ue_s1ap_id_c := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			enb_ue_s1ap_id = (int32)(*enb_ue_s1ap_id_c)
		default:
		}
	}
	return mme_ue_s1ap_id, enb_ue_s1ap_id, nil
}

// Handler for Reset
func ResetHandle(packet unsafe.Pointer) (string, error) {
	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.Reset_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.ResetIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	var resetInfo string = "Reset Details: "

	for _, ie := range ies {
		switch ie.id {
		case C.ProtocolIE_ID_id_Cause:
			resetInfo += "Cause IE found; "
		case C.ProtocolIE_ID_id_ResetType:
			resetInfo += "ResetType IE found; "
		default:
			resetInfo += fmt.Sprintf("Unknown IE %d; ", ie.id)
		}
	}
	return resetInfo, nil
}

// Generic handler for messages that only need basic info extraction
func GenericS1APHandle(packet unsafe.Pointer, messageType int) (string, error) {
	procedureName := GetProcedureName(messageType)
	return fmt.Sprintf("%s message handled", procedureName), nil
}

func UplinkNASTransportHandle(packet unsafe.Pointer) (int32, int, error) {
	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.UplinkNASTransport_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.UplinkNASTransport_IEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	var enb_ie_s1ap_id int32
	var eps_mmm_type int

	for _, ie := range ies {
		switch ie.id {
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			fmt.Println("IE: eNB_UE_S1AP_ID")
			enb_ie_s1ap_id_c := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			enb_ie_s1ap_id = (int32)(*enb_ie_s1ap_id_c)
		case C.ProtocolIE_ID_id_NAS_PDU:
			fmt.Println("IE: NAS_PDU")
			// OCTET_STRING_T
			// typedef struct OCTET_STRING {
			// uint8_t *buf;   /* Buffer with consecutive OCTET_STRING bits */
			// size_t size;    /* Size of the buffer */
			//
			// asn_struct_ctx_t _asn_ctx;      /* Parsing across buffer boundaries */
			// } OCTET_STRING_t;
			nas_pdu := (*C.NAS_PDU_t)(unsafe.Pointer(&ie.value.choice))

			var nas_pdu_buf []byte
			slice := (*reflect.SliceHeader)((unsafe.Pointer(&nas_pdu_buf)))
			slice.Cap = (int)(nas_pdu.size)
			slice.Len = (int)(nas_pdu.size)
			slice.Data = uintptr(unsafe.Pointer(nas_pdu.buf))

			fmt.Println("NAS_PDU_LEN", len(nas_pdu_buf))
			for _, val := range nas_pdu_buf {
				fmt.Printf("%02x ", val)
			}
			fmt.Printf("\n")
			var securityHeaderType byte
			var protocolDisc byte
			for len(nas_pdu_buf) > 0 {
				securityHeaderType = (nas_pdu_buf[0] & 0xf0) >> 4
				protocolDisc = (nas_pdu_buf[0] & 0x0f)
				nas_pdu_buf = nas_pdu_buf[1:]
				fmt.Printf("securityHeaderType: %02x\n", securityHeaderType)
				fmt.Printf("protocolDisc: %02x\n", protocolDisc)

				if protocolDisc != 7 {
					return 0, 0, fmt.Errorf("Protocol discrimiter is not EPS MMM")
				}

				switch securityHeaderType {
				case 0:
					fmt.Printf("MMM Type %02x\n", nas_pdu_buf[0])
					typ := nas_pdu_buf[0]
					nas_pdu_buf = nas_pdu_buf[1:]
					switch typ {
					case 0x53:
						eps_mmm_type = NAS_EPS_AUTH_RESPONSE
						if len(nas_pdu_buf) > 0 {
							len := nas_pdu_buf[0]
							nas_pdu_buf = nas_pdu_buf[len+1:]
						}
					case 0x5e:
						eps_mmm_type = NAS_EPS_SECURITY_MODE_COMPLETE
					default:
						eps_mmm_type = 0
					}
				case 4:
					nas_pdu_buf = nas_pdu_buf[5:]
				default:
					return 0, 0, fmt.Errorf("Security header type is not known %d", securityHeaderType)
				}
			}
		case C.ProtocolIE_ID_id_TAI:
			fmt.Println("IE: TAI")
			//TAI = &ie->value.choice.TAI;
		case C.ProtocolIE_ID_id_EUTRAN_CGI:
			fmt.Println("IE: EUTRAN_CGI")
			//EUTRAN_CGI = &ie->value.choice.EUTRAN_CGI;
		case C.ProtocolIE_ID_id_S_TMSI:
			fmt.Println("IE: S_TMSI")
			//S_TMSI = &ie->value.choice.S_TMSI;
		default:
		}
	}
	return enb_ie_s1ap_id, eps_mmm_type, nil
}

func Decode(buf []byte) (unsafe.Pointer, int, error) {
	packet := C.calloc(C.sizeof_struct_S1AP_PDU, 1)
	var opt_codec *C.asn_codec_ctx_t = nil

	ret := C.aper_decode(
		opt_codec,
		&C.asn_DEF_S1AP_PDU,
		(*unsafe.Pointer)(&packet),
		(unsafe.Pointer)(&buf[0]),
		(C.size_t)(len(buf)),
		0,
		0)

	if ret.code != C.RC_OK {
		C.free(packet)
		return nil, 0, fmt.Errorf("aper_decode failed: %d", ret)
	}

	pdu := (*C.S1AP_PDU_t)(packet)
	log.Println("PDU type:", S1AP_PDU2String(pdu.present))

	typ := 0
	switch pdu.present {
	case C.S1AP_PDU_PR_NOTHING:
	case C.S1AP_PDU_PR_initiatingMessage:
		msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
		log.Println("Message type:", S1AP_Initiating2String(msg.value.present))
		
		// Enhanced switch to support all PDU types following the same logic
		switch msg.value.present {
		// Basic message types (original)
		case C.InitiatingMessage__value_PR_S1SetupRequest:
			typ = S1_SETUP_REQUEST
		case C.InitiatingMessage__value_PR_InitialUEMessage:
			typ = INITIAL_UE_MESSAGE
		case C.InitiatingMessage__value_PR_UplinkNASTransport:
			typ = UPLINK_NAS_TRANSPORT
		case C.InitiatingMessage__value_PR_DownlinkNASTransport:
			typ = DOWNLINK_NAS_TRANSPORT
		case C.InitiatingMessage__value_PR_Paging:
			typ = PAGING
			
		// Context management
		case C.InitiatingMessage__value_PR_UEContextReleaseRequest:
			typ = UE_CONTEXT_RELEASE_REQUEST
		case C.InitiatingMessage__value_PR_UEContextReleaseCommand:
			typ = UE_CONTEXT_RELEASE
		case C.InitiatingMessage__value_PR_UEContextModificationRequest:
			typ = UE_CONTEXT_MODIFICATION
		case C.InitiatingMessage__value_PR_InitialContextSetupRequest:
			typ = INITIAL_CONTEXT_SETUP
		case C.InitiatingMessage__value_PR_UEContextModificationIndication:
			typ = UE_CONTEXT_MODIFICATION_INDICATION
		case C.InitiatingMessage__value_PR_UEContextSuspendRequest:
			typ = UE_CONTEXT_SUSPEND
		case C.InitiatingMessage__value_PR_UEContextResumeRequest:
			typ = UE_CONTEXT_RESUME
			
		// E-RAB management
		case C.InitiatingMessage__value_PR_E_RABSetupRequest:
			typ = E_RAB_SETUP
		case C.InitiatingMessage__value_PR_E_RABModifyRequest:
			typ = E_RAB_MODIFY
		case C.InitiatingMessage__value_PR_E_RABReleaseCommand:
			typ = E_RAB_RELEASE
		case C.InitiatingMessage__value_PR_E_RABReleaseIndication:
			typ = E_RAB_RELEASE_INDICATION
		case C.InitiatingMessage__value_PR_E_RABModificationIndication:
			typ = E_RAB_MODIFICATION_INDICATION
			
		// Handover procedures
		case C.InitiatingMessage__value_PR_HandoverRequired:
			typ = HANDOVER_PREPARATION
		case C.InitiatingMessage__value_PR_HandoverRequest:
			typ = HANDOVER_RESOURCE_ALLOCATION
		case C.InitiatingMessage__value_PR_HandoverNotify:
			typ = HANDOVER_NOTIFICATION
		case C.InitiatingMessage__value_PR_HandoverCancel:
			typ = HANDOVER_CANCEL
		case C.InitiatingMessage__value_PR_PathSwitchRequest:
			typ = PATH_SWITCH_REQUEST
			
		// Configuration and management
		case C.InitiatingMessage__value_PR_Reset:
			typ = RESET
		case C.InitiatingMessage__value_PR_ErrorIndication:
			typ = ERROR_INDICATION
		case C.InitiatingMessage__value_PR_NASNonDeliveryIndication:
			typ = NAS_NON_DELIVERY_INDICATION
		case C.InitiatingMessage__value_PR_ENBConfigurationUpdate:
			typ = ENB_CONFIGURATION_UPDATE
		case C.InitiatingMessage__value_PR_MMEConfigurationUpdate:
			typ = MME_CONFIGURATION_UPDATE
		case C.InitiatingMessage__value_PR_ENBConfigurationTransfer:
			typ = ENB_CONFIGURATION_TRANSFER
		case C.InitiatingMessage__value_PR_MMEConfigurationTransfer:
			typ = MME_CONFIGURATION_TRANSFER
			
		// Location and reporting
		case C.InitiatingMessage__value_PR_LocationReportingControl:
			typ = LOCATION_REPORTING_CONTROL
		case C.InitiatingMessage__value_PR_LocationReportingFailureIndication:
			typ = LOCATION_REPORTING_FAILURE_INDICATION
		case C.InitiatingMessage__value_PR_LocationReport:
			typ = LOCATION_REPORT
			
		// Overload management
		case C.InitiatingMessage__value_PR_OverloadStart:
			typ = OVERLOAD_START
		case C.InitiatingMessage__value_PR_OverloadStop:
			typ = OVERLOAD_STOP
			
		// Warning and emergency
		case C.InitiatingMessage__value_PR_WriteReplaceWarningRequest:
			typ = WRITE_REPLACE_WARNING
		case C.InitiatingMessage__value_PR_KillRequest:
			typ = KILL
		case C.InitiatingMessage__value_PR_PWSRestartIndication:
			typ = PWS_RESTART_INDICATION
		case C.InitiatingMessage__value_PR_PWSFailureIndication:
			typ = PWS_FAILURE_INDICATION
			
		// Information transfer
		case C.InitiatingMessage__value_PR_ENBDirectInformationTransfer:
			typ = ENB_DIRECT_INFORMATION_TRANSFER
		case C.InitiatingMessage__value_PR_MMEDirectInformationTransfer:
			typ = MME_DIRECT_INFORMATION_TRANSFER
		case C.InitiatingMessage__value_PR_PrivateMessage:
			typ = PRIVATE_MESSAGE
			
		// Trace procedures
		case C.InitiatingMessage__value_PR_TraceStart:
			typ = TRACE_START
		case C.InitiatingMessage__value_PR_TraceFailureIndication:
			typ = TRACE_FAILURE_INDICATION
		case C.InitiatingMessage__value_PR_DeactivateTrace:
			typ = DEACTIVATE_TRACE
		case C.InitiatingMessage__value_PR_CellTrafficTrace:
			typ = CELL_TRAFFIC_TRACE
			
		// UE capability and status transfer
		case C.InitiatingMessage__value_PR_UECapabilityInfoIndication:
			typ = UE_CAPABILITY_INFO_INDICATION
		case C.InitiatingMessage__value_PR_ENBStatusTransfer:
			typ = ENB_STATUS_TRANSFER
		case C.InitiatingMessage__value_PR_MMEStatusTransfer:
			typ = MME_STATUS_TRANSFER
		case C.InitiatingMessage__value_PR_UERadioCapabilityMatchRequest:
			typ = UE_RADIO_CAPABILITY_MATCH
			
		// CDMA2000 tunneling
		case C.InitiatingMessage__value_PR_DownlinkS1cdma2000tunnelling:
			typ = DOWNLINK_S1CDMA2000_TUNNELLING
		case C.InitiatingMessage__value_PR_UplinkS1cdma2000tunnelling:
			typ = UPLINK_S1CDMA2000_TUNNELLING
			
		// LPPa transport
		case C.InitiatingMessage__value_PR_DownlinkUEAssociatedLPPaTransport:
			typ = DOWNLINK_UE_ASSOCIATED_LPPA_TRANSPORT
		case C.InitiatingMessage__value_PR_UplinkUEAssociatedLPPaTransport:
			typ = UPLINK_UE_ASSOCIATED_LPPA_TRANSPORT
		case C.InitiatingMessage__value_PR_DownlinkNonUEAssociatedLPPaTransport:
			typ = DOWNLINK_NON_UE_ASSOCIATED_LPPA_TRANSPORT
		case C.InitiatingMessage__value_PR_UplinkNonUEAssociatedLPPaTransport:
			typ = UPLINK_NON_UE_ASSOCIATED_LPPA_TRANSPORT
			
		// Additional procedures
		case C.InitiatingMessage__value_PR_RerouteNASRequest:
			typ = REROUTE_NAS_REQUEST
		case C.InitiatingMessage__value_PR_ConnectionEstablishmentIndication:
			typ = CONNECTION_ESTABLISHMENT_INDICATION
		case C.InitiatingMessage__value_PR_NASDeliveryIndication:
			typ = NAS_DELIVERY_INDICATION
		case C.InitiatingMessage__value_PR_RetrieveUEInformation:
			typ = RETRIEVE_UE_INFORMATION
		case C.InitiatingMessage__value_PR_UEInformationTransfer:
			typ = UE_INFORMATION_TRANSFER
		case C.InitiatingMessage__value_PR_ENBCPRelocationIndication:
			typ = ENB_CP_RELOCATION_INDICATION
		case C.InitiatingMessage__value_PR_MMECPRelocationIndication:
			typ = MME_CP_RELOCATION_INDICATION
			
		default:
			// Log unknown procedure for debugging
			log.Printf("Unknown InitiatingMessage procedure: %d", msg.value.present)
		}
	case C.S1AP_PDU_PR_successfulOutcome:
		// Handle successful outcome messages if needed
		log.Println("SuccessfulOutcome message detected")
	case C.S1AP_PDU_PR_unsuccessfulOutcome:
		// Handle unsuccessful outcome messages if needed
		log.Println("UnsuccessfulOutcome message detected")
	default:
	}
	return packet, typ, nil
}

func XerPrint(message unsafe.Pointer) {
	C.xer_fprint(C.stdout, &C.asn_DEF_S1AP_PDU, message)
}

func Free(packet unsafe.Pointer) {
	C.free(packet)
}
