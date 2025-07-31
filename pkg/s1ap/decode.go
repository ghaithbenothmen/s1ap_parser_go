package s1ap

// #cgo CFLAGS: -I./asn1
// #cgo LDFLAGS: -L/usr/local/lib -ls1ap -lasn1c
// #include "S1AP-PDU.h"
// #include "InitiatingMessage.h"
// #include "SuccessfulOutcome.h"
// #include "UnsuccessfulOutcome.h"
// #include "ProtocolIE-Field.h"
// #include "Paging.h"
// #include "UEPagingID.h"
// #include "S-TMSI.h"
// #include "IMSI.h"
// #include "CNDomain.h"
// #include "TAIList.h"
// #include "TAIItem.h"
// #include "TAI.h"
// #include "PagingDRX.h"
// #include "PagingPriority.h"
// #include "CellTrafficTrace.h"
// #include "E-UTRAN-Trace-ID.h"
// #include "EUTRAN-CGI.h"
// #include "TraceStart.h"
// #include "TraceFailureIndication.h"
// #include "DeactivateTrace.h"
// #include "LocationReportingControl.h"
// #include "LocationReportingFailureIndication.h"
// #include "LocationReport.h"
// #include "TransportLayerAddress.h"
// #include "PrivacyIndicator.h"
// #include <stdio.h>
// #include <stdlib.h>
import "C"
import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"reflect"
	"strings"
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
			// Extraire et décoder TAI
			taiPtr := unsafe.Pointer(&ie.value.choice[0])
			taiValue, taiRaw := extractTAI(taiPtr)
			log.Printf("IE TAI decoded: %s (raw: %s)", taiValue, taiRaw)
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

	var pagingInfo string = "Paging Details:\n"
	var taiListInfo string

	for _, ie := range ies {
		switch ie.id {
		case C.ProtocolIE_ID_id_UEIdentityIndexValue:
			pagingInfo += "  - UEIdentityIndexValue found\n"
		case C.ProtocolIE_ID_id_UEPagingID:
			pagingInfo += "  - UEPagingID found\n"
		case C.ProtocolIE_ID_id_CNDomain:
			pagingInfo += "  - CNDomain found\n"
		case C.ProtocolIE_ID_id_TAIList:
			// Extraire et décoder la TAIList complète
			taiListPtr := unsafe.Pointer(&ie.value.choice[0])
			taiValue, taiRaw := extractTAIList(taiListPtr)
			pagingInfo += fmt.Sprintf("  - %s\n", taiValue)
			taiListInfo = taiRaw
			log.Printf("TAIList decoded: %s (raw: %s)", taiValue, taiRaw)
		default:
			pagingInfo += fmt.Sprintf("  - Unknown IE %d\n", ie.id)
		}
	}
	
	if taiListInfo != "" {
		pagingInfo += fmt.Sprintf("Raw TAI data: %s", taiListInfo)
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

// Handler for UEContextReleaseComplete
func UEContextReleaseCompleteHandle(packet unsafe.Pointer) (int32, int32, error) {
	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.SuccessfulOutcome_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.UEContextReleaseComplete_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.UEContextReleaseComplete_IEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	var mme_ue_s1ap_id int32 = -1
	var enb_ue_s1ap_id int32 = -1

	for _, ie := range ies {
		switch ie.id {
		case C.ProtocolIE_ID_id_MME_UE_S1AP_ID:
			mme_id_c := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			mme_ue_s1ap_id = (int32)(*mme_id_c)
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_id_c := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			enb_ue_s1ap_id = (int32)(*enb_id_c)
		default:
		}
	}

	return mme_ue_s1ap_id, enb_ue_s1ap_id, nil
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
			// Extraire et décoder TAI
			taiPtr := unsafe.Pointer(&ie.value.choice[0])
			taiValue, taiRaw := extractTAI(taiPtr)
			log.Printf("IE TAI decoded: %s (raw: %s)", taiValue, taiRaw)
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

// IE ID to name mapping (complete list from asn1c generated ProtocolIE-ID.h)
var IEIDToNameMap = map[int]string{
	0:   "id_MME_UE_S1AP_ID",
	1:   "id_HandoverType",
	2:   "id_Cause",
	3:   "id_SourceID",
	4:   "id_TargetID",
	8:   "id_eNB_UE_S1AP_ID",
	12:  "id_E_RABSubjecttoDataForwardingList",
	13:  "id_E_RABtoReleaseListHOCmd",
	14:  "id_E_RABDataForwardingItem",
	15:  "id_E_RABReleaseItemBearerRelComp",
	16:  "id_E_RABToBeSetupListBearerSUReq",
	17:  "id_E_RABToBeSetupItemBearerSUReq",
	18:  "id_E_RABAdmittedList",
	19:  "id_E_RABFailedToSetupListHOReqAck",
	20:  "id_E_RABAdmittedItem",
	21:  "id_E_RABFailedtoSetupItemHOReqAck",
	22:  "id_E_RABToBeSwitchedDLList",
	23:  "id_E_RABToBeSwitchedDLItem",
	24:  "id_E_RABToBeSetupListCtxtSUReq",
	25:  "id_TraceActivation",
	26:  "id_NAS_PDU",
	27:  "id_E_RABToBeSetupItemHOReq",
	28:  "id_E_RABSetupListBearerSURes",
	29:  "id_E_RABFailedToSetupListBearerSURes",
	30:  "id_E_RABToBeModifiedListBearerModReq",
	31:  "id_E_RABModifyListBearerModRes",
	32:  "id_E_RABFailedToModifyList",
	33:  "id_E_RABToBeReleasedList",
	34:  "id_E_RABFailedToReleaseList",
	35:  "id_E_RABItem",
	36:  "id_E_RABToBeModifiedItemBearerModReq",
	37:  "id_E_RABModifyItemBearerModRes",
	38:  "id_E_RABReleaseItem",
	39:  "id_E_RABSetupItemBearerSURes",
	40:  "id_SecurityContext",
	41:  "id_HandoverRestrictionList",
	43:  "id_UEPagingID",
	44:  "id_pagingDRX",
	46:  "id_TAIList",
	47:  "id_TAIItem",
	48:  "id_E_RABFailedToSetupListCtxtSURes",
	49:  "id_E_RABReleaseItemHOCmd",
	50:  "id_E_RABSetupItemCtxtSURes",
	51:  "id_E_RABSetupListCtxtSURes",
	52:  "id_E_RABToBeSetupItemCtxtSUReq",
	53:  "id_E_RABToBeSetupListHOReq",
	55:  "id_GERANtoLTEHOInformationRes",
	57:  "id_UTRANtoLTEHOInformationRes",
	58:  "id_CriticalityDiagnostics",
	59:  "id_Global_ENB_ID",
	60:  "id_eNBname",
	61:  "id_MMEname",
	63:  "id_ServedPLMNs",
	64:  "id_SupportedTAs",
	65:  "id_TimeToWait",
	66:  "id_uEaggregateMaximumBitrate",
	67:  "id_TAI",
	69:  "id_E_RABReleaseListBearerRelComp",
	70:  "id_cdma2000PDU",
	71:  "id_cdma2000RATType",
	72:  "id_cdma2000SectorID",
	73:  "id_SecurityKey",
	74:  "id_UERadioCapability",
	75:  "id_GUMMEI_ID",
	78:  "id_E_RABInformationListItem",
	79:  "id_Direct_Forwarding_Path_Availability",
	80:  "id_UEIdentityIndexValue",
	83:  "id_cdma2000HOStatus",
	84:  "id_cdma2000HORequiredIndication",
	86:  "id_E_UTRAN_Trace_ID",
	87:  "id_RelativeMMECapacity",
	88:  "id_SourceMME_UE_S1AP_ID",
	89:  "id_Bearers_SubjectToStatusTransfer_Item",
	90:  "id_eNB_StatusTransfer_TransparentContainer",
	91:  "id_UE_associatedLogicalS1_ConnectionItem",
	92:  "id_ResetType",
	93:  "id_UE_associatedLogicalS1_ConnectionListResAck",
	94:  "id_E_RABToBeSwitchedULItem",
	95:  "id_E_RABToBeSwitchedULList",
	96:  "id_S_TMSI",
	97:  "id_cdma2000OneXRAND",
	98:  "id_RequestType",
	99:  "id_UE_S1AP_IDs",
	100: "id_EUTRAN_CGI",
	101: "id_OverloadResponse",
	102: "id_cdma2000OneXSRVCCInfo",
	103: "id_E_RABFailedToBeReleasedList",
	104: "id_Source_ToTarget_TransparentContainer",
	105: "id_ServedGUMMEIs",
	106: "id_SubscriberProfileIDforRFP",
	107: "id_UESecurityCapabilities",
	108: "id_CSFallbackIndicator",
	109: "id_CNDomain",
	110: "id_E_RABReleasedList",
	111: "id_MessageIdentifier",
	112: "id_SerialNumber",
	113: "id_WarningAreaList",
	114: "id_RepetitionPeriod",
	115: "id_NumberofBroadcastRequest",
	116: "id_WarningType",
	117: "id_WarningSecurityInfo",
	118: "id_DataCodingScheme",
	119: "id_WarningMessageContents",
	120: "id_BroadcastCompletedAreaList",
	121: "id_Inter_SystemInformationTransferTypeEDT",
	122: "id_Inter_SystemInformationTransferTypeMDT",
	123: "id_Target_ToSource_TransparentContainer",
	124: "id_SRVCCOperationPossible",
	125: "id_SRVCCHOIndication",
	126: "id_NAS_DownlinkCount",
	127: "id_CSG_Id",
	128: "id_CSG_IdList",
	129: "id_SONConfigurationTransferECT",
	130: "id_SONConfigurationTransferMCT",
	131: "id_TraceCollectionEntityIPAddress",
	132: "id_MSClassmark2",
	133: "id_MSClassmark3",
	134: "id_RRC_Establishment_Cause",
	135: "id_NASSecurityParametersfromE_UTRAN",
	136: "id_NASSecurityParameterstoE_UTRAN",
	137: "id_DefaultPagingDRX",
	138: "id_Source_ToTarget_TransparentContainer_Secondary",
	139: "id_Target_ToSource_TransparentContainer_Secondary",
	140: "id_EUTRANRoundTripDelayEstimationInfo",
	141: "id_BroadcastCancelledAreaList",
	142: "id_ConcurrentWarningMessageIndicator",
	143: "id_Data_Forwarding_Not_Possible",
	144: "id_ExtendedRepetitionPeriod",
	145: "id_CellAccessMode",
	146: "id_CSGMembershipStatus",
	147: "id_LPPa_PDU",
	148: "id_Routing_ID",
	149: "id_Time_Synchronisation_Info",
	150: "id_PS_ServiceNotAvailable",
	151: "id_PagingPriority",
	152: "id_x2TNLConfigurationInfo",
	153: "id_eNBX2ExtendedTransportLayerAddresses",
	154: "id_GUMMEIList",
	155: "id_GW_TransportLayerAddress",
	156: "id_Correlation_ID",
	157: "id_SourceMME_GUMMEI",
	158: "id_MME_UE_S1AP_ID_2",
	159: "id_RegisteredLAI",
	160: "id_RelayNode_Indicator",
	161: "id_TrafficLoadReductionIndication",
	162: "id_MDTConfiguration",
	163: "id_MMERelaySupportIndicator",
	164: "id_GWContextReleaseIndication",
	165: "id_ManagementBasedMDTAllowed",
	166: "id_PrivacyIndicator",
	167: "id_Time_UE_StayedInCell_EnhancedGranularity",
	168: "id_HO_Cause",
	169: "id_VoiceSupportMatchIndicator",
	170: "id_GUMMEIType",
	171: "id_M3Configuration",
	172: "id_M4Configuration",
	173: "id_M5Configuration",
	174: "id_MDT_Location_Info",
	175: "id_MobilityInformation",
	176: "id_Tunnel_Information_for_BBF",
	177: "id_ManagementBasedMDTPLMNList",
	178: "id_SignallingBasedMDTPLMNList",
	179: "id_ULCOUNTValueExtended",
	180: "id_DLCOUNTValueExtended",
	181: "id_ReceiveStatusOfULPDCPSDUsExtended",
	182: "id_ECGIListForRestart",
	183: "id_SIPTO_Correlation_ID",
	184: "id_SIPTO_L_GW_TransportLayerAddress",
	185: "id_TransportInformation",
	186: "id_LHN_ID",
	187: "id_AdditionalCSFallbackIndicator",
	188: "id_TAIListForRestart",
	189: "id_UserLocationInformation",
	190: "id_EmergencyAreaIDListForRestart",
	191: "id_KillAllWarningMessages",
	192: "id_Masked_IMEISV",
	193: "id_eNBIndirectX2TransportLayerAddresses",
	194: "id_uE_HistoryInformationFromTheUE",
	195: "id_ProSeAuthorized",
	196: "id_ExpectedUEBehaviour",
	197: "id_LoggedMBSFNMDT",
	198: "id_UERadioCapabilityForPaging",
	199: "id_E_RABToBeModifiedListBearerModInd",
	200: "id_E_RABToBeModifiedItemBearerModInd",
	201: "id_E_RABNotToBeModifiedListBearerModInd",
	202: "id_E_RABNotToBeModifiedItemBearerModInd",
	203: "id_E_RABModifyListBearerModConf",
	204: "id_E_RABModifyItemBearerModConf",
	205: "id_E_RABFailedToModifyListBearerModConf",
	206: "id_SON_Information_Report",
	207: "id_Muting_Availability_Indication",
	208: "id_Muting_Pattern_Information",
	209: "id_Synchronisation_Information",
	210: "id_E_RABToBeReleasedListBearerModConf",
	211: "id_AssistanceDataForPaging",
	212: "id_CellIdentifierAndCELevelForCECapableUEs",
	213: "id_InformationOnRecommendedCellsAndENBsForPaging",
	214: "id_RecommendedCellItem",
	215: "id_RecommendedENBItem",
	216: "id_ProSeUEtoNetworkRelaying",
	217: "id_ULCOUNTValuePDCP_SNlength18",
	218: "id_DLCOUNTValuePDCP_SNlength18",
	219: "id_ReceiveStatusOfULPDCPSDUsPDCP_SNlength18",
	220: "id_M6Configuration",
	221: "id_M7Configuration",
	222: "id_PWSfailedECGIList",
	223: "id_MME_Group_ID",
	224: "id_Additional_GUTI",
	225: "id_S1_Message",
	226: "id_CSGMembershipInfo",
	227: "id_Paging_eDRXInformation",
	228: "id_UE_RetentionInformation",
	230: "id_UE_Usage_Type",
	231: "id_extended_UEIdentityIndexValue",
	232: "id_RAT_Type",
	233: "id_BearerType",
	234: "id_NB_IoT_DefaultPagingDRX",
	235: "id_E_RABFailedToResumeListResumeReq",
	236: "id_E_RABFailedToResumeItemResumeReq",
	237: "id_E_RABFailedToResumeListResumeRes",
	238: "id_E_RABFailedToResumeItemResumeRes",
	239: "id_NB_IoT_Paging_eDRXInformation",
	240: "id_V2XServicesAuthorized",
	241: "id_UEUserPlaneCIoTSupportIndicator",
	242: "id_CE_mode_B_SupportIndicator",
	243: "id_SRVCCOperationNotPossible",
	244: "id_NB_IoT_UEIdentityIndexValue",
	245: "id_RRC_Resume_Cause",
	246: "id_DCN_ID",
	247: "id_ServedDCNs",
	248: "id_UESidelinkAggregateMaximumBitrate",
	249: "id_DLNASPDUDeliveryAckRequest",
	250: "id_Coverage_Level",
	251: "id_EnhancedCoverageRestricted",
	252: "id_UE_Level_QoS_Parameters",
	253: "id_DL_CP_SecurityInformation",
	254: "id_UL_CP_SecurityInformation",
	255: "id_extended_e_RAB_MaximumBitrateDL",
	256: "id_extended_e_RAB_MaximumBitrateUL",
	257: "id_extended_e_RAB_GuaranteedBitrateDL",
	258: "id_extended_e_RAB_GuaranteedBitrateUL",
	259: "id_extended_uEaggregateMaximumBitRateDL",
	260: "id_extended_uEaggregateMaximumBitRateUL",
	261: "id_NRrestrictioninEPSasSecondaryRAT",
	262: "id_UEAppLayerMeasConfig",
	263: "id_UE_Application_Layer_Measurement_Capability",
	264: "id_SecondaryRATDataUsageReportList",
	265: "id_SecondaryRATDataUsageReportItem",
	266: "id_HandoverFlag",
	267: "id_E_RABUsageReportItem",
	268: "id_SecondaryRATDataUsageRequest",
	269: "id_NRUESecurityCapabilities",
	270: "id_UnlicensedSpectrumRestriction",
	271: "id_CE_ModeBRestricted",
	272: "id_LTE_M_Indication",
	273: "id_DownlinkPacketLossRate",
	274: "id_UplinkPacketLossRate",
	275: "id_UECapabilityInfoRequest",
	276: "id_serviceType",
	277: "id_AerialUEsubscriptionInformation",
	278: "id_Subscription_Based_UE_DifferentiationInfo",
	280: "id_EndIndication",
	281: "id_EDT_Session",
	282: "id_CNTypeRestrictions",
	283: "id_PendingDataIndication",
	284: "id_BluetoothMeasurementConfiguration",
	285: "id_WLANMeasurementConfiguration",
	286: "id_WarningAreaCoordinates",
	287: "id_NRrestrictionin5GS",
	288: "id_PSCellInformation",
	290: "id_LastNG_RANPLMNIdentity",
	291: "id_ConnectedengNBList",
	292: "id_ConnectedengNBToAddList",
	293: "id_ConnectedengNBToRemoveList",
	294: "id_EN_DCSONConfigurationTransfer_ECT",
	295: "id_EN_DCSONConfigurationTransfer_MCT",
	296: "id_IMSvoiceEPSfallbackfrom5G",
	297: "id_TimeSinceSecondaryNodeRelease",
	298: "id_RequestTypeAdditionalInfo",
	299: "id_AdditionalRRMPriorityIndex",
	300: "id_ContextatSource",
	301: "id_IAB_Authorized",
	302: "id_IAB_Node_Indication",
	303: "id_IAB_Supported",
	304: "id_DataSize",
	305: "id_Ethernet_Type",
	306: "id_NRV2XServicesAuthorized",
	307: "id_NRUESidelinkAggregateMaximumBitrate",
	308: "id_PC5QoSParameters",
	309: "id_IntersystemSONConfigurationTransferMCT",
	310: "id_IntersystemSONConfigurationTransferECT",
	311: "id_IntersystemMeasurementConfiguration",
	312: "id_SourceNodeID",
	313: "id_NB_IoT_RLF_Report_Container",
	314: "id_UERadioCapabilityID",
	315: "id_UERadioCapability_NR_Format",
	316: "id_MDTConfigurationNR",
	317: "id_DAPSRequestInfo",
	318: "id_DAPSResponseInfoList",
	319: "id_DAPSResponseInfoItem",
	320: "id_NotifySourceeNB",
	321: "id_eNB_EarlyStatusTransfer_TransparentContainer",
	322: "id_Bearers_SubjectToEarlyStatusTransfer_Item",
	323: "id_WUS_Assistance_Information",
	324: "id_NB_IoT_PagingDRX",
	325: "id_TraceCollectionEntityURI",
	326: "id_EmergencyIndicator",
	327: "id_UERadioCapabilityForPaging_NR_Format",
	328: "id_SourceTransportLayerAddress",
	329: "id_lastVisitedPSCellList",
	330: "id_RACSIndication",
	331: "id_PagingCause",
	332: "id_SecurityIndication",
	333: "id_SecurityResult",
	334: "id_E_RABSecurityResultItem",
	335: "id_E_RABSecurityResultList",
	336: "id_RAT_Restrictions",
	337: "id_UEContextReferenceatSourceeNB",
	339: "id_LTE_NTN_TAI_Information",
	340: "id_SourceNodeTransportLayerAddress",
	341: "id_E_RABToBeUpdatedList",
	342: "id_E_RABToBeUpdatedItem",
	343: "id_SourceSNID",
	344: "id_LoggedMDTTrigger",
	345: "id_SensorMeasurementConfiguration",
}

// Get IE name by ID
func GetIEName(id int) string {
	if name, exists := IEIDToNameMap[id]; exists {
		return name
	}
	return fmt.Sprintf("Unknown_IE_%d", id)
}

// ExtractAllIEs extracts all Information Elements from a decoded S1AP PDU
func ExtractAllIEs(packet unsafe.Pointer, messageType int, realProcCode ...int) []*InformationElement {
	var ies []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	log.Printf("DEBUG: ExtractAllIEs called - pdu.present: %d, messageType: %d", pdu.present, messageType)

	// Determine the procedure code to use
	procCode := messageType
	if len(realProcCode) > 0 {
		procCode = realProcCode[0]
	}

	switch pdu.present {
	case C.S1AP_PDU_PR_initiatingMessage:
		log.Printf("DEBUG: Calling extractInitiatingMessageIEs for messageType: %d, procCode: %d", messageType, procCode)
		ies = extractInitiatingMessageIEs(packet, messageType, procCode)
	case C.S1AP_PDU_PR_successfulOutcome:
		ies = extractSuccessfulOutcomeIEs(packet, messageType)
	case C.S1AP_PDU_PR_unsuccessfulOutcome:
		ies = extractUnsuccessfulOutcomeIEs(packet, messageType)
	default:
		log.Printf("DEBUG: Unsupported PDU type: %d", pdu.present)
	}

	return ies
}

func extractInitiatingMessageIEs(packet unsafe.Pointer, messageType int, procCode int) []*InformationElement {
	var ies []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	if pdu.present != C.S1AP_PDU_PR_initiatingMessage {
		return ies
	}

	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))

	// Switch based on message type to extract IEs appropriately
	log.Printf("DEBUG: extractInitiatingMessageIEs - msg.value.present: %d, messageType: %d, procCode: %d", msg.value.present, messageType, procCode)
	
	// First check procedure code for specific routing (override ASN.1 present values)
	if procCode == 12 { // InitialUEMessage procedure code
		log.Printf("DEBUG: Detected InitialUEMessage via procedure code 12 - calling extractInitialUEMessageIEs")
		ies = extractInitialUEMessageIEs(packet)
		return ies
	}
	
	if procCode == 13 { // UplinkNASTransport procedure code
		log.Printf("DEBUG: Detected UplinkNASTransport via procedure code 13 - calling extractUplinkNASTransportIEs")
		ies = extractUplinkNASTransportIEs(packet)
		return ies
	}
	
	switch msg.value.present {
	case C.InitiatingMessage__value_PR_InitialUEMessage:
		log.Printf("DEBUG: Detected InitialUEMessage - calling extractInitialUEMessageIEs")
		ies = extractInitialUEMessageIEs(packet)
	case C.InitiatingMessage__value_PR_UplinkNASTransport:
		log.Printf("DEBUG: Detected UplinkNASTransport - calling extractUplinkNASTransportIEs")
		ies = extractUplinkNASTransportIEs(packet)
	case C.InitiatingMessage__value_PR_Paging:
		// Handle both Paging and DownlinkNASTransport (which seem to have the same internal type)
		log.Printf("DEBUG: Paging case - procCode: %d (11=DownlinkNASTransport, 10=Paging)", procCode)
		if procCode == 11 { // DownlinkNASTransport procedure code
			log.Printf("DEBUG: Detected DownlinkNASTransport via Paging case - calling extractDownlinkNASTransportIEs")
			ies = extractDownlinkNASTransportIEs(packet)
		} else {
			log.Printf("DEBUG: Detected Paging message - calling extractPagingIEs")
			ies = extractPagingIEs(packet)
		}
	case C.InitiatingMessage__value_PR_CellTrafficTrace:
		log.Printf("DEBUG: Detected CellTrafficTrace - calling extractCellTrafficTraceIEs")
		ies = extractCellTrafficTraceIEs(packet)
	case C.InitiatingMessage__value_PR_TraceStart:
		log.Printf("DEBUG: Detected TraceStart - calling extractTraceStartIEs")
		ies = extractTraceStartIEs(packet)
	case C.InitiatingMessage__value_PR_TraceFailureIndication:
		log.Printf("DEBUG: Detected TraceFailureIndication")
		ies = extractTraceFailureIndicationIEs(packet)
	case C.InitiatingMessage__value_PR_DeactivateTrace:
		log.Printf("DEBUG: Detected DeactivateTrace")
		ies = extractDeactivateTraceIEs(packet)
	case C.InitiatingMessage__value_PR_LocationReportingControl:
		log.Printf("DEBUG: Detected LocationReportingControl")
		ies = extractLocationReportingControlIEs(packet)
	case C.InitiatingMessage__value_PR_LocationReportingFailureIndication:
		log.Printf("DEBUG: Detected LocationReportingFailureIndication")
		ies = extractLocationReportingFailureIndicationIEs(packet)
	case C.InitiatingMessage__value_PR_LocationReport:
		log.Printf("DEBUG: Detected LocationReport")
		ies = extractLocationReportIEs(packet)
	case C.InitiatingMessage__value_PR_UEContextReleaseRequest:
		ies = extractUEContextReleaseRequestIEs(packet)
	case C.InitiatingMessage__value_PR_E_RABSetupRequest:
		ies = extractERABSetupRequestIEs(packet)
	case C.InitiatingMessage__value_PR_InitialContextSetupRequest:
		ies = extractInitialContextSetupRequestIEs(packet)
	case C.InitiatingMessage__value_PR_Reset:
		ies = extractResetIEs(packet)
	case C.InitiatingMessage__value_PR_S1SetupRequest:
		ies = extractS1SetupRequestIEs(packet)
	case C.InitiatingMessage__value_PR_DownlinkNASTransport:
		log.Printf("DEBUG: Detected DownlinkNASTransport via dedicated case - calling extractDownlinkNASTransportIEs")
		ies = extractDownlinkNASTransportIEs(packet)
	case C.InitiatingMessage__value_PR_HandoverRequired:
		ies = extractHandoverRequiredIEs(packet)
	case C.InitiatingMessage__value_PR_UECapabilityInfoIndication:
		ies = extractUECapabilityInfoIndicationIEs(packet)
	default:
		// For unsupported message types, try enhanced extraction
		log.Printf("DEBUG: extractInitiatingMessageIEs default case - msg.value.present: %d, messageType: %d, procCode: %d", msg.value.present, messageType, procCode)
		ies = extractEnhancedIEs(packet, messageType, int(procCode))
	}

	return ies
}

func extractSuccessfulOutcomeIEs(packet unsafe.Pointer, messageType int) []*InformationElement {
	var ies []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	if pdu.present != C.S1AP_PDU_PR_successfulOutcome {
		return ies
	}

	msg := *(**C.SuccessfulOutcome_t)(unsafe.Pointer(&pdu.choice))
	
	log.Printf("DEBUG: SuccessfulOutcome - procedure code: %d, messageType: %d", msg.procedureCode, messageType)

	// Use procedure code to determine message type since the ASN.1 constants may not be available
	switch msg.procedureCode {
	case 23: // UEContextRelease
		log.Printf("DEBUG: Calling extractUEContextReleaseCompleteIEs for procedure code 23")
		ies = extractUEContextReleaseCompleteIEs(packet)
	case 5: // E-RABSetup
		ies = extractERABSetupResponseIEs(packet)
	case 17: // S1Setup
		ies = extractS1SetupResponseIEs(packet)
	case 9: // InitialContextSetup
		ies = extractInitialContextSetupResponseIEs(packet)
	case 25: // UEContextModification
		ies = extractUEContextModificationResponseIEs(packet)
	case 0: // HandoverPreparation
		ies = extractHandoverCommandIEs(packet)
	default:
		log.Printf("DEBUG: SuccessfulOutcome default case - procedure code: %d", msg.procedureCode)
		// For unsupported successful outcome types, try generic extraction
		ies = extractGenericIEs(packet, messageType)
	}

	return ies
}

func extractUnsuccessfulOutcomeIEs(packet unsafe.Pointer, messageType int) []*InformationElement {
	var ies []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	if pdu.present != C.S1AP_PDU_PR_unsuccessfulOutcome {
		return ies
	}

	msg := *(**C.UnsuccessfulOutcome_t)(unsafe.Pointer(&pdu.choice))

	// Switch based on message type to extract IEs appropriately
	switch msg.value.present {
	case C.UnsuccessfulOutcome__value_PR_S1SetupFailure:
		ies = extractS1SetupFailureIEs(packet)
	case C.UnsuccessfulOutcome__value_PR_InitialContextSetupFailure:
		ies = extractInitialContextSetupFailureIEs(packet)
	case C.UnsuccessfulOutcome__value_PR_UEContextModificationFailure:
		ies = extractUEContextModificationFailureIEs(packet)
	default:
		// For unsupported unsuccessful outcome types, try generic extraction
		ies = extractGenericIEs(packet, messageType)
	}

	return ies
}

// Helper function to extract IEs from InitialUEMessage
func extractInitialUEMessageIEs(packet unsafe.Pointer) []*InformationElement {
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.InitialUEMessage_t)(unsafe.Pointer(&msg.value.choice))

	log.Printf("DEBUG: InitialUEMessage extracting IEs, protocolIEs.list.count: %d", val.protocolIEs.list.count)

	var ies []*C.InitialUEMessage_IEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	log.Printf("DEBUG: InitialUEMessage got %d IEs in slice", len(ies))

	for i, ie := range ies {
		if ie == nil {
			log.Printf("DEBUG: InitialUEMessage IE[%d] is nil, skipping", i)
			continue
		}

		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		log.Printf("DEBUG: InitialUEMessage IE[%d] - ID: %d, Name: %s, Present: %d", i, ie.id, ieStruct.Name, ie.value.present)

		// Use the value present enum instead of the ID, with correct pointer casting
		switch ie.value.present {
		case C.InitialUEMessage_IEs__value_PR_ENB_UE_S1AP_ID:
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice[0]))
			ieStruct.Value = int32(*enb_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*enb_id))
			log.Printf("DEBUG: InitialUEMessage extracted eNB_UE_S1AP_ID: %d", int32(*enb_id))
		case C.InitialUEMessage_IEs__value_PR_NAS_PDU:
			nas_pdu := (*C.NAS_PDU_t)(unsafe.Pointer(&ie.value.choice[0]))
			hexData := extractOctetString(nas_pdu)
			ieStruct.Value = fmt.Sprintf("NAS_PDU(%d bytes)", nas_pdu.size)
			ieStruct.RawValue = hexData
			log.Printf("DEBUG: InitialUEMessage extracted NAS_PDU: %d bytes", nas_pdu.size)
		case C.InitialUEMessage_IEs__value_PR_TAI:
			tai := (*C.TAI_t)(unsafe.Pointer(&ie.value.choice[0]))
			taiValue, taiRaw := extractTAI(unsafe.Pointer(tai))
			ieStruct.Value = taiValue
			ieStruct.RawValue = taiRaw
			log.Printf("DEBUG: InitialUEMessage extracted TAI: %s (raw: %s)", taiValue, taiRaw)
		case C.InitialUEMessage_IEs__value_PR_EUTRAN_CGI:
			eutran_cgi := (*C.EUTRAN_CGI_t)(unsafe.Pointer(&ie.value.choice[0]))
			plmnHex := extractGenericOctetString(&eutran_cgi.pLMNidentity)
			// Cell ID est un BIT STRING, pas un OCTET STRING
			cellIdBytes := C.GoBytes(unsafe.Pointer(eutran_cgi.cell_ID.buf), C.int(eutran_cgi.cell_ID.size))
			cellIdHex := fmt.Sprintf("%x", cellIdBytes)
			ieStruct.Value = fmt.Sprintf("EUTRAN_CGI(PLMN:%s, CellID:%s)", plmnHex[:6], cellIdHex[:8])
			ieStruct.RawValue = plmnHex + cellIdHex
			log.Printf("DEBUG: InitialUEMessage extracted EUTRAN_CGI: %s", ieStruct.Value)
		case C.InitialUEMessage_IEs__value_PR_RRC_Establishment_Cause:
			rrc_cause := (*C.RRC_Establishment_Cause_t)(unsafe.Pointer(&ie.value.choice[0]))
			causeValue := int32(*rrc_cause)
			causeName := getRRCEstablishmentCauseName(causeValue)
			ieStruct.Value = fmt.Sprintf("RRC_Cause(%s)", causeName)
			ieStruct.RawValue = fmt.Sprintf("%d", causeValue)
			log.Printf("DEBUG: InitialUEMessage extracted RRC_Establishment_Cause: %s", ieStruct.Value)
		case C.InitialUEMessage_IEs__value_PR_S_TMSI:
			s_tmsi := (*C.S_TMSI_t)(unsafe.Pointer(&ie.value.choice[0]))
			mmecHex := extractGenericOctetString(&s_tmsi.mMEC)
			mtmsiHex := extractGenericOctetString(&s_tmsi.m_TMSI)
			
			// Handle potential empty data
			var mmecStr, mtmsiStr string
			if len(mmecHex) >= 2 {
				mmecStr = mmecHex[:2]
			} else {
				mmecStr = mmecHex
			}
			if len(mtmsiHex) >= 11 { // "xx xx xx xx" format = 11 chars
				mtmsiStr = mtmsiHex[:11]
			} else {
				mtmsiStr = mtmsiHex
			}
			
			ieStruct.Value = fmt.Sprintf("S_TMSI(MMEC:%s, M-TMSI:%s)", mmecStr, mtmsiStr)
			ieStruct.RawValue = mmecHex + " " + mtmsiHex
			log.Printf("DEBUG: InitialUEMessage extracted S_TMSI: %s", ieStruct.Value)
		case C.InitialUEMessage_IEs__value_PR_GUMMEIType:
			gummei_type := (*C.GUMMEIType_t)(unsafe.Pointer(&ie.value.choice[0]))
			typeValue := int32(*gummei_type)
			var typeName string
			switch typeValue {
			case 0:
				typeName = "native"
			case 1:
				typeName = "mapped"
			default:
				typeName = "unknown"
			}
			ieStruct.Value = fmt.Sprintf("GUMMEIType(%s)", typeName)
			ieStruct.RawValue = fmt.Sprintf("%d", typeValue)
			log.Printf("DEBUG: InitialUEMessage extracted GUMMEIType: %s", ieStruct.Value)
		case C.InitialUEMessage_IEs__value_PR_CSG_Id:
			csg_id := (*C.CSG_Id_t)(unsafe.Pointer(&ie.value.choice[0]))
			csgBytes := C.GoBytes(unsafe.Pointer(csg_id.buf), C.int(csg_id.size))
			csgHex := fmt.Sprintf("%x", csgBytes)
			ieStruct.Value = fmt.Sprintf("CSG_Id(%s)", csgHex[:8])
			ieStruct.RawValue = csgHex
			log.Printf("DEBUG: InitialUEMessage extracted CSG_Id: %s", ieStruct.Value)
		case C.InitialUEMessage_IEs__value_PR_GUMMEI:
			gummei := (*C.GUMMEI_t)(unsafe.Pointer(&ie.value.choice[0]))
			plmnHex := extractOctetString(&gummei.pLMN_Identity)
			mmegi := extractOctetString(&gummei.mME_Group_ID)
			mmec := extractOctetString(&gummei.mME_Code)
			ieStruct.Value = fmt.Sprintf("GUMMEI(PLMN:%s, MMEGI:%s, MMEC:%s)", plmnHex[:6], mmegi[:4], mmec[:2])
			ieStruct.RawValue = plmnHex + mmegi + mmec
			log.Printf("DEBUG: InitialUEMessage extracted GUMMEI: %s", ieStruct.Value)
		case C.InitialUEMessage_IEs__value_PR_CellAccessMode:
			access_mode := (*C.CellAccessMode_t)(unsafe.Pointer(&ie.value.choice[0]))
			modeValue := int32(*access_mode)
			var modeName string
			switch modeValue {
			case 0:
				modeName = "hybrid"
			case 1:
				modeName = "closed"
			default:
				modeName = "unknown"
			}
			ieStruct.Value = fmt.Sprintf("CellAccessMode(%s)", modeName)
			ieStruct.RawValue = fmt.Sprintf("%d", modeValue)
			log.Printf("DEBUG: InitialUEMessage extracted CellAccessMode: %s", ieStruct.Value)
		case C.InitialUEMessage_IEs__value_PR_TransportLayerAddress:
			tla := (*C.TransportLayerAddress_t)(unsafe.Pointer(&ie.value.choice[0]))
			tlaBytes := C.GoBytes(unsafe.Pointer(tla.buf), C.int(tla.size))
			if len(tlaBytes) >= 4 {
				ip := net.IPv4(tlaBytes[0], tlaBytes[1], tlaBytes[2], tlaBytes[3])
				ieStruct.Value = fmt.Sprintf("TransportLayerAddress(%s)", ip.String())
			} else {
				ieStruct.Value = fmt.Sprintf("TransportLayerAddress(%x)", tlaBytes)
			}
			ieStruct.RawValue = fmt.Sprintf("%x", tlaBytes)
			log.Printf("DEBUG: InitialUEMessage extracted TransportLayerAddress: %s", ieStruct.Value)
		case C.InitialUEMessage_IEs__value_PR_RelayNode_Indicator:
			relay_indicator := (*C.RelayNode_Indicator_t)(unsafe.Pointer(&ie.value.choice[0]))
			indicatorValue := int32(*relay_indicator)
			var indicatorName string
			switch indicatorValue {
			case 0:
				indicatorName = "true"
			default:
				indicatorName = "false"
			}
			ieStruct.Value = fmt.Sprintf("RelayNode_Indicator(%s)", indicatorName)
			ieStruct.RawValue = fmt.Sprintf("%d", indicatorValue)
			log.Printf("DEBUG: InitialUEMessage extracted RelayNode_Indicator: %s", ieStruct.Value)
		default:
			// Gestion générique pour les IEs non supportés spécifiquement
			ieStruct.Value = "Unknown"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present (PR=%d)", ie.id, ie.value.present)
			log.Printf("DEBUG: InitialUEMessage unknown IE ID: %d, present: %d, name: %s", ie.id, ie.value.present, ieStruct.Name)
			
			// Essayer d'extraire des données brutes si possible
			if ie.value.present > 0 {
				// Tentative d'extraction de données brutes générique
				switch ie.id {
				case C.ProtocolIE_ID_id_LHN_ID, C.ProtocolIE_ID_id_MME_Group_ID, C.ProtocolIE_ID_id_UE_Usage_Type:
					// Pour ces IEs, essayer d'extraire comme OCTET STRING
					if ie.value.present < 20 { // Protection contre les valeurs aberrantes
						octetPtr := (*C.OCTET_STRING_t)(unsafe.Pointer(&ie.value.choice[0]))
						if octetPtr != nil && octetPtr.size > 0 && octetPtr.size < 256 {
							rawData := extractOctetString(octetPtr)
							ieStruct.RawValue = rawData
							ieStruct.Value = fmt.Sprintf("Data(%d bytes)", octetPtr.size)
							log.Printf("DEBUG: InitialUEMessage extracted generic OCTET_STRING for IE %d: %d bytes", ie.id, octetPtr.size)
						}
					}
				default:
					// Pour d'autres IEs, essayer d'extraire comme INTEGER
					if ie.value.present < 20 { // Protection contre les valeurs aberrantes
						intPtr := (*C.long)(unsafe.Pointer(&ie.value.choice[0]))
						if intPtr != nil {
							ieStruct.RawValue = fmt.Sprintf("%d", *intPtr)
							ieStruct.Value = fmt.Sprintf("Value(%d)", *intPtr)
							log.Printf("DEBUG: InitialUEMessage extracted generic INTEGER for IE %d: %d", ie.id, *intPtr)
						}
					}
				}
			}
		}

		result = append(result, ieStruct)
	}

	log.Printf("DEBUG: InitialUEMessage extraction completed with %d IEs", len(result))
	
	return result
}

// Helper function to extract IEs from UplinkNASTransport
func extractUplinkNASTransportIEs(packet unsafe.Pointer) []*InformationElement {
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.UplinkNASTransport_t)(unsafe.Pointer(&msg.value.choice))

	log.Printf("DEBUG: UplinkNASTransport extracting IEs, protocolIEs.list.count: %d", val.protocolIEs.list.count)

	var ies []*C.UplinkNASTransport_IEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	log.Printf("DEBUG: UplinkNASTransport got %d IEs in slice", len(ies))

	for i, ie := range ies {
		if ie == nil {
			log.Printf("DEBUG: UplinkNASTransport IE[%d] is nil, skipping", i)
			continue
		}

		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		log.Printf("DEBUG: UplinkNASTransport IE[%d] - ID: %d, Name: %s, Present: %d", i, ie.id, ieStruct.Name, ie.value.present)

		// Use ID-based switching with proper union member access
		switch int(ie.id) {
		case 0: // id_MME_UE_S1AP_ID
			if ie.value.present == C.UplinkNASTransport_IEs__value_PR_MME_UE_S1AP_ID {
				mme_id := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice[0]))
				ieStruct.Value = int32(*mme_id)
				ieStruct.RawValue = fmt.Sprintf("%d", int32(*mme_id))
				log.Printf("DEBUG: UplinkNASTransport extracted MME_UE_S1AP_ID: %d", int32(*mme_id))
			} else {
				ieStruct.Value = "Extraction Error"
				ieStruct.RawValue = fmt.Sprintf("Expected PR_MME_UE_S1AP_ID(%d), got %d", C.UplinkNASTransport_IEs__value_PR_MME_UE_S1AP_ID, ie.value.present)
			}
		case 8: // id_eNB_UE_S1AP_ID
			if ie.value.present == C.UplinkNASTransport_IEs__value_PR_ENB_UE_S1AP_ID {
				enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice[0]))
				ieStruct.Value = int32(*enb_id)
				ieStruct.RawValue = fmt.Sprintf("%d", int32(*enb_id))
				log.Printf("DEBUG: UplinkNASTransport extracted eNB_UE_S1AP_ID: %d", int32(*enb_id))
			} else {
				ieStruct.Value = "Extraction Error"
				ieStruct.RawValue = fmt.Sprintf("Expected PR_ENB_UE_S1AP_ID(%d), got %d", C.UplinkNASTransport_IEs__value_PR_ENB_UE_S1AP_ID, ie.value.present)
			}
		case 26: // id_NAS_PDU
			if ie.value.present == C.UplinkNASTransport_IEs__value_PR_NAS_PDU {
				nas_pdu := (*C.NAS_PDU_t)(unsafe.Pointer(&ie.value.choice[0]))
				hexData := extractOctetString(nas_pdu)
				ieStruct.Value = fmt.Sprintf("NAS_PDU(%d bytes)", nas_pdu.size)
				ieStruct.RawValue = hexData
				log.Printf("DEBUG: UplinkNASTransport extracted NAS_PDU: %d bytes", nas_pdu.size)
			} else {
				ieStruct.Value = "Extraction Error"
				ieStruct.RawValue = fmt.Sprintf("Expected PR_NAS_PDU(%d), got %d", C.UplinkNASTransport_IEs__value_PR_NAS_PDU, ie.value.present)
			}
		case 100: // id_EUTRAN_CGI
			if ie.value.present == C.UplinkNASTransport_IEs__value_PR_EUTRAN_CGI {
				eutran_cgi := (*C.EUTRAN_CGI_t)(unsafe.Pointer(&ie.value.choice[0]))
				// Utiliser extractGenericOctetString pour pLMNidentity
				plmnHex := extractGenericOctetString(&eutran_cgi.pLMNidentity)
				cellIdBytes := C.GoBytes(unsafe.Pointer(eutran_cgi.cell_ID.buf), C.int(eutran_cgi.cell_ID.size))
				cellIdHex := fmt.Sprintf("%x", cellIdBytes)
				ieStruct.Value = fmt.Sprintf("EUTRAN_CGI(PLMN:%s, CellID:%s)", plmnHex[:6], cellIdHex[:8])
				ieStruct.RawValue = plmnHex + cellIdHex
				log.Printf("DEBUG: UplinkNASTransport extracted EUTRAN_CGI: %s", ieStruct.Value)
			} else {
				ieStruct.Value = "Extraction Error"
				ieStruct.RawValue = fmt.Sprintf("Expected PR_EUTRAN_CGI(%d), got %d", C.UplinkNASTransport_IEs__value_PR_EUTRAN_CGI, ie.value.present)
			}
		case 67: // id_TAI
			if ie.value.present == C.UplinkNASTransport_IEs__value_PR_TAI {
				tai := (*C.TAI_t)(unsafe.Pointer(&ie.value.choice[0]))
				// Utiliser notre fonction extractTAI améliorée
				taiValue, taiRaw := extractTAI(unsafe.Pointer(tai))
				ieStruct.Value = taiValue
				ieStruct.RawValue = taiRaw
				log.Printf("DEBUG: UplinkNASTransport extracted TAI: %s (raw: %s)", taiValue, taiRaw)
			} else {
				ieStruct.Value = "Extraction Error"
				ieStruct.RawValue = fmt.Sprintf("Expected PR_TAI(%d), got %d", C.UplinkNASTransport_IEs__value_PR_TAI, ie.value.present)
			}
		default:
			ieStruct.Value = "Unknown IE"
			ieStruct.RawValue = fmt.Sprintf("IE_ID_%d present_type=%d", ie.id, ie.value.present)
			log.Printf("DEBUG: UplinkNASTransport unknown IE ID: %d, present: %d", ie.id, ie.value.present)
		}

		result = append(result, ieStruct)
	}

	log.Printf("DEBUG: UplinkNASTransport extraction completed with %d IEs", len(result))

	return result
}

// Helper function to extract IEs from UEContextReleaseRequest
func extractUEContextReleaseRequestIEs(packet unsafe.Pointer) []*InformationElement {
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.UEContextReleaseRequest_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.UEContextReleaseRequest_IEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	for _, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		switch ie.id {
		case C.ProtocolIE_ID_id_MME_UE_S1AP_ID:
			mme_id := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*mme_id)
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*enb_id)
		case C.ProtocolIE_ID_id_Cause:
			ieStruct.Value = "Cause"
			ieStruct.RawValue = "Cause structure present"
		default:
			ieStruct.Value = "Unknown"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
		}

		result = append(result, ieStruct)
	}

	return result
}

// Helper function to extract IEs from E-RABSetupRequest
func extractERABSetupRequestIEs(packet unsafe.Pointer) []*InformationElement {
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.E_RABSetupRequest_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.E_RABSetupRequestIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	for _, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		switch ie.id {
		case C.ProtocolIE_ID_id_MME_UE_S1AP_ID:
			mme_id := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*mme_id)
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*enb_id)
		case C.ProtocolIE_ID_id_E_RABToBeSetupListBearerSUReq:
			ieStruct.Value = "E_RABToBeSetupListBearerSUReq"
			ieStruct.RawValue = "E_RAB list present"
		case C.ProtocolIE_ID_id_uEaggregateMaximumBitrate:
			ieStruct.Value = "UEAggregateMaximumBitrate"
			ieStruct.RawValue = "UEAggregateMaximumBitrate present"
		default:
			ieStruct.Value = "Unknown"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
		}

		result = append(result, ieStruct)
	}

	return result
}

// Helper function to extract IEs from InitialContextSetupRequest
func extractInitialContextSetupRequestIEs(packet unsafe.Pointer) []*InformationElement {
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.InitialContextSetupRequest_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.InitialContextSetupRequestIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	for _, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		switch ie.id {
		case C.ProtocolIE_ID_id_MME_UE_S1AP_ID:
			mme_id := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*mme_id)
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*enb_id)
		case C.ProtocolIE_ID_id_uEaggregateMaximumBitrate:
			ieStruct.Value = "UEAggregateMaximumBitrate"
			ieStruct.RawValue = "UEAggregateMaximumBitrate present"
		case C.ProtocolIE_ID_id_E_RABToBeSetupListCtxtSUReq:
			ieStruct.Value = "E_RABToBeSetupListCtxtSUReq"
			ieStruct.RawValue = "E_RAB context setup list present"
		case C.ProtocolIE_ID_id_UESecurityCapabilities:
			ieStruct.Value = "UESecurityCapabilities"
			ieStruct.RawValue = "UESecurityCapabilities present"
		case C.ProtocolIE_ID_id_SecurityKey:
			ieStruct.Value = "SecurityKey"
			ieStruct.RawValue = "SecurityKey present"
		default:
			ieStruct.Value = "Unknown"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
		}

		result = append(result, ieStruct)
	}

	return result
}

// Helper function to extract IEs from Reset
func extractResetIEs(packet unsafe.Pointer) []*InformationElement {
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.Reset_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.ResetIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	for _, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		switch ie.id {
		case C.ProtocolIE_ID_id_Cause:
			ieStruct.Value = "Cause"
			ieStruct.RawValue = "Cause structure present"
		case C.ProtocolIE_ID_id_ResetType:
			ieStruct.Value = "ResetType"
			ieStruct.RawValue = "ResetType present"
		default:
			ieStruct.Value = "Unknown"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
		}

		result = append(result, ieStruct)
	}

	return result
}

// Helper function to extract IEs from S1SetupRequest
func extractS1SetupRequestIEs(packet unsafe.Pointer) []*InformationElement {
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.S1SetupRequest_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.S1SetupRequestIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	for _, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		switch ie.id {
		case C.ProtocolIE_ID_id_Global_ENB_ID:
			ieStruct.Value = "Global_ENB_ID"
			ieStruct.RawValue = "Global_ENB_ID present"
		case C.ProtocolIE_ID_id_eNBname:
			ieStruct.Value = "eNBname"
			ieStruct.RawValue = "eNBname present"
		case C.ProtocolIE_ID_id_SupportedTAs:
			ieStruct.Value = "SupportedTAs"
			ieStruct.RawValue = "SupportedTAs list present"
		case C.ProtocolIE_ID_id_DefaultPagingDRX:
			ieStruct.Value = "DefaultPagingDRX"
			ieStruct.RawValue = "DefaultPagingDRX present"
		default:
			ieStruct.Value = "Unknown"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
		}

		result = append(result, ieStruct)
	}

	return result
}

// Helper function to extract IEs from DownlinkNASTransport
func extractDownlinkNASTransportIEs(packet unsafe.Pointer) []*InformationElement {
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.DownlinkNASTransport_t)(unsafe.Pointer(&msg.value.choice))

	log.Printf("DEBUG: DownlinkNASTransport extracting IEs, protocolIEs.list.count: %d", val.protocolIEs.list.count)

	// Use the correct structure: DownlinkNASTransport_IEs_t
	var ies []*C.DownlinkNASTransport_IEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	log.Printf("DEBUG: DownlinkNASTransport got %d IEs in slice", len(ies))

	for i, ie := range ies {
		if ie == nil {
			log.Printf("DEBUG: DownlinkNASTransport IE[%d] is nil, skipping", i)
			continue
		}

		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		log.Printf("DEBUG: DownlinkNASTransport IE[%d] - ID: %d, Name: %s, Present: %d", i, ie.id, ieStruct.Name, ie.value.present)

		// Use the value present enum instead of the ID, with correct pointer casting
		switch ie.value.present {
		case C.DownlinkNASTransport_IEs__value_PR_MME_UE_S1AP_ID:
			// Cast the choice buffer to the appropriate type
			mme_id := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice[0]))
			ieStruct.Value = int32(*mme_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*mme_id))
			log.Printf("DEBUG: DownlinkNASTransport extracted MME_UE_S1AP_ID: %d", int32(*mme_id))
		case C.DownlinkNASTransport_IEs__value_PR_ENB_UE_S1AP_ID:
			// Cast the choice buffer to the appropriate type
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice[0]))
			ieStruct.Value = int32(*enb_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*enb_id))
			log.Printf("DEBUG: DownlinkNASTransport extracted eNB_UE_S1AP_ID: %d", int32(*enb_id))
		case C.DownlinkNASTransport_IEs__value_PR_NAS_PDU:
			// Cast the choice buffer to the appropriate type
			nas_pdu := (*C.NAS_PDU_t)(unsafe.Pointer(&ie.value.choice[0]))
			hexData := extractOctetString(nas_pdu)
			ieStruct.Value = fmt.Sprintf("NAS_PDU(%d bytes)", nas_pdu.size)
			ieStruct.RawValue = hexData
			log.Printf("DEBUG: DownlinkNASTransport extracted NAS_PDU: %d bytes", nas_pdu.size)
		case C.DownlinkNASTransport_IEs__value_PR_UERadioCapability:
			// Cast the choice buffer to the appropriate type
			ue_radio_cap := (*C.UERadioCapability_t)(unsafe.Pointer(&ie.value.choice[0]))
			hexData := extractOctetString(ue_radio_cap)
			ieStruct.Value = fmt.Sprintf("UERadioCapability(%d bytes)", ue_radio_cap.size)
			ieStruct.RawValue = hexData
			log.Printf("DEBUG: DownlinkNASTransport extracted UERadioCapability: %d bytes", ue_radio_cap.size)
		default:
			ieStruct.Value = "Unknown"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present (PR=%d)", ie.id, ie.value.present)
			log.Printf("DEBUG: DownlinkNASTransport unknown IE ID: %d, present: %d", ie.id, ie.value.present)
		}

		result = append(result, ieStruct)
	}

	log.Printf("DEBUG: DownlinkNASTransport extraction completed with %d IEs", len(result))
	
	return result
}

// Enhanced extraction functions for specific message types using tshark insights

func extractPagingIEs(packet unsafe.Pointer) []*InformationElement {
	log.Printf("DEBUG: Enhanced Paging IE extraction started")
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.Paging_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.PagingIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	log.Printf("DEBUG: Paging IE count: %d", len(ies))

	for _, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		log.Printf("DEBUG: Processing Paging IE - ID: %d, Name: %s", ie.id, ieStruct.Name)

		switch ie.id {
		case C.ProtocolIE_ID_id_UEIdentityIndexValue:
			// Extract UE Identity Index Value (10-bit value)
			bitString := (*C.BIT_STRING_t)(unsafe.Pointer(&ie.value.choice))
			if bitString.buf != nil && bitString.size > 0 {
				data := C.GoBytes(unsafe.Pointer(bitString.buf), C.int(bitString.size))
				hexStr := hex.EncodeToString(data)
				
				// Calculate decimal value from 10-bit field
				var value uint16 = 0
				if len(data) >= 2 {
					// Extract 10 bits (most significant bits of first two bytes)
					value = (uint16(data[0]) << 2) | (uint16(data[1]) >> 6)
					ieStruct.Value = value
					ieStruct.RawValue = fmt.Sprintf("0x%s [decimal=%d, bits=%010b]", hexStr, value, value)
				} else if len(data) == 1 {
					value = uint16(data[0]) >> 6 // Only 2 bits if single byte
					ieStruct.Value = value
					ieStruct.RawValue = fmt.Sprintf("0x%s [decimal=%d]", hexStr, value)
				} else {
					ieStruct.Value = hexStr
					ieStruct.RawValue = "0x" + hexStr
				}
				log.Printf("DEBUG: UEIdentityIndexValue - hex: %s, decimal: %d", hexStr, value)
			} else {
				ieStruct.Value = "Invalid"
				ieStruct.RawValue = "Empty or null buffer"
			}

		case C.ProtocolIE_ID_id_UEPagingID:
			// Extract UE Paging ID (S-TMSI or IMSI) with detailed decoding
			pagingID := (*C.UEPagingID_t)(unsafe.Pointer(&ie.value.choice))
			switch pagingID.present {
			case C.UEPagingID_PR_s_TMSI:
				// Extract S-TMSI with detailed MMEC and M-TMSI decoding
				// Note: In UEPagingID, s_TMSI is a pointer unlike in InitialUEMessage
				// Dereference the pointer to get the actual S-TMSI structure
				s_tmsi := *(**C.S_TMSI_t)(unsafe.Pointer(&pagingID.choice[0]))
				if s_tmsi != nil {
					mmecHex := extractGenericOctetString(&s_tmsi.mMEC)
					mtmsiHex := extractGenericOctetString(&s_tmsi.m_TMSI)
					
					// Handle potential empty data
					var mmecStr, mtmsiStr string
					if len(mmecHex) >= 2 {
						mmecStr = mmecHex[:2]
					} else {
						mmecStr = mmecHex
					}
					if len(mtmsiHex) >= 11 { // "xx xx xx xx" format = 11 chars
						mtmsiStr = mtmsiHex[:11]
					} else {
						mtmsiStr = mtmsiHex
					}
					
					ieStruct.Value = fmt.Sprintf("S_TMSI(MMEC:%s, M-TMSI:%s)", mmecStr, mtmsiStr)
					ieStruct.RawValue = mmecHex + " " + mtmsiHex
					log.Printf("DEBUG: UEPagingID - S-TMSI decoded: MMEC=%s, M-TMSI=%s", mmecStr, mtmsiStr)
				} else {
					ieStruct.Value = "S-TMSI(null)"
					ieStruct.RawValue = "S-TMSI pointer is null"
					log.Printf("DEBUG: UEPagingID - S-TMSI pointer is null")
				}
			case C.UEPagingID_PR_iMSI:
				// Extract IMSI with BCD decoding
				imsi_ptr := (*C.IMSI_t)(unsafe.Pointer(&pagingID.choice[0]))
				if imsi_ptr.buf != nil && imsi_ptr.size > 0 {
					imsiData := C.GoBytes(unsafe.Pointer(imsi_ptr.buf), C.int(imsi_ptr.size))
					imsiStr := decodeIMSI(imsiData)
					ieStruct.Value = fmt.Sprintf("IMSI(%s)", imsiStr)
					ieStruct.RawValue = hex.EncodeToString(imsiData)
					log.Printf("DEBUG: UEPagingID - IMSI decoded: %s", imsiStr)
				} else {
					ieStruct.Value = "IMSI(Invalid)"
					ieStruct.RawValue = "Empty IMSI buffer"
				}
			default:
				ieStruct.Value = "Unknown"
				ieStruct.RawValue = fmt.Sprintf("UEPagingID type %d", pagingID.present)
			}

		case C.ProtocolIE_ID_id_CNDomain:
			// Extract CN Domain
			cnDomain := (*C.CNDomain_t)(unsafe.Pointer(&ie.value.choice))
			domainStr := "Unknown"
			switch *cnDomain {
			case C.CNDomain_ps:
				domainStr = "PS (Packet Switched)"
			case C.CNDomain_cs:
				domainStr = "CS (Circuit Switched)"
			default:
				domainStr = fmt.Sprintf("Unknown (%d)", int(*cnDomain))
			}
			ieStruct.Value = domainStr
			ieStruct.RawValue = fmt.Sprintf("%d", int(*cnDomain))
			log.Printf("DEBUG: CNDomain: %s", domainStr)

		case C.ProtocolIE_ID_id_TAIList:
			// Extract TAI List avec notre fonction améliorée
			taiList := (*C.TAIList_t)(unsafe.Pointer(&ie.value.choice))
			taiValue, taiRaw := extractTAIList(unsafe.Pointer(taiList))
			ieStruct.Value = taiValue
			ieStruct.RawValue = taiRaw
			log.Printf("DEBUG: TAIList decoded: %s (raw: %s)", taiValue, taiRaw)

		case C.ProtocolIE_ID_id_pagingDRX:
			// Extract Paging DRX
			pagingDRX := (*C.PagingDRX_t)(unsafe.Pointer(&ie.value.choice))
			var drxStr string
			switch *pagingDRX {
			case C.PagingDRX_v32:
				drxStr = "v32 (32 subframes)"
			case C.PagingDRX_v64:
				drxStr = "v64 (64 subframes)"
			case C.PagingDRX_v128:
				drxStr = "v128 (128 subframes)"
			case C.PagingDRX_v256:
				drxStr = "v256 (256 subframes)"
			default:
				drxStr = fmt.Sprintf("Unknown (%d)", int(*pagingDRX))
			}
			ieStruct.Value = drxStr
			ieStruct.RawValue = fmt.Sprintf("%d", int(*pagingDRX))

		case C.ProtocolIE_ID_id_PagingPriority:
			// Extract Paging Priority
			priority := (*C.PagingPriority_t)(unsafe.Pointer(&ie.value.choice))
			var priorityStr string
			switch *priority {
			case C.PagingPriority_priolevel1:
				priorityStr = "Level 1 (Highest)"
			case C.PagingPriority_priolevel2:
				priorityStr = "Level 2"
			case C.PagingPriority_priolevel3:
				priorityStr = "Level 3"
			case C.PagingPriority_priolevel4:
				priorityStr = "Level 4"
			case C.PagingPriority_priolevel5:
				priorityStr = "Level 5"
			case C.PagingPriority_priolevel6:
				priorityStr = "Level 6"
			case C.PagingPriority_priolevel7:
				priorityStr = "Level 7"
			case C.PagingPriority_priolevel8:
				priorityStr = "Level 8 (Lowest)"
			default:
				priorityStr = fmt.Sprintf("Unknown (%d)", int(*priority))
			}
			ieStruct.Value = priorityStr
			ieStruct.RawValue = fmt.Sprintf("%d", int(*priority))

		case 231: // C.ProtocolIE_ID_id_extended_UEIdentityIndexValue
			// Extract Extended UE Identity Index Value (14-bit value for NB-IoT)
			bitString := (*C.BIT_STRING_t)(unsafe.Pointer(&ie.value.choice))
			if bitString.buf != nil && bitString.size > 0 {
				data := C.GoBytes(unsafe.Pointer(bitString.buf), C.int(bitString.size))
				hexStr := hex.EncodeToString(data)
				
				// Calculate decimal value from 14-bit field for NB-IoT
				var value uint16 = 0
				if len(data) >= 2 {
					// Extract 14 bits from the data
					value = (uint16(data[0]) << 6) | (uint16(data[1]) >> 2)
					ieStruct.Value = value
					ieStruct.RawValue = fmt.Sprintf("0x%s [decimal=%d, bits=%014b]", hexStr, value, value)
				} else if len(data) == 1 {
					value = uint16(data[0]) >> 2 // Only 6 bits if single byte
					ieStruct.Value = value
					ieStruct.RawValue = fmt.Sprintf("0x%s [decimal=%d]", hexStr, value)
				} else {
					ieStruct.Value = hexStr
					ieStruct.RawValue = "0x" + hexStr
				}
				log.Printf("DEBUG: Extended UEIdentityIndexValue - hex: %s, decimal: %d (14-bit)", hexStr, value)
			} else {
				ieStruct.Value = "Invalid"
				ieStruct.RawValue = "Empty or null buffer"
			}

		case C.ProtocolIE_ID_id_Paging_eDRXInformation:
			// Extract Paging eDRX Information
			ieStruct.Value = "Paging eDRX Information"
			ieStruct.RawValue = "eDRX Information present"
			log.Printf("DEBUG: Paging eDRX Information detected")

		case C.ProtocolIE_ID_id_NB_IoT_DefaultPagingDRX:
			// Extract NB-IoT Default Paging DRX
			ieStruct.Value = "NB-IoT Default Paging DRX"
			ieStruct.RawValue = "NB-IoT DRX present"
			log.Printf("DEBUG: NB-IoT Default Paging DRX detected")

		case C.ProtocolIE_ID_id_NB_IoT_Paging_eDRXInformation:
			// Extract NB-IoT Paging eDRX Information
			ieStruct.Value = "NB-IoT Paging eDRX Information"
			ieStruct.RawValue = "NB-IoT eDRX Information present"
			log.Printf("DEBUG: NB-IoT Paging eDRX Information detected")

		case 244: // C.ProtocolIE_ID_id_NB_IoT_UEIdentityIndexValue
			// Extract NB-IoT UE Identity Index Value
			bitString := (*C.BIT_STRING_t)(unsafe.Pointer(&ie.value.choice))
			if bitString.buf != nil && bitString.size > 0 {
				data := C.GoBytes(unsafe.Pointer(bitString.buf), C.int(bitString.size))
				hexStr := hex.EncodeToString(data)
				
				// Calculate decimal value - NB-IoT specific
				var value uint16 = 0
				if len(data) >= 2 {
					value = binary.BigEndian.Uint16(data)
					ieStruct.Value = value
					ieStruct.RawValue = fmt.Sprintf("0x%s [decimal=%d, NB-IoT]", hexStr, value)
				} else if len(data) == 1 {
					value = uint16(data[0])
					ieStruct.Value = value
					ieStruct.RawValue = fmt.Sprintf("0x%s [decimal=%d, NB-IoT]", hexStr, value)
				} else {
					ieStruct.Value = hexStr
					ieStruct.RawValue = "0x" + hexStr
				}
				log.Printf("DEBUG: NB-IoT UEIdentityIndexValue - hex: %s, decimal: %d", hexStr, value)
			} else {
				ieStruct.Value = "Invalid"
				ieStruct.RawValue = "Empty or null buffer"
			}

		default:
			// Try generic extraction for unknown IEs
			ieStruct.Value = "Unknown IE"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
			log.Printf("DEBUG: Unknown Paging IE - ID: %d", ie.id)
		}

		result = append(result, ieStruct)
	}

	log.Printf("DEBUG: Paging IE extraction completed - %d IEs extracted", len(result))
	return result
}

func extractCellTrafficTraceIEs(packet unsafe.Pointer) []*InformationElement {
	log.Printf("DEBUG: Enhanced CellTrafficTrace IE extraction started")
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.CellTrafficTrace_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.CellTrafficTraceIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	log.Printf("DEBUG: CellTrafficTrace IE count: %d", len(ies))

	for _, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		log.Printf("DEBUG: Processing CellTrafficTrace IE - ID: %d, Name: %s", ie.id, ieStruct.Name)

		switch ie.id {
		case C.ProtocolIE_ID_id_MME_UE_S1AP_ID:
			mme_id := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*mme_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*mme_id))
			log.Printf("DEBUG: MME_UE_S1AP_ID: %d", int32(*mme_id))

		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*enb_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*enb_id))
			log.Printf("DEBUG: eNB_UE_S1AP_ID: %d", int32(*enb_id))

		case C.ProtocolIE_ID_id_E_UTRAN_Trace_ID:
			// Extract E-UTRAN Trace ID with detailed parsing
			traceID := (*C.E_UTRAN_Trace_ID_t)(unsafe.Pointer(&ie.value.choice))
			if traceID.buf != nil && traceID.size >= 8 {
				data := C.GoBytes(unsafe.Pointer(traceID.buf), C.int(traceID.size))
				hexStr := hex.EncodeToString(data)

				// Decode PLMN (first 3 bytes) and Trace ID (remaining 5 bytes)
				if len(data) >= 8 {
					mcc, mnc := decodePLMNIdentity(data[:3])
					traceRef := hex.EncodeToString(data[3:])
					
					ieStruct.Value = hexStr
					ieStruct.RawValue = fmt.Sprintf("PLMN: MCC=%s, MNC=%s, TraceRef=0x%s", mcc, mnc, traceRef)
					log.Printf("DEBUG: E_UTRAN_Trace_ID: MCC=%s, MNC=%s, TraceRef=%s", mcc, mnc, traceRef)
				} else {
					ieStruct.Value = hexStr
					ieStruct.RawValue = "0x" + hexStr
				}
			} else {
				ieStruct.Value = "Invalid"
				ieStruct.RawValue = "Empty or insufficient trace ID data"
			}

		case C.ProtocolIE_ID_id_EUTRAN_CGI:
			// Extract EUTRAN CGI with detailed cell identification
			cgi_ptr := unsafe.Pointer(&ie.value.choice)
			cgi := (*C.EUTRAN_CGI_t)(cgi_ptr)
			
			var mcc, mnc, cellID string
			
			// Extract PLMN identity
			if cgi.pLMNidentity.buf != nil && cgi.pLMNidentity.size >= 3 {
				plmnData := C.GoBytes(unsafe.Pointer(cgi.pLMNidentity.buf), C.int(cgi.pLMNidentity.size))
				mcc, mnc = decodePLMNIdentity(plmnData[:3])
			}
			
			// Extract Cell Identity (28 bits)
			if cgi.cell_ID.buf != nil && cgi.cell_ID.size >= 4 {
				cellData := C.GoBytes(unsafe.Pointer(cgi.cell_ID.buf), C.int(cgi.cell_ID.size))
				if len(cellData) >= 4 {
					// Cell ID is 28 bits, extract eNB ID (20 bits) and Cell ID (8 bits)
					cellValue := binary.BigEndian.Uint32(cellData) >> 4 // Remove padding bits
					enbID := cellValue >> 8
					cellLocal := cellValue & 0xFF
					cellID = fmt.Sprintf("0x%07x [eNB=%d, Cell=%d]", cellValue, enbID, cellLocal)
				}
			}
			
			ieStruct.Value = fmt.Sprintf("CGI: MCC=%s, MNC=%s", mcc, mnc)
			ieStruct.RawValue = fmt.Sprintf("EUTRAN-CGI: MCC=%s, MNC=%s, CellID=%s", mcc, mnc, cellID)
			log.Printf("DEBUG: EUTRAN_CGI: MCC=%s, MNC=%s, CellID=%s", mcc, mnc, cellID)

		case C.ProtocolIE_ID_id_TraceCollectionEntityIPAddress:
			// Extract Trace Collection Entity IP Address
			ipAddr := (*C.TransportLayerAddress_t)(unsafe.Pointer(&ie.value.choice))
			if ipAddr.buf != nil && ipAddr.size > 0 {
				data := C.GoBytes(unsafe.Pointer(ipAddr.buf), C.int(ipAddr.size))
				
				// Check if IPv4 (4 bytes) or IPv6 (16 bytes)
				if len(data) >= 4 {
					if len(data) == 4 {
						ip := net.IP(data)
						ieStruct.Value = ip.String()
						ieStruct.RawValue = fmt.Sprintf("IPv4: %s", ip.String())
					} else if len(data) >= 16 {
						ip := net.IP(data[:16])
						ieStruct.Value = ip.String()
						ieStruct.RawValue = fmt.Sprintf("IPv6: %s", ip.String())
					} else {
						hexStr := hex.EncodeToString(data)
						ieStruct.Value = hexStr
						ieStruct.RawValue = "0x" + hexStr
					}
				} else {
					ieStruct.Value = "Invalid IP"
					ieStruct.RawValue = "Insufficient IP address data"
				}
			} else {
				ieStruct.Value = "No IP"
				ieStruct.RawValue = "Empty IP address"
			}

		case C.ProtocolIE_ID_id_PrivacyIndicator:
			// Extract Privacy Indicator
			privacy := (*C.PrivacyIndicator_t)(unsafe.Pointer(&ie.value.choice))
			var privacyStr string
			switch *privacy {
			case C.PrivacyIndicator_immediate_MDT:
				privacyStr = "Immediate MDT"
			case C.PrivacyIndicator_logged_MDT:
				privacyStr = "Logged MDT"
			default:
				privacyStr = fmt.Sprintf("Unknown (%d)", int(*privacy))
			}
			ieStruct.Value = privacyStr
			ieStruct.RawValue = fmt.Sprintf("%d", int(*privacy))

		default:
			// Try generic extraction for unknown IEs
			ieStruct.Value = "Unknown IE"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
			log.Printf("DEBUG: Unknown CellTrafficTrace IE - ID: %d", ie.id)
		}

		result = append(result, ieStruct)
	}

	log.Printf("DEBUG: CellTrafficTrace IE extraction completed - %d IEs extracted", len(result))
	return result
}

// Generic IE extraction for unsupported message types
func extractGenericIEs(packet unsafe.Pointer, messageType int) []*InformationElement {
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	if pdu == nil {
		return result
	}

	log.Printf("DEBUG: Generic IE extraction started for messageType: %d", messageType)

	// Try to extract from different PDU types
	switch pdu.present {
	case C.S1AP_PDU_PR_initiatingMessage:
		msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
		if msg != nil {
			result = extractGenericInitiatingMessageIEs(packet, msg, messageType)
		}
	case C.S1AP_PDU_PR_successfulOutcome:
		msg := *(**C.SuccessfulOutcome_t)(unsafe.Pointer(&pdu.choice))
		if msg != nil {
			result = extractGenericSuccessfulOutcomeIEs(packet, msg, messageType)
		}
	case C.S1AP_PDU_PR_unsuccessfulOutcome:
		msg := *(**C.UnsuccessfulOutcome_t)(unsafe.Pointer(&pdu.choice))
		if msg != nil {
			result = extractGenericUnsuccessfulOutcomeIEs(packet, msg, messageType)
		}
	default:
		log.Printf("DEBUG: Unsupported PDU type in generic extraction: %d", pdu.present)
	}

	log.Printf("DEBUG: Generic extraction found %d IEs", len(result))
	return result
}

// Generic extraction for InitiatingMessage
func extractGenericInitiatingMessageIEs(packet unsafe.Pointer, msg *C.InitiatingMessage_t, messageType int) []*InformationElement {
	var result []*InformationElement

	// Try to access the protocolIEs list generically
	// Most S1AP messages have a similar structure with protocolIEs
	// We'll try to cast to common structures and extract IEs

	switch messageType {
	case 11: // DownlinkNASTransport
		return tryExtractDownlinkNASTransportGeneric(packet)
	case 18: // UEContextReleaseRequest  
		return tryExtractUEContextReleaseRequestGeneric(packet)
	case 9: // InitialContextSetupResponse (though this should be SuccessfulOutcome)
		return tryExtractInitialContextSetupResponseGeneric(packet)
	default:
		log.Printf("DEBUG: No specific generic extraction for messageType: %d", messageType)
	}

	return result
}

// Generic extraction for SuccessfulOutcome
func extractGenericSuccessfulOutcomeIEs(packet unsafe.Pointer, msg *C.SuccessfulOutcome_t, messageType int) []*InformationElement {
	var result []*InformationElement

	switch msg.procedureCode {
	case 9: // InitialContextSetupResponse
		return tryExtractInitialContextSetupResponseGeneric(packet)
	case 21: // UEContextModificationResponse
		return tryExtractUEContextModificationResponseGeneric(packet)
	default:
		log.Printf("DEBUG: No specific generic extraction for SuccessfulOutcome procedure: %d", msg.procedureCode)
	}

	return result
}

// Generic extraction for UnsuccessfulOutcome
func extractGenericUnsuccessfulOutcomeIEs(packet unsafe.Pointer, msg *C.UnsuccessfulOutcome_t, messageType int) []*InformationElement {
	var result []*InformationElement
	log.Printf("DEBUG: Generic UnsuccessfulOutcome extraction not implemented yet")
	return result
}

// Helper functions for specific message types using fallback extraction
func tryExtractDownlinkNASTransportGeneric(packet unsafe.Pointer) []*InformationElement {
	log.Printf("DEBUG: Trying generic DownlinkNASTransport extraction")
	
	// Use fallback extraction with likely payload
	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	
	// Try to get raw payload for fallback
	if msg != nil {
		return ExtractFallbackIEs(nil, 11) // DownlinkNASTransport procedure code
	}
	
	return []*InformationElement{}
}

func tryExtractUEContextReleaseRequestGeneric(packet unsafe.Pointer) []*InformationElement {
	log.Printf("DEBUG: Trying generic UEContextReleaseRequest extraction")
	return ExtractFallbackIEs(nil, 18) // UEContextReleaseRequest procedure code
}

func tryExtractInitialContextSetupResponseGeneric(packet unsafe.Pointer) []*InformationElement {
	log.Printf("DEBUG: Trying generic InitialContextSetupResponse extraction")
	return ExtractFallbackIEs(nil, 9) // InitialContextSetupResponse procedure code
}

func tryExtractUEContextModificationResponseGeneric(packet unsafe.Pointer) []*InformationElement {
	log.Printf("DEBUG: Trying generic UEContextModificationResponse extraction")
	return ExtractFallbackIEs(nil, 21) // UEContextModificationResponse procedure code
}

// Helper function to get RRC Establishment Cause name
func getRRCEstablishmentCauseName(cause int32) string {
	switch cause {
	case 0:
		return "emergency"
	case 1:
		return "highPriorityAccess"
	case 2:
		return "mt-Access"
	case 3:
		return "mo-Signalling"
	case 4:
		return "mo-Data"
	case 5:
		return "delayTolerantAccess"
	default:
		return "unknown"
	}
}

// Helper function to get criticality string
func getCriticalityString(criticality int) string {
	switch criticality {
	case 0:
		return "reject"
	case 1:
		return "ignore"
	case 2:
		return "notify"
	default:
		return "unknown"
	}
}

// Helper function to extract octet string data from OCTET_STRING_t
func extractGenericOctetString(octetString *C.OCTET_STRING_t) string {
	if octetString.size == 0 {
		return ""
	}

	var data []byte
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&data)))
	slice.Cap = (int)(octetString.size)
	slice.Len = (int)(octetString.size)
	slice.Data = uintptr(unsafe.Pointer(octetString.buf))

	result := ""
	for i, b := range data {
		if i > 0 {
			result += " "
		}
		result += fmt.Sprintf("%02x", b)
		if i >= 31 { // Limit output length
			result += "..."
			break
		}
	}

	return result
}

// Helper function to extract octet string data (existing function for NAS_PDU_t)
func extractOctetString(octetString *C.NAS_PDU_t) string {
	if octetString.size == 0 {
		return ""
	}

	var data []byte
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&data)))
	slice.Cap = (int)(octetString.size)
	slice.Len = (int)(octetString.size)
	slice.Data = uintptr(unsafe.Pointer(octetString.buf))

	result := ""
	for i, b := range data {
		if i > 0 {
			result += " "
		}
		result += fmt.Sprintf("%02x", b)
		if i >= 31 { // Limit output length
			result += "..."
			break
		}
	}

	return result
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
		// Handle successful outcome messages
		msg := *(**C.SuccessfulOutcome_t)(unsafe.Pointer(&pdu.choice))
		log.Printf("SuccessfulOutcome message detected, procedure code: %d", msg.procedureCode)
		
		// Map procedure codes to specific successful outcome types
		switch msg.procedureCode {
		case 23: // UEContextRelease
			typ = UE_CONTEXT_RELEASE_COMPLETE
		case 0: // HandoverPreparation
			typ = HANDOVER_COMMAND
		case 1: // HandoverResourceAllocation  
			typ = HANDOVER_REQUEST_ACKNOWLEDGE
		case 5: // E-RABSetup
			typ = E_RAB_SETUP_RESPONSE
		case 6: // E-RABModify
			typ = E_RAB_MODIFY_RESPONSE
		case 9: // InitialContextSetup
			typ = INITIAL_CONTEXT_SETUP_RESPONSE
		case 17: // S1Setup
			typ = S1_SETUP_RESPONSE
		case 14: // Reset
			typ = RESET_ACKNOWLEDGE
		default:
			log.Printf("Unknown SuccessfulOutcome procedure: %d", msg.procedureCode)
			typ = -1
		}
	case C.S1AP_PDU_PR_unsuccessfulOutcome:
		// Handle unsuccessful outcome messages
		msg := *(**C.UnsuccessfulOutcome_t)(unsafe.Pointer(&pdu.choice))
		log.Printf("UnsuccessfulOutcome message detected, procedure code: %d", msg.procedureCode)
		
		// Map procedure codes to specific unsuccessful outcome types
		switch msg.procedureCode {
		case 0: // HandoverPreparation
			typ = HANDOVER_PREPARATION_FAILURE
		case 1: // HandoverResourceAllocation
			typ = HANDOVER_FAILURE
		case 5: // E-RABSetup
			typ = E_RAB_SETUP_FAILURE
		case 9: // InitialContextSetup
			typ = INITIAL_CONTEXT_SETUP_FAILURE
		case 17: // S1Setup
			typ = S1_SETUP_FAILURE
		default:
			log.Printf("Unknown UnsuccessfulOutcome procedure: %d", msg.procedureCode)
			typ = -1
		}
	default:
	}
	return packet, typ, nil
}

// Enhanced helper functions for complex IE types based on tshark analysis
func decodePLMNIdentity(data []byte) (mcc, mnc string) {
	if len(data) < 3 {
		return "Unknown", "Unknown"
	}

	// PLMN identity format: BCD encoded in 3 bytes
	// Example: 06f510 -> MCC=605, MNC=01
	mcc1 := data[0] & 0x0F
	mcc2 := (data[0] & 0xF0) >> 4
	mcc3 := data[1] & 0x0F
	mnc3 := (data[1] & 0xF0) >> 4
	mnc1 := data[2] & 0x0F
	mnc2 := (data[2] & 0xF0) >> 4

	mcc = fmt.Sprintf("%d%d%d", mcc1, mcc2, mcc3)

	if mnc3 == 0xF {
		// 2-digit MNC
		mnc = fmt.Sprintf("%02d", mnc1*10+mnc2)
	} else {
		// 3-digit MNC
		mnc = fmt.Sprintf("%03d", mnc3*100+mnc1*10+mnc2)
	}

	return mcc, mnc
}

func XerPrint(message unsafe.Pointer) {
	C.xer_fprint(C.stdout, &C.asn_DEF_S1AP_PDU, message)
}

func Free(packet unsafe.Pointer) {
	C.free(packet)
}

// ExtractFallbackIEs attempts to extract basic IE information from raw payload
// when APER decoding fails, using pattern matching and known S1AP structures
func ExtractFallbackIEs(payload []byte, procedureCode int) []*InformationElement {
	var result []*InformationElement

	log.Printf("DEBUG: Fallback IE extraction for procedure code %d", procedureCode)

	if len(payload) < 10 {
		return result
	}

	// Basic fallback extraction based on procedure type
	switch procedureCode {
	case 10: // Paging
		result = append(result, &InformationElement{
			ID:          1, // UEIdentityList
			Name:        "id_UEIdentityList",
			Criticality: "reject",
			Value:       "UEIdentityList (fallback extraction)",
			RawValue:    "Extracted from raw payload",
		})

		result = append(result, &InformationElement{
			ID:          2, // UEPagingID
			Name:        "id_UEPagingID",
			Criticality: "ignore",
			Value:       "UEPagingID (fallback extraction)",
			RawValue:    "Raw payload analysis",
		})

	case 12: // InitialUEMessage
		result = append(result, &InformationElement{
			ID:          8, // eNB-UE-S1AP-ID
			Name:        "id_eNB_UE_S1AP_ID",
			Criticality: "reject",
			Value:       "eNB_UE_S1AP_ID (fallback)",
			RawValue:    "Extracted from payload",
		})

		result = append(result, &InformationElement{
			ID:          26, // NAS-PDU
			Name:        "id_NAS_PDU",
			Criticality: "reject",
			Value:       "NAS_PDU (fallback)",
			RawValue:    "Raw NAS data present",
		})

	case 13: // UplinkNASTransport
		result = append(result, &InformationElement{
			ID:          0, // MME-UE-S1AP-ID
			Name:        "id_MME_UE_S1AP_ID",
			Criticality: "reject",
			Value:       "MME_UE_S1AP_ID (fallback)",
			RawValue:    "Extracted from payload",
		})

		result = append(result, &InformationElement{
			ID:          26, // NAS-PDU
			Name:        "id_NAS_PDU",
			Criticality: "reject",
			Value:       "NAS_PDU (fallback)",
			RawValue:    "Raw NAS data present",
		})

	case 42: // CellTrafficTrace
		result = append(result, &InformationElement{
			ID:          86, // TraceCollectionEntityIPAddress
			Name:        "id_TraceCollectionEntityIPAddress",
			Criticality: "ignore",
			Value:       "IP Address (fallback)",
			RawValue:    "IP address extraction attempted",
		})

	default:
		result = append(result, &InformationElement{
			ID:          999, // Generic
			Name:        "unknown_fallback",
			Criticality: "ignore",
			Value:       fmt.Sprintf("Fallback extraction for procedure %d", procedureCode),
			RawValue:    fmt.Sprintf("Raw payload %d bytes", len(payload)),
		})
	}

	log.Printf("DEBUG: Fallback extraction found %d IEs", len(result))
	return result
}

// ===== FONCTIONS UTILITAIRES POUR LE DÉCODAGE =====

// decodeIMSI decodes IMSI from BCD format
func decodeIMSI(data []byte) string {
	if len(data) == 0 {
		return "Invalid"
	}
	
	var imsi strings.Builder
	
	// First digit is in the lower nibble of first byte
	if len(data) > 0 {
		firstDigit := data[0] & 0x0F
		if firstDigit == 0x0F {
			// Skip if padding
		} else {
			imsi.WriteString(fmt.Sprintf("%d", firstDigit))
		}
		
		// Second digit is in upper nibble of first byte
		secondDigit := (data[0] & 0xF0) >> 4
		if secondDigit != 0x0F {
			imsi.WriteString(fmt.Sprintf("%d", secondDigit))
		}
	}
	
	// Remaining digits are packed in BCD format
	for i := 1; i < len(data); i++ {
		lowNibble := data[i] & 0x0F
		highNibble := (data[i] & 0xF0) >> 4
		
		if lowNibble != 0x0F {
			imsi.WriteString(fmt.Sprintf("%d", lowNibble))
		}
		if highNibble != 0x0F {
			imsi.WriteString(fmt.Sprintf("%d", highNibble))
		}
	}
	
	return imsi.String()
}

// Enhanced decoder for different message types
func extractEnhancedIEs(packet unsafe.Pointer, messageType int, procedureCode int) []*InformationElement {
	log.Printf("DEBUG: Enhanced IE extraction for messageType: %d, procedureCode: %d", messageType, procedureCode)
	
	// Map specific procedure codes to enhanced extractors
	switch procedureCode {
	case 10: // Paging
		return extractPagingIEs(packet)
	case 42: // CellTrafficTrace
		return extractCellTrafficTraceIEs(packet)
	case 37: // TraceStart
		return extractTraceStartIEs(packet)
	case 38: // TraceFailureIndication
		return extractTraceFailureIndicationIEs(packet)
	case 39: // DeactivateTrace
		return extractDeactivateTraceIEs(packet)
	case 40: // LocationReportingControl
		return extractLocationReportingControlIEs(packet)
	case 41: // LocationReportingFailureIndication
		return extractLocationReportingFailureIndicationIEs(packet)
	case 47: // LocationReport
		return extractLocationReportIEs(packet)
	default:
		// Use generic extraction for unknown procedure codes
		return extractGenericIEs(packet, messageType)
	}
}

// New extractors for trace-related messages
func extractTraceStartIEs(packet unsafe.Pointer) []*InformationElement {
	var result []*InformationElement
	log.Printf("DEBUG: Enhanced TraceStart IE extraction")
	
	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.TraceStart_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.TraceStartIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	for _, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		switch ie.id {
		case C.ProtocolIE_ID_id_MME_UE_S1AP_ID:
			mme_id := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*mme_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*mme_id))
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*enb_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*enb_id))
		case C.ProtocolIE_ID_id_TraceActivation:
			ieStruct.Value = "Trace Activation present"
			ieStruct.RawValue = "TraceActivation structure"
		default:
			ieStruct.Value = "Unknown IE"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
		}
		result = append(result, ieStruct)
	}
	
	return result
}

func extractTraceFailureIndicationIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 38) // TraceFailureIndication
}

func extractDeactivateTraceIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 39) // DeactivateTrace
}

func extractLocationReportingControlIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 40) // LocationReportingControl
}

func extractLocationReportingFailureIndicationIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 41) // LocationReportingFailureIndication
}

func extractLocationReportIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 47) // LocationReport
}

// ===== FONCTIONS D'EXTRACTION SIMPLIFIÉES =====

func extractERABSetupResponseIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 5) // E-RABSetupResponse
}

func extractHandoverRequiredIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 11) // HandoverRequired
}

func extractUECapabilityInfoIndicationIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 22) // UECapabilityInfoIndication
}

func extractUEContextModificationResponseIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 25) // UEContextModificationResponse
}

func extractS1SetupResponseIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 1) // S1SetupResponse
}

func extractInitialContextSetupResponseIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 9) // InitialContextSetupResponse
}

func extractHandoverCommandIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 12) // HandoverCommand
}

func extractUEContextReleaseCompleteIEs(packet unsafe.Pointer) []*InformationElement {
	var ies []*InformationElement
	
	log.Printf("DEBUG: extractUEContextReleaseCompleteIEs called")

	pdu := (*C.S1AP_PDU_t)(packet)
	if pdu.present != C.S1AP_PDU_PR_successfulOutcome {
		log.Printf("DEBUG: PDU is not successfulOutcome: %d", pdu.present)
		return ies
	}

	msg := *(**C.SuccessfulOutcome_t)(unsafe.Pointer(&pdu.choice))
	
	// Try multiple approaches to extract IEs
	defer func() {
		if r := recover(); r != nil {
			log.Printf("DEBUG: extractUEContextReleaseCompleteIEs panicked: %v", r)
			// Try to use the C handler as fallback
			if mmeID, enbID, err := UEContextReleaseCompleteHandle(packet); err == nil {
				log.Printf("DEBUG: Using C handler fallback - MME: %d, eNB: %d", mmeID, enbID)
				ies = []*InformationElement{}
				if mmeID != -1 {
					ies = append(ies, &InformationElement{
						ID:          0,
						Name:        "id_MME_UE_S1AP_ID",
						Criticality: "reject",
						Value:       mmeID,
						RawValue:    fmt.Sprintf("%d", mmeID),
					})
				}
				if enbID != -1 {
					ies = append(ies, &InformationElement{
						ID:          8,
						Name:        "id_eNB_UE_S1AP_ID",
						Criticality: "reject",
						Value:       enbID,
						RawValue:    fmt.Sprintf("%d", enbID),
					})
				}
			} else {
				log.Printf("DEBUG: C handler also failed: %v", err)
				ies = createFallbackUEContextReleaseCompleteIEs()
			}
		}
	}()
	
	// Try to use a more generic extraction based on the structure
	val := (*C.UEContextReleaseComplete_t)(unsafe.Pointer(&msg.value.choice))

	var iesList []*C.UEContextReleaseComplete_IEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&iesList)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	log.Printf("DEBUG: Found %d IEs in UEContextReleaseComplete", len(iesList))

	for i, ie := range iesList {
		ieInfo := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		log.Printf("DEBUG: Processing IE[%d] - ID: %d, Name: %s", i, ie.id, ieInfo.Name)

		switch ie.id {
		case C.ProtocolIE_ID_id_MME_UE_S1AP_ID:
			mme_id_c := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieInfo.Value = int32(*mme_id_c)
			ieInfo.RawValue = fmt.Sprintf("%d", int32(*mme_id_c))
			log.Printf("DEBUG: Extracted MME_UE_S1AP_ID: %d", int32(*mme_id_c))
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_id_c := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieInfo.Value = int32(*enb_id_c)
			ieInfo.RawValue = fmt.Sprintf("%d", int32(*enb_id_c))
			log.Printf("DEBUG: Extracted eNB_UE_S1AP_ID: %d", int32(*enb_id_c))
		default:
			ieInfo.Value = "Not decoded"
			ieInfo.RawValue = "Binary data not extracted"
			log.Printf("DEBUG: IE ID %d not specifically handled", ie.id)
		}

		ies = append(ies, ieInfo)
	}

	log.Printf("DEBUG: Returning %d IEs from UEContextReleaseComplete", len(ies))
	return ies
}

// Fallback function to create basic IEs if the main extraction fails
func createFallbackUEContextReleaseCompleteIEs() []*InformationElement {
	log.Printf("DEBUG: Using fallback IE creation for UEContextReleaseComplete")
	return []*InformationElement{
		{
			ID:          0,
			Name:        "id_MME_UE_S1AP_ID",
			Criticality: "reject",
			Value:       "Extraction failed",
			RawValue:    "Fallback placeholder",
		},
		{
			ID:          8,
			Name:        "id_eNB_UE_S1AP_ID", 
			Criticality: "reject",
			Value:       "Extraction failed",
			RawValue:    "Fallback placeholder",
		},
	}
}

func extractUEContextModificationFailureIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 26) // UEContextModificationFailure
}

func extractS1SetupFailureIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 2) // S1SetupFailure
}

func extractInitialContextSetupFailureIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 10) // InitialContextSetupFailure
}

func extractERABSetupFailureIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 16) // E-RABSetupFailure
}

// Helper function to get criticality value
func getCriticality(criticality C.Criticality_t) int {
	return int(criticality)
}

// ===== FONCTIONS DE DÉCODAGE SPÉCIALISÉES POUR LES IEs =====

// Fonction pour décoder TAI (Tracking Area Identity)
// extractTAI extrait les informations TAI selon le format Wireshark/tshark
func extractTAI(tai_ptr unsafe.Pointer) (string, string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: extractTAI panicked: %v", r)
		}
	}()

	if tai_ptr == nil {
		return "TAI: null pointer", "null pointer"
	}

	tai := (*C.TAI_t)(tai_ptr)
	if tai == nil {
		return "TAI: null TAI struct", "null TAI struct"
	}

	// Extraire PLMN identity (TBCD-STRING)
	var plmnData []byte
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&plmnData)))
	slice.Cap = (int)(tai.pLMNidentity.size)
	slice.Len = (int)(tai.pLMNidentity.size)
	slice.Data = uintptr(unsafe.Pointer(tai.pLMNidentity.buf))

	if len(plmnData) < 3 {
		return "TAI: invalid PLMN size", fmt.Sprintf("PLMN size: %d", len(plmnData))
	}

	mcc, mnc := decodePLMNIdentity(plmnData)

	// Extraire TAC (OCTET_STRING, 2 bytes)
	var tacData []byte
	tacSlice := (*reflect.SliceHeader)((unsafe.Pointer(&tacData)))
	tacSlice.Cap = (int)(tai.tAC.size)
	tacSlice.Len = (int)(tai.tAC.size) 
	tacSlice.Data = uintptr(unsafe.Pointer(tai.tAC.buf))

	var tac uint16
	if len(tacData) >= 2 {
		tac = uint16(tacData[0])<<8 | uint16(tacData[1])
	}

	// Format similaire à Wireshark: "PLMN Identity: MCC 605, MNC 01 (TAC: 0x0001)"
	value := fmt.Sprintf("PLMN Identity: MCC %s, MNC %s (TAC: 0x%04x)", mcc, mnc, tac)
	rawValue := fmt.Sprintf("plmn_id=%s tac=%04x", hex.EncodeToString(plmnData), tac)

	return value, rawValue
}

// extractTAIItem extrait les informations d'un TAIItem
func extractTAIItem(tai_item_ptr unsafe.Pointer) (string, string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: extractTAIItem panicked: %v", r)
		}
	}()

	if tai_item_ptr == nil {
		return "TAIItem: null pointer", "null pointer"
	}

	taiItem := (*C.TAIItem_t)(tai_item_ptr)
	if taiItem == nil {
		return "TAIItem: null TAIItem struct", "null TAIItem struct"
	}

	// Extraire le TAI depuis TAIItem
	taiValue, taiRaw := extractTAI(unsafe.Pointer(&taiItem.tAI))
	
	// Format: "TAI Item: [contenu TAI]"
	value := fmt.Sprintf("TAI Item: %s", taiValue)
	
	return value, taiRaw
}

// extractTAIList extrait et decode une liste TAI complète
func extractTAIList(tai_list_ptr unsafe.Pointer) (string, string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: extractTAIList panicked: %v", r)
		}
	}()

	if tai_list_ptr == nil {
		return "TAIList: null pointer", "null pointer"
	}

	taiList := (*C.TAIList_t)(tai_list_ptr)
	if taiList == nil {
		return "TAIList: null TAIList struct", "null TAIList struct"
	}

	count := int(taiList.list.count)
	if count == 0 {
		return "TAIList: empty list", "count=0"
	}

	// Extraire les éléments de la liste TAIItemIEs
	var taiItemIEs []*C.TAIItemIEs_t
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&taiItemIEs))
	slice.Cap = count
	slice.Len = count
	slice.Data = uintptr(unsafe.Pointer(taiList.list.array))

	var taiItems []string
	var rawItems []string

	for i, taiItemIE := range taiItemIEs {
		if taiItemIE != nil {
			// Vérifier le présent (should be TAIItemIEs__value_PR_TAIItem)
			if taiItemIE.value.present == C.TAIItemIEs__value_PR_TAIItem {
				// Accéder au TAIItem depuis le choice using byte array access
				taiItemPtr := unsafe.Pointer(&taiItemIE.value.choice[0])
				taiItem := (*C.TAIItem_t)(taiItemPtr)
				
				// Le TAIItem contient directement un TAI_t
				taiValue, taiRaw := extractTAI(unsafe.Pointer(&taiItem.tAI))
				
				taiItems = append(taiItems, fmt.Sprintf("  Item[%d]: %s", i, taiValue))
				rawItems = append(rawItems, fmt.Sprintf("item_%d={%s}", i, taiRaw))
			} else {
				log.Printf("WARNING: TAIItemIE %d has unexpected present value: %d", i, taiItemIE.value.present)
				taiItems = append(taiItems, fmt.Sprintf("  Item[%d]: Invalid present value", i))
			}
		}
	}

	// Format similaire à Wireshark
	value := fmt.Sprintf("TAI List (%d items):\n%s", count, strings.Join(taiItems, "\n"))
	rawValue := fmt.Sprintf("count=%d %s", count, strings.Join(rawItems, " "))

	return value, rawValue
}

// createTAIInformationElement crée un InformationElement pour TAI
func createTAIInformationElement(ieID int, taiPtr unsafe.Pointer, criticality int) *InformationElement {
	value, rawValue := extractTAI(taiPtr)
	
	return &InformationElement{
		ID:          ieID,
		Name:        GetIEName(ieID),
		Criticality: getCriticalityString(criticality),
		Value:       value,
		RawValue:    rawValue,
	}
}

// createTAIListInformationElement crée un InformationElement pour TAIList
func createTAIListInformationElement(ieID int, taiListPtr unsafe.Pointer, criticality int) *InformationElement {
	value, rawValue := extractTAIList(taiListPtr)
	
	return &InformationElement{
		ID:          ieID,
		Name:        GetIEName(ieID),
		Criticality: getCriticalityString(criticality),
		Value:       value,
		RawValue:    rawValue,
	}
}

// Fonction pour décoder EUTRAN-CGI (E-UTRAN Cell Global Identity)
func extractEUTRANCGI(cgi_ptr unsafe.Pointer) (string, string) {
	cgi := (*C.EUTRAN_CGI_t)(cgi_ptr)

	// Extraire PLMN identity
	var plmnData []byte
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&plmnData)))
	slice.Cap = (int)(cgi.pLMNidentity.size)
	slice.Len = (int)(cgi.pLMNidentity.size)
	slice.Data = uintptr(unsafe.Pointer(cgi.pLMNidentity.buf))

	mcc, mnc := decodePLMNIdentity(plmnData)

	// Extraire Cell Identity (28 bits)
	var cellIdData []byte
	cellSlice := (*reflect.SliceHeader)((unsafe.Pointer(&cellIdData)))
	cellSlice.Cap = (int)(cgi.cell_ID.size)
	cellSlice.Len = (int)(cgi.cell_ID.size)
	cellSlice.Data = uintptr(unsafe.Pointer(cgi.cell_ID.buf))

	var cellId uint32
	if len(cellIdData) >= 4 {
		cellId = uint32(cellIdData[0])<<20 | uint32(cellIdData[1])<<12 | uint32(cellIdData[2])<<4 | uint32(cellIdData[3])>>4
		cellId &= 0x0FFFFFFF // 28 bits seulement
	}

	// Extraire eNB ID (20 bits) et Cell ID (8 bits)
	enbId := cellId >> 8
	localCellId := cellId & 0xFF

	value := fmt.Sprintf("EUTRAN-CGI(MCC=%s,MNC=%s,eNB-ID=%d,Cell-ID=%d)", mcc, mnc, enbId, localCellId)
	rawValue := fmt.Sprintf("PLMN=%s,CellID=%08x", hex.EncodeToString(plmnData), cellId)

	return value, rawValue
}

// Fonction pour décoder S-TMSI
func extractSTMSI(stmsi_ptr unsafe.Pointer) (string, string) {
	stmsi := (*C.S_TMSI_t)(stmsi_ptr)

	// Extraire MME Code
	var mmecData []byte
	mmecSlice := (*reflect.SliceHeader)((unsafe.Pointer(&mmecData)))
	mmecSlice.Cap = (int)(stmsi.mMEC.size)
	mmecSlice.Len = (int)(stmsi.mMEC.size)
	mmecSlice.Data = uintptr(unsafe.Pointer(stmsi.mMEC.buf))

	var mmec uint8
	if len(mmecData) >= 1 {
		mmec = mmecData[0]
	}

	// Extraire M-TMSI
	var mtmsiData []byte
	mtmsiSlice := (*reflect.SliceHeader)((unsafe.Pointer(&mtmsiData)))
	mtmsiSlice.Cap = (int)(stmsi.m_TMSI.size)
	mtmsiSlice.Len = (int)(stmsi.m_TMSI.size)
	mtmsiSlice.Data = uintptr(unsafe.Pointer(stmsi.m_TMSI.buf))

	var mtmsi uint32
	if len(mtmsiData) >= 4 {
		mtmsi = uint32(mtmsiData[0])<<24 | uint32(mtmsiData[1])<<16 | uint32(mtmsiData[2])<<8 | uint32(mtmsiData[3])
	}

	value := fmt.Sprintf("S-TMSI(MMEC=%d,M-TMSI=0x%08x)", mmec, mtmsi)
	rawValue := fmt.Sprintf("MMEC=%02x,M-TMSI=%s", mmec, hex.EncodeToString(mtmsiData))

	return value, rawValue
}

// Fonction pour décoder RRC Establishment Cause
func extractRRCEstablishmentCause(cause_ptr unsafe.Pointer) (string, string) {
	cause := (*C.RRC_Establishment_Cause_t)(cause_ptr)

	var causeStr string
	switch *cause {
	case C.RRC_Establishment_Cause_emergency:
		causeStr = "emergency"
	case C.RRC_Establishment_Cause_highPriorityAccess:
		causeStr = "highPriorityAccess"
	case C.RRC_Establishment_Cause_mt_Access:
		causeStr = "mt-Access"
	case C.RRC_Establishment_Cause_mo_Signalling:
		causeStr = "mo-Signalling"
	case C.RRC_Establishment_Cause_mo_Data:
		causeStr = "mo-Data"
	case C.RRC_Establishment_Cause_delay_TolerantAccess:
		causeStr = "delay-TolerantAccess"
	case C.RRC_Establishment_Cause_mo_VoiceCall:
		causeStr = "mo-VoiceCall"
	case C.RRC_Establishment_Cause_mo_ExceptionData:
		causeStr = "mo-ExceptionData"
	default:
		causeStr = fmt.Sprintf("unknown(%d)", *cause)
	}

	value := fmt.Sprintf("RRC-Establishment-Cause=%s", causeStr)
	rawValue := fmt.Sprintf("cause=%d", *cause)

	return value, rawValue
}
