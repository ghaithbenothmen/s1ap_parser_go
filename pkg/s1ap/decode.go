package s1ap

// #cgo CFLAGS: -I./asn1
// #cgo LDFLAGS: -L/usr/local/lib -ls1ap -lasn1c
// #include "S1AP-PDU.h"
// #include "InitiatingMessage.h"
// #include "ProtocolIE-Field.h"
// #include <stdio.h>
// #include <stdlib.h>
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
func ExtractAllIEs(packet unsafe.Pointer, messageType int) []*InformationElement {
	var ies []*InformationElement
	
	pdu := (*C.S1AP_PDU_t)(packet)
	if pdu.present != C.S1AP_PDU_PR_initiatingMessage {
		return ies // Only handle initiating messages for now
	}

	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	
	// Switch based on message type to extract IEs appropriately
	switch msg.value.present {
	case C.InitiatingMessage__value_PR_InitialUEMessage:
		ies = extractInitialUEMessageIEs(packet)
	case C.InitiatingMessage__value_PR_UplinkNASTransport:
		ies = extractUplinkNASTransportIEs(packet)
	case C.InitiatingMessage__value_PR_Paging:
		// Handle both Paging and DownlinkNASTransport (which seem to have the same internal type)
		if messageType == 6 { // DownlinkNASTransport procedure code
			ies = extractDownlinkNASTransportIEs(packet)
		} else {
			ies = extractPagingIEs(packet)
		}
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
		ies = extractDownlinkNASTransportIEs(packet)
	default:
		// For unsupported message types, try generic extraction
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

	var ies []*C.InitialUEMessage_IEs_t
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
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*enb_id)
		case C.ProtocolIE_ID_id_NAS_PDU:
			nas_pdu := (*C.NAS_PDU_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = fmt.Sprintf("NAS_PDU(%d bytes)", nas_pdu.size)
			ieStruct.RawValue = extractOctetString(nas_pdu)
		case C.ProtocolIE_ID_id_TAI:
			ieStruct.Value = "TAI"
			ieStruct.RawValue = "TAI structure present"
		case C.ProtocolIE_ID_id_EUTRAN_CGI:
			ieStruct.Value = "EUTRAN_CGI"
			ieStruct.RawValue = "EUTRAN_CGI structure present"
		case C.ProtocolIE_ID_id_S_TMSI:
			ieStruct.Value = "S_TMSI"
			ieStruct.RawValue = "S_TMSI structure present"
		case C.ProtocolIE_ID_id_RRC_Establishment_Cause:
			ieStruct.Value = "RRC_Establishment_Cause"
			ieStruct.RawValue = "RRC_Establishment_Cause present"
		default:
			ieStruct.Value = "Unknown"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
		}
		
		result = append(result, ieStruct)
	}
	
	return result
}

// Helper function to extract IEs from UplinkNASTransport
func extractUplinkNASTransportIEs(packet unsafe.Pointer) []*InformationElement {
	var result []*InformationElement
	
	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.UplinkNASTransport_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.UplinkNASTransport_IEs_t
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
		case C.ProtocolIE_ID_id_NAS_PDU:
			nas_pdu := (*C.NAS_PDU_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = fmt.Sprintf("NAS_PDU(%d bytes)", nas_pdu.size)
			ieStruct.RawValue = extractOctetString(nas_pdu)
		case C.ProtocolIE_ID_id_EUTRAN_CGI:
			ieStruct.Value = "EUTRAN_CGI"
			ieStruct.RawValue = "EUTRAN_CGI structure present"
		case C.ProtocolIE_ID_id_TAI:
			ieStruct.Value = "TAI"
			ieStruct.RawValue = "TAI structure present"
		default:
			ieStruct.Value = "Unknown"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
		}
		
		result = append(result, ieStruct)
	}
	
	return result
}

// Helper function to extract IEs from Paging
func extractPagingIEs(packet unsafe.Pointer) []*InformationElement {
	var result []*InformationElement
	
	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.Paging_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.PagingIEs_t
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
		case C.ProtocolIE_ID_id_UEIdentityIndexValue:
			ieStruct.Value = "UEIdentityIndexValue"
			ieStruct.RawValue = "UEIdentityIndexValue present"
		case C.ProtocolIE_ID_id_UEPagingID:
			ieStruct.Value = "UEPagingID"
			ieStruct.RawValue = "UEPagingID present"
		case C.ProtocolIE_ID_id_CNDomain:
			ieStruct.Value = "CNDomain"
			ieStruct.RawValue = "CNDomain present"
		case C.ProtocolIE_ID_id_TAIList:
			ieStruct.Value = "TAIList"
			ieStruct.RawValue = "TAIList present"
		default:
			ieStruct.Value = "Unknown"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
		}
		
		result = append(result, ieStruct)
	}
	
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

	var ies []*C.DownlinkNASTransport_IEs_t
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
		case C.ProtocolIE_ID_id_NAS_PDU:
			nas_pdu := (*C.NAS_PDU_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = fmt.Sprintf("NAS_PDU(%d bytes)", nas_pdu.size)
			ieStruct.RawValue = extractOctetString(nas_pdu)
		default:
			ieStruct.Value = "Unknown"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
		}
		
		result = append(result, ieStruct)
	}
	
	return result
}

// Generic IE extraction for unsupported message types
func extractGenericIEs(packet unsafe.Pointer, messageType int) []*InformationElement {
	var result []*InformationElement
	
	// For now, return empty slice for unsupported types
	// This can be extended to handle more message types
	
	return result
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

// Helper function to extract octet string data
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
