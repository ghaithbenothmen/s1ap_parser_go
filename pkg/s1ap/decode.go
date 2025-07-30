package s1ap

// #cgo CFLAGS: -I./asn1
// #cgo LDFLAGS: -L/usr/local/lib -ls1ap -lasn1c
// #include "S1AP-PDU.h"
// #include "InitiatingMessage.h"
// #include "SuccessfulOutcome.h"
// #include "UnsuccessfulOutcome.h"
// #include "ProtocolIE-Field.h"
// #include "ProtocolIE-SingleContainer.h"
// #include "ProtocolIE-Container.h"
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
// #include "UEContextReleaseRequest.h"
// #include "UEContextReleaseCommand.h"
// #include "UEContextModificationRequest.h"
// #include "NASNonDeliveryIndication.h"
// #include "PathSwitchRequest.h"
// #include "InitialContextSetupResponse.h"
// #include "UEContextReleaseComplete.h"
// #include "UplinkNASTransport.h"
// #include "Cause.h"
// #include "CauseRadioNetwork.h"
// #include "CauseTransport.h"
// #include "CauseNas.h"
// #include "CauseProtocol.h"
// #include "CauseMisc.h"
// #include "UEIdentityIndexValue.h"
// #include "Extended-UEIdentityIndexValue.h"
// #include "MME-Code.h"
// #include "M-TMSI.h"
// #include "PLMNidentity.h"
// #include "TAC.h"
// #include "TBCD-STRING.h"
// #include "InitialContextSetupResponse.h"
// #include "E-RABSetupListCtxtSURes.h"
// #include "E-RABSetupItemCtxtSURes.h"
// #include "E-RAB-ID.h"
// #include "GTP-TEID.h"
// #include <stdio.h>
// #include <stdlib.h>
//
// // Extract TAI data from TAIItem structure 
// typedef struct TAIData {
//     uint8_t plmn[3];    // PLMN identity (3 bytes)
//     uint16_t tac;       // TAC (2 bytes)
//     int valid;          // 1 if extraction successful, 0 otherwise
// } TAIData;
//
// TAIData extractTAIData(void* tai_item_ptr) {
//     TAIData result = {0};
//     if (!tai_item_ptr) return result;
//     
//     TAIItem_t* tai_item = (TAIItem_t*)tai_item_ptr;
//     if (!tai_item) return result;
//     
//     // Extract PLMN identity
//     if (tai_item->tAI.pLMNidentity.buf && tai_item->tAI.pLMNidentity.size >= 3) {
//         memcpy(result.plmn, tai_item->tAI.pLMNidentity.buf, 3);
//     }
//     
//     // Extract TAC
//     if (tai_item->tAI.tAC.buf && tai_item->tAI.tAC.size >= 2) {
//         result.tac = (tai_item->tAI.tAC.buf[0] << 8) | tai_item->tAI.tAC.buf[1];
//     }
//     
//     result.valid = 1;
//     return result;
// }
//
// // Extract S-TMSI data from S_TMSI structure
// typedef struct STMSIData {
//     uint8_t mmec;       // MME Code
//     uint32_t mtmsi;     // M-TMSI
//     int valid;          // 1 if extraction successful, 0 otherwise
// } STMSIData;
//
// STMSIData extractSTMSIData(void* stmsi_ptr) {
//     STMSIData result = {0};
//     if (!stmsi_ptr) return result;
//     
//     S_TMSI_t* stmsi = (S_TMSI_t*)stmsi_ptr;
//     if (!stmsi) return result;
//     
//     // Extract MMEC
//     if (stmsi->mMEC.buf && stmsi->mMEC.size >= 1) {
//         result.mmec = stmsi->mMEC.buf[0];
//     }
//     
//     // Extract M-TMSI (4 bytes)
//     if (stmsi->m_TMSI.buf && stmsi->m_TMSI.size >= 4) {
//         result.mtmsi = (stmsi->m_TMSI.buf[0] << 24) | 
//                       (stmsi->m_TMSI.buf[1] << 16) | 
//                       (stmsi->m_TMSI.buf[2] << 8) | 
//                       stmsi->m_TMSI.buf[3];
//     }
//     
//     result.valid = 1;
//     return result;
// }
//
// // Extract E-RAB Setup Item data from E_RABSetupItemCtxtSURes structure
// typedef struct ERABSetupItemData {
//     long erab_id;                    // E-RAB ID
//     uint8_t transport_address[16];   // Transport Layer Address (up to 16 bytes for IPv6)
//     uint8_t transport_address_len;   // Length of transport address  
//     uint32_t gtp_teid;              // GTP TEID
//     int valid;                      // 1 if extraction successful, 0 otherwise
// } ERABSetupItemData;
//
// ERABSetupItemData extractERABSetupItemData(void* erab_item_ptr) {
//     ERABSetupItemData result = {0};
//     if (!erab_item_ptr) return result;
//     
//     E_RABSetupItemCtxtSURes_t* erab_item = (E_RABSetupItemCtxtSURes_t*)erab_item_ptr;
//     if (!erab_item) return result;
//     
//     // Extract E-RAB ID
//     result.erab_id = erab_item->e_RAB_ID;
//     
//     // Extract Transport Layer Address
//     if (erab_item->transportLayerAddress.buf && erab_item->transportLayerAddress.size > 0) {
//         result.transport_address_len = (uint8_t)erab_item->transportLayerAddress.size;
//         if (result.transport_address_len <= 16) {
//             memcpy(result.transport_address, erab_item->transportLayerAddress.buf, result.transport_address_len);
//         }
//     }
//     
//     // Extract GTP TEID (4 bytes)
//     if (erab_item->gTP_TEID.buf && erab_item->gTP_TEID.size >= 4) {
//         result.gtp_teid = (erab_item->gTP_TEID.buf[0] << 24) | 
//                          (erab_item->gTP_TEID.buf[1] << 16) | 
//                          (erab_item->gTP_TEID.buf[2] << 8) | 
//                          erab_item->gTP_TEID.buf[3];
//     }
//     
//     result.valid = 1;
//     return result;
// }
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
		log.Printf("DEBUG: Detected UEContextReleaseRequest - calling extractUEContextReleaseRequestIEs")
		ies = extractUEContextReleaseRequestIEs(packet)
	case C.InitiatingMessage__value_PR_UEContextReleaseCommand:
		log.Printf("DEBUG: Detected UEContextReleaseCommand - calling extractUEContextReleaseCommandIEs")
		ies = extractUEContextReleaseCommandIEs(packet)
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
	case C.InitiatingMessage__value_PR_PathSwitchRequest:
		log.Printf("DEBUG: Detected PathSwitchRequest - calling extractPathSwitchRequestIEs")
		ies = extractPathSwitchRequestIEs(packet)
	case C.InitiatingMessage__value_PR_NASNonDeliveryIndication:
		log.Printf("DEBUG: Detected NASNonDeliveryIndication - using enhanced extraction")
		ies = extractEnhancedIEs(packet, messageType, int(procCode))
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
			hexData := extractOctetString(&tai.pLMNidentity)
			// TAC est un OCTET STRING de 2 bytes
			if tai.tAC.size >= 2 {
				tacBytes := C.GoBytes(unsafe.Pointer(tai.tAC.buf), C.int(tai.tAC.size))
				tac := fmt.Sprintf("%04x", binary.BigEndian.Uint16(tacBytes))
				ieStruct.Value = fmt.Sprintf("TAI(PLMN:%s, TAC:%s)", hexData[:6], tac)
			} else {
				ieStruct.Value = fmt.Sprintf("TAI(PLMN:%s, TAC:invalid)", hexData[:6])
			}
			ieStruct.RawValue = hexData
			log.Printf("DEBUG: InitialUEMessage extracted TAI: %s", ieStruct.Value)
		case C.InitialUEMessage_IEs__value_PR_EUTRAN_CGI:
			eutran_cgi := (*C.EUTRAN_CGI_t)(unsafe.Pointer(&ie.value.choice[0]))
			plmnHex := extractOctetString(&eutran_cgi.pLMNidentity)
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

		// Use the value present enum instead of the ID, with correct pointer casting
		switch ie.value.present {
		case C.UplinkNASTransport_IEs__value_PR_MME_UE_S1AP_ID:
			mme_id := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice[0]))
			ieStruct.Value = int32(*mme_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*mme_id))
			log.Printf("DEBUG: UplinkNASTransport extracted MME_UE_S1AP_ID: %d", int32(*mme_id))
		case C.UplinkNASTransport_IEs__value_PR_ENB_UE_S1AP_ID:
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice[0]))
			ieStruct.Value = int32(*enb_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*enb_id))
			log.Printf("DEBUG: UplinkNASTransport extracted eNB_UE_S1AP_ID: %d", int32(*enb_id))
		case C.UplinkNASTransport_IEs__value_PR_NAS_PDU:
			nas_pdu := (*C.NAS_PDU_t)(unsafe.Pointer(&ie.value.choice[0]))
			hexData := extractOctetString(nas_pdu)
			ieStruct.Value = fmt.Sprintf("NAS_PDU(%d bytes)", nas_pdu.size)
			ieStruct.RawValue = hexData
			log.Printf("DEBUG: UplinkNASTransport extracted NAS_PDU: %d bytes", nas_pdu.size)
		case C.UplinkNASTransport_IEs__value_PR_EUTRAN_CGI:
			eutran_cgi := (*C.EUTRAN_CGI_t)(unsafe.Pointer(&ie.value.choice[0]))
			plmnHex := extractOctetString(&eutran_cgi.pLMNidentity)
			cellIdBytes := C.GoBytes(unsafe.Pointer(eutran_cgi.cell_ID.buf), C.int(eutran_cgi.cell_ID.size))
			cellIdHex := fmt.Sprintf("%x", cellIdBytes)
			ieStruct.Value = fmt.Sprintf("EUTRAN_CGI(PLMN:%s, CellID:%s)", plmnHex[:6], cellIdHex[:8])
			ieStruct.RawValue = plmnHex + cellIdHex
			log.Printf("DEBUG: UplinkNASTransport extracted EUTRAN_CGI: %s", ieStruct.Value)
		case C.UplinkNASTransport_IEs__value_PR_TAI:
			tai := (*C.TAI_t)(unsafe.Pointer(&ie.value.choice[0]))
			hexData := extractOctetString(&tai.pLMNidentity)
			tacBytes := C.GoBytes(unsafe.Pointer(tai.tAC.buf), C.int(tai.tAC.size))
			tac := fmt.Sprintf("%04x", binary.BigEndian.Uint16(tacBytes))
			ieStruct.Value = fmt.Sprintf("TAI(PLMN:%s, TAC:%s)", hexData[:6], tac)
			ieStruct.RawValue = hexData
			log.Printf("DEBUG: UplinkNASTransport extracted TAI: %s", ieStruct.Value)
		default:
			ieStruct.Value = "Unknown"
			ieStruct.RawValue = fmt.Sprintf("IE_%d present (PR=%d)", ie.id, ie.value.present)
			log.Printf("DEBUG: UplinkNASTransport unknown IE ID: %d, present: %d", ie.id, ie.value.present)
		}

		result = append(result, ieStruct)
	}

	log.Printf("DEBUG: UplinkNASTransport extraction completed with %d IEs", len(result))

	return result
}

// Helper function to extract IEs from UEContextReleaseRequest
func extractUEContextReleaseRequestIEs(packet unsafe.Pointer) []*InformationElement {
	log.Printf("DEBUG: Enhanced UEContextReleaseRequest IE extraction started")
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.UEContextReleaseRequest_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.UEContextReleaseRequest_IEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	log.Printf("DEBUG: UEContextReleaseRequest IE count: %d", len(ies))

	for i, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		log.Printf("DEBUG: Processing UEContextReleaseRequest IE[%d] - ID: %d, Name: %s", i, ie.id, ieStruct.Name)

		switch ie.id {
		case C.ProtocolIE_ID_id_MME_UE_S1AP_ID:
			mme_id := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*mme_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*mme_id))
			log.Printf("DEBUG: Extracted MME_UE_S1AP_ID: %d", int32(*mme_id))
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*enb_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*enb_id))
			log.Printf("DEBUG: Extracted eNB_UE_S1AP_ID: %d", int32(*enb_id))
		case C.ProtocolIE_ID_id_Cause:
			// Extract cause information with detailed decoding
			ieStruct.Value, ieStruct.RawValue = extractDetailedCause(unsafe.Pointer(&ie.value.choice[0]))
			log.Printf("DEBUG: Extracted Cause IE")
		default:
			ieStruct.Value = fmt.Sprintf("Unknown_IE_%d", ie.id)
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
			log.Printf("DEBUG: Unknown UEContextReleaseRequest IE - ID: %d", ie.id)
		}

		result = append(result, ieStruct)
	}

	log.Printf("DEBUG: UEContextReleaseRequest IE extraction completed - %d IEs extracted", len(result))
	return result
}

// Helper function to extract IEs from UEContextReleaseCommand
func extractUEContextReleaseCommandIEs(packet unsafe.Pointer) []*InformationElement {
	log.Printf("DEBUG: Enhanced UEContextReleaseCommand IE extraction started")
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.UEContextReleaseCommand_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.UEContextReleaseCommand_IEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	log.Printf("DEBUG: UEContextReleaseCommand IE count: %d", len(ies))

	for i, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		log.Printf("DEBUG: Processing UEContextReleaseCommand IE[%d] - ID: %d, Name: %s", i, ie.id, ieStruct.Name)

		switch ie.id {
		case C.ProtocolIE_ID_id_UE_S1AP_IDs:
			// UE S1AP IDs (can be MME and eNB IDs)
			ieStruct.Value = "UE_S1AP_IDs (MME and eNB identifiers)"
			ieStruct.RawValue = "UE_S1AP_IDs structure present"
			log.Printf("DEBUG: Extracted UE_S1AP_IDs")
		case C.ProtocolIE_ID_id_Cause:
			ieStruct.Value = "Cause (detailed structure)"
			ieStruct.RawValue = "Cause structure present"
			log.Printf("DEBUG: Extracted Cause IE")
		default:
			ieStruct.Value = fmt.Sprintf("Unknown_IE_%d", ie.id)
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
			log.Printf("DEBUG: Unknown UEContextReleaseCommand IE - ID: %d", ie.id)
		}

		result = append(result, ieStruct)
	}

	log.Printf("DEBUG: UEContextReleaseCommand IE extraction completed - %d IEs extracted", len(result))
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

// Enhanced UEIdentityIndexValue extraction matching Wireshark format
func extractDetailedUEIdentityIndexValue(bitString *C.BIT_STRING_t) (interface{}, string) {
	if bitString.buf == nil || bitString.size == 0 {
		return "Invalid", "Empty or null buffer"
	}

	data := C.GoBytes(unsafe.Pointer(bitString.buf), C.int(bitString.size))
	hexStr := hex.EncodeToString(data)
	
	// UEIdentityIndexValue is 10 bits according to spec
	// Wireshark format: "b140 [bit length 10, 6 LSB pad bits, 1011 0001  01.. .... decimal value 709]"
	
	if len(data) >= 2 {
		// Extract full 16-bit value for bit manipulation
		fullValue := binary.BigEndian.Uint16(data)
		
		// Extract 10 most significant bits (right shift by 6 to remove padding)
		value := fullValue >> 6
		
		// Calculate padding bits (6 LSB pad bits for 10-bit value in 16-bit field)
		padBits := 6
		
		// Format binary representation like Wireshark with proper bit masking
		binaryFull := fmt.Sprintf("%016b", fullValue)
		// Show the 10 significant bits and 6 padding bits: "1011 0001  01.. ...."
		binaryFormatted := fmt.Sprintf("%s %s  %s %s", 
			binaryFull[0:4], binaryFull[4:8], binaryFull[8:10]+"..", "....")
		
		rawValue := fmt.Sprintf("%s [bit length 10, %d LSB pad bits, %s decimal value %d]",
			hexStr, padBits, binaryFormatted, value)
		
		return int(value), rawValue
	} else if len(data) == 1 {
		// Single byte case
		fullValue := uint16(data[0]) << 8 // Shift to MSB position
		value := fullValue >> 6           // Extract 10 bits
		binaryFormatted := fmt.Sprintf("%08b", data[0])
		
		rawValue := fmt.Sprintf("%s [bit length 10, %s decimal value %d]", hexStr, binaryFormatted, value)
		return int(value), rawValue
	}
	
	return hexStr, "0x" + hexStr
}

// Enhanced Extended UEIdentityIndexValue extraction matching Wireshark format  
func extractDetailedExtendedUEIdentityIndexValue(bitString *C.BIT_STRING_t) (interface{}, string) {
	if bitString.buf == nil || bitString.size == 0 {
		return "Invalid", "Empty or null buffer"
	}

	data := C.GoBytes(unsafe.Pointer(bitString.buf), C.int(bitString.size))
	hexStr := hex.EncodeToString(data)
	
	// Extended UEIdentityIndexValue is 14 bits according to spec
	// Wireshark format: "9b14 [bit length 14, 2 LSB pad bits, 1001 1011  0001 01.. decimal value 9925]"
	
	if len(data) >= 2 {
		// Extract full 16-bit value for bit manipulation
		fullValue := binary.BigEndian.Uint16(data)
		
		// Extract 14 most significant bits (right shift by 2 to remove padding)
		value := fullValue >> 2
		
		// Calculate padding bits (2 LSB pad bits for 14-bit value in 16-bit field)
		padBits := 2
		
		// Format binary representation like Wireshark with proper bit masking
		binaryFull := fmt.Sprintf("%016b", fullValue)
		// Show the 14 significant bits and 2 padding bits: "1001 1011  0001 01.."
		binaryFormatted := fmt.Sprintf("%s %s  %s %s", 
			binaryFull[0:4], binaryFull[4:8], binaryFull[8:12], binaryFull[12:14]+"..")
		
		rawValue := fmt.Sprintf("%s [bit length 14, %d LSB pad bits, %s decimal value %d]",
			hexStr, padBits, binaryFormatted, value)
		
		return int(value), rawValue
	} else if len(data) == 1 {
		// Single byte case  
		fullValue := uint16(data[0]) << 8 // Shift to MSB position
		value := fullValue >> 2           // Extract 14 bits
		binaryFormatted := fmt.Sprintf("%08b", data[0])
		
		rawValue := fmt.Sprintf("%s [bit length 14, %s decimal value %d]", hexStr, binaryFormatted, value)
		return int(value), rawValue
	}
	
	return hexStr, "0x" + hexStr
}

// Enhanced UEPagingID extraction matching Wireshark format
func extractDetailedUEPagingID(pagingID *C.UEPagingID_t) (interface{}, string) {
	switch pagingID.present {
	case C.UEPagingID_PR_s_TMSI:
		// Use C function to extract S-TMSI data safely
		s_tmsi := *(**C.S_TMSI_t)(unsafe.Pointer(&pagingID.choice[0]))
		if s_tmsi != nil {
			stmsiData := C.extractSTMSIData(unsafe.Pointer(s_tmsi))
			
			if stmsiData.valid == 1 {
				mmecValue := uint8(stmsiData.mmec)
				mtmsiValue := uint32(stmsiData.mtmsi)
				
				// Format according to Wireshark: "UEPagingID: s-TMSI (0)" with detailed fields
				value := "s-TMSI (0)"
				rawValue := fmt.Sprintf("mMEC: %d (0x%02x), m-TMSI: %d (0x%08x)", 
					mmecValue, mmecValue, mtmsiValue, mtmsiValue)
				
				return value, rawValue
			}
		}
		return "s-TMSI (extraction failed)", "S-TMSI extraction failed"
		
	case C.UEPagingID_PR_iMSI:
		// Extract IMSI with BCD decoding
		imsi_ptr := (*C.IMSI_t)(unsafe.Pointer(&pagingID.choice[0]))
		if imsi_ptr.buf != nil && imsi_ptr.size > 0 {
			imsiData := C.GoBytes(unsafe.Pointer(imsi_ptr.buf), C.int(imsi_ptr.size))
			imsiStr := decodeIMSI(imsiData)
			value := "iMSI (1)"
			rawValue := fmt.Sprintf("IMSI: %s", imsiStr)
			return value, rawValue
		} else {
			return "iMSI(Invalid)", "Empty IMSI buffer"
		}
		
	default:
		return "Unknown", fmt.Sprintf("UEPagingID type %d", pagingID.present)
	}
}

// Enhanced TAIList extraction matching Wireshark format
func extractDetailedTAIList(taiList *C.TAIList_t) (interface{}, string) {
	if taiList == nil || taiList.list.count == 0 {
		return "Empty TAI List", "TAI List: empty"
	}

	count := int(taiList.list.count)
	
	// Get TAI Items from protocol container array
	var taiContainers []*C.ProtocolIE_SingleContainer_8146P7_t
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&taiContainers))
	slice.Cap = count
	slice.Len = count
	slice.Data = uintptr(unsafe.Pointer(taiList.list.array))

	if len(taiContainers) > 0 && taiContainers[0] != nil {
		// Get the first TAI item - TAIItemIEs has TAIItem in its choice
		container := taiContainers[0]
		// Cast to TAIItemIEs structure and access the TAIItem
		taiItemPtr := (*C.TAIItem_t)(unsafe.Pointer(&container.value.choice))
		if taiItemPtr != nil {
			// Use C function to extract TAI data safely
			taiData := C.extractTAIData(unsafe.Pointer(taiItemPtr))
			
			if taiData.valid == 1 {
				// Decode PLMN identity from the 3 bytes
				plmnBytes := C.GoBytes(unsafe.Pointer(&taiData.plmn[0]), 3)
				plmnHex := hex.EncodeToString(plmnBytes)
				mcc, mnc := decodePLMNIdentity(plmnBytes)
				
				// TAC value
				tacValue := uint16(taiData.tac)
				
				// Format like Wireshark output
				var value string
				if count == 1 {
					value = "1 item"
				} else {
					value = fmt.Sprintf("%d items", count)
				}
				
				rawValue := fmt.Sprintf("Item 0: id-TAIItem - pLMNidentity: %s, Mobile Country Code (MCC): %s, Mobile Network Code (MNC): %s, tAC: %d (0x%04x)", 
					plmnHex, getMCCDescription(mcc), getMNCDescription(mnc), tacValue, tacValue)
				
				return value, rawValue
			}
		}
	}
	
	// Fallback if extraction failed
	return fmt.Sprintf("TAI List (%d items)", count), "TAI List: extraction failed"
}

// Helper functions for MCC/MNC descriptions (matching Wireshark)
func getMCCDescription(mcc string) string {
	switch mcc {
	case "605":
		return "Tunisia (605)"
	case "001":
		return "Test (001)"
	default:
		return fmt.Sprintf("Unknown (%s)", mcc)
	}
}

func getMNCDescription(mnc string) string {
	switch mnc {
	case "01":
		return "Unknown (01)"
	case "02":
		return "Unknown (02)"
	default:
		return fmt.Sprintf("Unknown (%s)", mnc)
	}
}

// Enhanced E-RAB Setup List extraction matching Wireshark format
func extractDetailedERABSetupList(erabList *C.E_RABSetupListCtxtSURes_t) (interface{}, string) {
	if erabList == nil || erabList.list.count == 0 {
		return "Empty E-RAB Setup List", "E-RAB Setup List: empty"
	}

	count := int(erabList.list.count)
	
	// Get E-RAB Setup Items from protocol container array
	var erabContainers []*C.ProtocolIE_SingleContainer_8146P6_t
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&erabContainers))
	slice.Cap = count
	slice.Len = count
	slice.Data = uintptr(unsafe.Pointer(erabList.list.array))

	if len(erabContainers) > 0 && erabContainers[0] != nil {
		// Get the first E-RAB Setup item
		container := erabContainers[0]
		// Cast to E-RABSetupItemCtxtSURes structure
		erabItemPtr := (*C.E_RABSetupItemCtxtSURes_t)(unsafe.Pointer(&container.value.choice))
		if erabItemPtr != nil {
			// Use C function to extract E-RAB data safely
			erabData := C.extractERABSetupItemData(unsafe.Pointer(erabItemPtr))
			
			if erabData.valid == 1 {
				// Extract transport layer address
				transportBytes := C.GoBytes(unsafe.Pointer(&erabData.transport_address[0]), C.int(erabData.transport_address_len))
				transportHex := hex.EncodeToString(transportBytes)
				
				// Format IP address (assuming IPv4 for now)
				var ipStr string
				if len(transportBytes) == 4 {
					ipAddr := net.IPv4(transportBytes[0], transportBytes[1], transportBytes[2], transportBytes[3])
					ipStr = ipAddr.String()
				} else {
					ipStr = "unknown format"
				}
				
				// Calculate decimal value for transport address
				var decimalValue uint32
				if len(transportBytes) >= 4 {
					decimalValue = binary.BigEndian.Uint32(transportBytes[:4])
				}
				
				// Format binary representation
				var binaryStr string
				if len(transportBytes) == 4 {
					binaryStr = fmt.Sprintf("%08b  %08b  %08b  %08b", 
						transportBytes[0], transportBytes[1], transportBytes[2], transportBytes[3])
				}
				
				// GTP TEID
				gtpTeidValue := uint32(erabData.gtp_teid)
				gtpTeidHex := fmt.Sprintf("%08x", gtpTeidValue)
				
				// Format like Wireshark output
				var value string
				if count == 1 {
					value = "1 item"
				} else {
					value = fmt.Sprintf("%d items", count)
				}
				
				rawValue := fmt.Sprintf("Item 0: id-E-RABSetupItemCtxtSURes - e-RAB-ID: %d, transportLayerAddress: %s [bit length %d, %s decimal value %d], transportLayerAddress(IPv4): %s, gTP-TEID: %s", 
					erabData.erab_id, transportHex, len(transportBytes)*8, binaryStr, decimalValue, ipStr, gtpTeidHex)
				
				return value, rawValue
			}
		}
	}
	
	// Fallback if extraction failed
	return fmt.Sprintf("E-RAB Setup List (%d items)", count), "E-RAB Setup List: extraction failed"
}

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
			// Extract UE Identity Index Value with Wireshark-style formatting
			bitString := (*C.BIT_STRING_t)(unsafe.Pointer(&ie.value.choice))
			value, rawValue := extractDetailedUEIdentityIndexValue(bitString)
			ieStruct.Value = value
			ieStruct.RawValue = rawValue
			log.Printf("DEBUG: UEIdentityIndexValue - value: %v", value)

		case C.ProtocolIE_ID_id_UEPagingID:
			// Extract UE Paging ID with Wireshark-style formatting
			pagingID := (*C.UEPagingID_t)(unsafe.Pointer(&ie.value.choice))
			value, rawValue := extractDetailedUEPagingID(pagingID)
			ieStruct.Value = value
			ieStruct.RawValue = rawValue
			log.Printf("DEBUG: UEPagingID - value: %v", value)

		case C.ProtocolIE_ID_id_CNDomain:
			// Extract CN Domain with Wireshark-style formatting
			cnDomain := (*C.CNDomain_t)(unsafe.Pointer(&ie.value.choice))
			var domainStr string
			switch *cnDomain {
			case C.CNDomain_ps:
				domainStr = "ps (0)"
			case C.CNDomain_cs:
				domainStr = "cs (1)"
			default:
				domainStr = fmt.Sprintf("unknown (%d)", int(*cnDomain))
			}
			ieStruct.Value = domainStr
			ieStruct.RawValue = fmt.Sprintf("%d", int(*cnDomain))
			log.Printf("DEBUG: CNDomain: %s", domainStr)

		case C.ProtocolIE_ID_id_TAIList:
			// Extract TAI List with Wireshark-style formatting
			taiList := (*C.TAIList_t)(unsafe.Pointer(&ie.value.choice))
			value, rawValue := extractDetailedTAIList(taiList)
			ieStruct.Value = value
			ieStruct.RawValue = rawValue
			log.Printf("DEBUG: TAIList - value: %v", value)

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
			// Extract Extended UE Identity Index Value with Wireshark-style formatting  
			bitString := (*C.BIT_STRING_t)(unsafe.Pointer(&ie.value.choice))
			value, rawValue := extractDetailedExtendedUEIdentityIndexValue(bitString)
			ieStruct.Value = value
			ieStruct.RawValue = rawValue
			log.Printf("DEBUG: Extended UEIdentityIndexValue - value: %v", value)

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

// Helper function to extract IEs from TraceFailureIndication
func extractTraceFailureIndicationIEs(packet unsafe.Pointer) []*InformationElement {
	log.Printf("DEBUG: Enhanced TraceFailureIndication IE extraction started")
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.TraceFailureIndication_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.TraceFailureIndicationIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	log.Printf("DEBUG: TraceFailureIndication IE count: %d", len(ies))

	for i, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		log.Printf("DEBUG: Processing TraceFailureIndication IE[%d] - ID: %d, Name: %s", i, ie.id, ieStruct.Name)

		switch ie.id {
		case C.ProtocolIE_ID_id_MME_UE_S1AP_ID:
			mme_id := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*mme_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*mme_id))
			log.Printf("DEBUG: Extracted MME_UE_S1AP_ID: %d", int32(*mme_id))
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*enb_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*enb_id))
			log.Printf("DEBUG: Extracted eNB_UE_S1AP_ID: %d", int32(*enb_id))
		case C.ProtocolIE_ID_id_E_UTRAN_Trace_ID:
			ieStruct.Value, ieStruct.RawValue = extractDetailedEUTRANTraceID(unsafe.Pointer(&ie.value.choice[0]))
			log.Printf("DEBUG: Extracted E_UTRAN_Trace_ID")
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
			// Extract Trace Collection Entity IP Address with detailed format
			ieStruct.Value, ieStruct.RawValue = extractDetailedTransportLayerAddress(unsafe.Pointer(&ie.value.choice[0]))
			log.Printf("DEBUG: TraceCollectionEntityIPAddress extracted")
		case C.ProtocolIE_ID_id_Cause:
			ieStruct.Value, ieStruct.RawValue = extractDetailedCause(unsafe.Pointer(&ie.value.choice[0]))
			log.Printf("DEBUG: Extracted Cause IE")
		default:
			ieStruct.Value = fmt.Sprintf("Unknown_TraceFailureIndication_IE_%d", ie.id)
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
			log.Printf("DEBUG: Unknown TraceFailureIndication IE - ID: %d", ie.id)
		}

		result = append(result, ieStruct)
	}

	log.Printf("DEBUG: TraceFailureIndication IE extraction completed - %d IEs extracted", len(result))
	return result
}

// Helper function to extract IEs from PathSwitchRequest
func extractPathSwitchRequestIEs(packet unsafe.Pointer) []*InformationElement {
	log.Printf("DEBUG: Enhanced PathSwitchRequest IE extraction started")
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	msg := *(**C.InitiatingMessage_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.PathSwitchRequest_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.PathSwitchRequestIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	log.Printf("DEBUG: PathSwitchRequest IE count: %d", len(ies))

	for i, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		log.Printf("DEBUG: Processing PathSwitchRequest IE[%d] - ID: %d, Name: %s", i, ie.id, ieStruct.Name)

		switch ie.id {
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*enb_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*enb_id))
			log.Printf("DEBUG: Extracted eNB_UE_S1AP_ID: %d", int32(*enb_id))
		case C.ProtocolIE_ID_id_E_RABToBeSwitchedDLList:
			ieStruct.Value = "E_RABToBeSwitchedDLList (bearer information)"
			ieStruct.RawValue = "E_RABToBeSwitchedDLList structure present"
			log.Printf("DEBUG: Extracted E_RABToBeSwitchedDLList")
		case C.ProtocolIE_ID_id_EUTRAN_CGI:
			ieStruct.Value = "EUTRAN_CGI (source cell)"
			ieStruct.RawValue = "EUTRAN_CGI structure present"
			log.Printf("DEBUG: Extracted Source EUTRAN_CGI")
		case C.ProtocolIE_ID_id_TAI:
			ieStruct.Value = "TAI (target tracking area)"
			ieStruct.RawValue = "TAI structure present"
			log.Printf("DEBUG: Extracted TAI")
		case C.ProtocolIE_ID_id_UESecurityCapabilities:
			ieStruct.Value = "UESecurityCapabilities"
			ieStruct.RawValue = "UESecurityCapabilities structure present"
			log.Printf("DEBUG: Extracted UESecurityCapabilities")
		default:
			ieStruct.Value = fmt.Sprintf("Unknown_PathSwitchRequest_IE_%d", ie.id)
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
			log.Printf("DEBUG: Unknown PathSwitchRequest IE - ID: %d", ie.id)
		}

		result = append(result, ieStruct)
	}

	log.Printf("DEBUG: PathSwitchRequest IE extraction completed - %d IEs extracted", len(result))
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
	case 13: // UplinkNASTransport
		return extractUplinkNASTransportIEs(packet)
	case 18: // UEContextReleaseRequest
		return extractUEContextReleaseRequestIEs(packet)
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
	log.Printf("DEBUG: Enhanced InitialContextSetupResponse IE extraction started")
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	if pdu.present != C.S1AP_PDU_PR_successfulOutcome {
		return result
	}

	msg := *(**C.SuccessfulOutcome_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.InitialContextSetupResponse_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.InitialContextSetupResponseIEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	log.Printf("DEBUG: InitialContextSetupResponse IE count: %d", len(ies))

	for i, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		log.Printf("DEBUG: Processing InitialContextSetupResponse IE[%d] - ID: %d, Name: %s", i, ie.id, ieStruct.Name)

		switch ie.id {
		case C.ProtocolIE_ID_id_MME_UE_S1AP_ID:
			mme_id := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*mme_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*mme_id))
			log.Printf("DEBUG: Extracted MME_UE_S1AP_ID: %d", int32(*mme_id))
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*enb_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*enb_id))
			log.Printf("DEBUG: Extracted eNB_UE_S1AP_ID: %d", int32(*enb_id))
		case C.ProtocolIE_ID_id_E_RABSetupListCtxtSURes:
			// Extract E-RAB Setup List with detailed information
			erabList := (*C.E_RABSetupListCtxtSURes_t)(unsafe.Pointer(&ie.value.choice))
			value, rawValue := extractDetailedERABSetupList(erabList)
			ieStruct.Value = value
			ieStruct.RawValue = rawValue
			log.Printf("DEBUG: Extracted detailed E-RAB Setup List")
		case C.ProtocolIE_ID_id_E_RABFailedToSetupListCtxtSURes:
			ieStruct.Value = "E-RAB Failed to Setup List"
			ieStruct.RawValue = "E-RAB Failed to Setup List structure present"
			log.Printf("DEBUG: Extracted E-RAB Failed to Setup List")
		default:
			ieStruct.Value = fmt.Sprintf("Unknown_IE_%d", ie.id)
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
			log.Printf("DEBUG: Unknown InitialContextSetupResponse IE - ID: %d", ie.id)
		}

		result = append(result, ieStruct)
	}

	log.Printf("DEBUG: InitialContextSetupResponse IE extraction completed - %d IEs extracted", len(result))
	return result
}

func extractHandoverCommandIEs(packet unsafe.Pointer) []*InformationElement {
	return extractGenericIEs(packet, 12) // HandoverCommand
}

func extractUEContextReleaseCompleteIEs(packet unsafe.Pointer) []*InformationElement {
	log.Printf("DEBUG: Enhanced UEContextReleaseComplete IE extraction started")
	var result []*InformationElement

	pdu := (*C.S1AP_PDU_t)(packet)
	if pdu.present != C.S1AP_PDU_PR_successfulOutcome {
		log.Printf("DEBUG: PDU is not successfulOutcome: %d", pdu.present)
		return result
	}

	msg := *(**C.SuccessfulOutcome_t)(unsafe.Pointer(&pdu.choice))
	val := (*C.UEContextReleaseComplete_t)(unsafe.Pointer(&msg.value.choice))

	var ies []*C.UEContextReleaseComplete_IEs_t
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&ies)))
	slice.Cap = (int)(val.protocolIEs.list.count)
	slice.Len = (int)(val.protocolIEs.list.count)
	slice.Data = uintptr(unsafe.Pointer(val.protocolIEs.list.array))

	log.Printf("DEBUG: UEContextReleaseComplete IE count: %d", len(ies))

	for i, ie := range ies {
		ieStruct := &InformationElement{
			ID:          int(ie.id),
			Name:        GetIEName(int(ie.id)),
			Criticality: getCriticalityString(int(ie.criticality)),
		}

		log.Printf("DEBUG: Processing UEContextReleaseComplete IE[%d] - ID: %d, Name: %s", i, ie.id, ieStruct.Name)

		switch ie.id {
		case C.ProtocolIE_ID_id_MME_UE_S1AP_ID:
			mme_id := (*C.MME_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*mme_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*mme_id))
			log.Printf("DEBUG: Extracted MME_UE_S1AP_ID: %d", int32(*mme_id))
		case C.ProtocolIE_ID_id_eNB_UE_S1AP_ID:
			enb_id := (*C.ENB_UE_S1AP_ID_t)(unsafe.Pointer(&ie.value.choice))
			ieStruct.Value = int32(*enb_id)
			ieStruct.RawValue = fmt.Sprintf("%d", int32(*enb_id))
			log.Printf("DEBUG: Extracted eNB_UE_S1AP_ID: %d", int32(*enb_id))
		case C.ProtocolIE_ID_id_CriticalityDiagnostics:
			ieStruct.Value = "Criticality Diagnostics"
			ieStruct.RawValue = "Criticality Diagnostics structure present"
			log.Printf("DEBUG: Extracted Criticality Diagnostics")
		default:
			ieStruct.Value = fmt.Sprintf("Unknown_IE_%d", ie.id)
			ieStruct.RawValue = fmt.Sprintf("IE_%d present", ie.id)
			log.Printf("DEBUG: Unknown UEContextReleaseComplete IE - ID: %d", ie.id)
		}

		result = append(result, ieStruct)
	}

	log.Printf("DEBUG: UEContextReleaseComplete IE extraction completed - %d IEs extracted", len(result))
	return result
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

	// Extraire PLMN identity
	var plmnData []byte
	slice := (*reflect.SliceHeader)((unsafe.Pointer(&plmnData)))
	slice.Cap = (int)(tai.pLMNidentity.size)
	slice.Len = (int)(tai.pLMNidentity.size)
	slice.Data = uintptr(unsafe.Pointer(tai.pLMNidentity.buf))

	if len(plmnData) < 3 {
		return "TAI: invalid PLMN size", fmt.Sprintf("PLMN size: %d", len(plmnData))
	}

	mcc, mnc := decodePLMNIdentity(plmnData)

	// Extraire TAC
	var tacData []byte
	tacSlice := (*reflect.SliceHeader)((unsafe.Pointer(&tacData)))
	tacSlice.Cap = (int)(tai.tAC.size)
	tacSlice.Len = (int)(tai.tAC.size)
	tacSlice.Data = uintptr(unsafe.Pointer(tai.tAC.buf))

	var tac uint16
	if len(tacData) >= 2 {
		tac = uint16(tacData[0])<<8 | uint16(tacData[1])
	}

	value := fmt.Sprintf("TAI(MCC=%s,MNC=%s,TAC=%d)", mcc, mnc, tac)
	rawValue := fmt.Sprintf("PLMN=%s,TAC=%04x", hex.EncodeToString(plmnData), tac)

	return value, rawValue
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

	value := fmt.Sprintf("RRC_Cause(%s)", causeStr)
	rawValue := fmt.Sprintf("%d", *cause)

	return value, rawValue
}

// Fonction pour décoder Cause détaillé
func extractDetailedCause(ie_ptr unsafe.Pointer) (string, string) {
	cause := (*C.Cause_t)(ie_ptr)
	
	switch cause.present {
	case C.Cause_PR_radioNetwork:
		radioNetworkCause := (*C.CauseRadioNetwork_t)(unsafe.Pointer(&cause.choice[0]))
		causeStr := getCauseRadioNetworkString(*radioNetworkCause)
		value := fmt.Sprintf("Cause: radioNetwork (%d) - %s", C.Cause_PR_radioNetwork-1, causeStr)
		rawValue := fmt.Sprintf("radioNetwork: %s (%d)", causeStr, *radioNetworkCause)
		return value, rawValue
		
	case C.Cause_PR_transport:
		transportCause := (*C.CauseTransport_t)(unsafe.Pointer(&cause.choice[0]))
		causeStr := getCauseTransportString(*transportCause)
		value := fmt.Sprintf("Cause: transport (%d) - %s", C.Cause_PR_transport-1, causeStr)
		rawValue := fmt.Sprintf("transport: %s (%d)", causeStr, *transportCause)
		return value, rawValue
		
	case C.Cause_PR_nas:
		nasCause := (*C.CauseNas_t)(unsafe.Pointer(&cause.choice[0]))
		causeStr := getCauseNasString(*nasCause)
		value := fmt.Sprintf("Cause: nas (%d) - %s", C.Cause_PR_nas-1, causeStr)
		rawValue := fmt.Sprintf("nas: %s (%d)", causeStr, *nasCause)
		return value, rawValue
		
	case C.Cause_PR_protocol:
		protocolCause := (*C.CauseProtocol_t)(unsafe.Pointer(&cause.choice[0]))
		causeStr := getCauseProtocolString(*protocolCause)
		value := fmt.Sprintf("Cause: protocol (%d) - %s", C.Cause_PR_protocol-1, causeStr)
		rawValue := fmt.Sprintf("protocol: %s (%d)", causeStr, *protocolCause)
		return value, rawValue
		
	case C.Cause_PR_misc:
		miscCause := (*C.CauseMisc_t)(unsafe.Pointer(&cause.choice[0]))
		causeStr := getCauseMiscString(*miscCause)
		value := fmt.Sprintf("Cause: misc (%d) - %s", C.Cause_PR_misc-1, causeStr)
		rawValue := fmt.Sprintf("misc: %s (%d)", causeStr, *miscCause)
		return value, rawValue
		
	default:
		return "Cause: unknown", fmt.Sprintf("unknown cause type (%d)", cause.present)
	}
}

// Fonction pour obtenir la chaîne RadioNetwork cause
func getCauseRadioNetworkString(cause C.CauseRadioNetwork_t) string {
	switch cause {
	case C.CauseRadioNetwork_unspecified:
		return "unspecified"
	case C.CauseRadioNetwork_tx2relocoverall_expiry:
		return "tx2relocoverall-expiry"
	case C.CauseRadioNetwork_successful_handover:
		return "successful-handover"
	case C.CauseRadioNetwork_release_due_to_eutran_generated_reason:
		return "release-due-to-eutran-generated-reason"
	case C.CauseRadioNetwork_handover_cancelled:
		return "handover-cancelled"
	case C.CauseRadioNetwork_partial_handover:
		return "partial-handover"
	case C.CauseRadioNetwork_ho_failure_in_target_EPC_eNB_or_target_system:
		return "ho-failure-in-target-EPC-eNB-or-target-system"
	case C.CauseRadioNetwork_ho_target_not_allowed:
		return "ho-target-not-allowed"
	case C.CauseRadioNetwork_tS1relocoverall_expiry:
		return "tS1relocoverall-expiry"
	case C.CauseRadioNetwork_tS1relocprep_expiry:
		return "tS1relocprep-expiry"
	case C.CauseRadioNetwork_cell_not_available:
		return "cell-not-available"
	case C.CauseRadioNetwork_unknown_targetID:
		return "unknown-targetID"
	case C.CauseRadioNetwork_no_radio_resources_available_in_target_cell:
		return "no-radio-resources-available-in-target-cell"
	case C.CauseRadioNetwork_unknown_mme_ue_s1ap_id:
		return "unknown-mme-ue-s1ap-id"
	case C.CauseRadioNetwork_unknown_enb_ue_s1ap_id:
		return "unknown-enb-ue-s1ap-id"
	case C.CauseRadioNetwork_unknown_pair_ue_s1ap_id:
		return "unknown-pair-ue-s1ap-id"
	case C.CauseRadioNetwork_handover_desirable_for_radio_reason:
		return "handover-desirable-for-radio-reason"
	case C.CauseRadioNetwork_time_critical_handover:
		return "time-critical-handover"
	case C.CauseRadioNetwork_resource_optimisation_handover:
		return "resource-optimisation-handover"
	case C.CauseRadioNetwork_reduce_load_in_serving_cell:
		return "reduce-load-in-serving-cell"
	case C.CauseRadioNetwork_user_inactivity:
		return "user-inactivity"
	case C.CauseRadioNetwork_radio_connection_with_ue_lost:
		return "radio-connection-with-ue-lost"
	case C.CauseRadioNetwork_load_balancing_tau_required:
		return "load-balancing-tau-required"
	case C.CauseRadioNetwork_cs_fallback_triggered:
		return "cs-fallback-triggered"
	case C.CauseRadioNetwork_ue_not_available_for_ps_service:
		return "ue-not-available-for-ps-service"
	case C.CauseRadioNetwork_radio_resources_not_available:
		return "radio-resources-not-available"
	case C.CauseRadioNetwork_failure_in_radio_interface_procedure:
		return "failure-in-radio-interface-procedure"
	case C.CauseRadioNetwork_invalid_qos_combination:
		return "invalid-qos-combination"
	case C.CauseRadioNetwork_interrat_redirection:
		return "interrat-redirection"
	case C.CauseRadioNetwork_interaction_with_other_procedure:
		return "interaction-with-other-procedure"
	case C.CauseRadioNetwork_unknown_E_RAB_ID:
		return "unknown-E-RAB-ID"
	case C.CauseRadioNetwork_multiple_E_RAB_ID_instances:
		return "multiple-E-RAB-ID-instances"
	case C.CauseRadioNetwork_encryption_and_or_integrity_protection_algorithms_not_supported:
		return "encryption-and-or-integrity-protection-algorithms-not-supported"
	case C.CauseRadioNetwork_s1_intra_system_handover_triggered:
		return "s1-intra-system-handover-triggered"
	case C.CauseRadioNetwork_s1_inter_system_handover_triggered:
		return "s1-inter-system-handover-triggered"
	case C.CauseRadioNetwork_x2_handover_triggered:
		return "x2-handover-triggered"
	case C.CauseRadioNetwork_redirection_towards_1xRTT:
		return "redirection-towards-1xRTT"
	case C.CauseRadioNetwork_not_supported_QCI_value:
		return "not-supported-QCI-value"
	case C.CauseRadioNetwork_invalid_CSG_Id:
		return "invalid-CSG-Id"
	case C.CauseRadioNetwork_release_due_to_pre_emption:
		return "release-due-to-pre-emption"
	case C.CauseRadioNetwork_n26_interface_not_available:
		return "n26-interface-not-available"
	case C.CauseRadioNetwork_insufficient_ue_capabilities:
		return "insufficient-ue-capabilities"
	case C.CauseRadioNetwork_maximum_bearer_pre_emption_rate_exceeded:
		return "maximum-bearer-pre-emption-rate-exceeded"
	case C.CauseRadioNetwork_up_integrity_protection_not_possible:
		return "up-integrity-protection-not-possible"
	default:
		return fmt.Sprintf("unknown-radio-network-cause(%d)", cause)
	}
}

// Fonction pour obtenir la chaîne Transport cause (exemple basique)
func getCauseTransportString(cause C.CauseTransport_t) string {
	// Les valeurs de CauseTransport dépendent de l'implémentation
	return fmt.Sprintf("transport-cause(%d)", cause)
}

// Fonction pour obtenir la chaîne NAS cause (exemple basique)
func getCauseNasString(cause C.CauseNas_t) string {
	// Les valeurs de CauseNas dépendent de l'implémentation
	return fmt.Sprintf("nas-cause(%d)", cause)
}

// Fonction pour obtenir la chaîne Protocol cause (exemple basique)
func getCauseProtocolString(cause C.CauseProtocol_t) string {
	// Les valeurs de CauseProtocol dépendent de l'implémentation
	return fmt.Sprintf("protocol-cause(%d)", cause)
}

// Fonction pour obtenir la chaîne Misc cause (exemple basique)
func getCauseMiscString(cause C.CauseMisc_t) string {
	// Les valeurs de CauseMisc dépendent de l'implémentation
	return fmt.Sprintf("misc-cause(%d)", cause)
}

// Fonction pour décoder E-UTRAN Trace ID détaillé
func extractDetailedEUTRANTraceID(ie_ptr unsafe.Pointer) (string, string) {
	traceID := (*C.E_UTRAN_Trace_ID_t)(ie_ptr)
	
	if traceID.size < 8 {
		return "E_UTRAN_Trace_ID (insufficient data)", "Insufficient trace ID data"
	}
	
	// Convertir en slice Go
	data := C.GoBytes(unsafe.Pointer(traceID.buf), C.int(traceID.size))
	
	// Format: 06f5100003a3e9cc
	hexStr := hex.EncodeToString(data)
	
	// Extraire les composants (basé sur l'exemple Wireshark)
	if len(data) >= 8 {
		// PLMN (3 bytes) + Trace ID (3 bytes) + Trace Recording Session Reference (2 bytes)
		plmn := data[0:3]
		traceIDBytes := data[3:6]
		sessionRef := data[6:8]
		
		// Décoder MCC/MNC du PLMN
		mcc, mnc := decodePLMNIdentity(plmn)
		
		value := fmt.Sprintf("E-UTRAN-Trace-ID: %s (MCC=%s, MNC=%s, TraceID=0x%x, Session=0x%x)", 
			hexStr, mcc, mnc, traceIDBytes, sessionRef)
		rawValue := fmt.Sprintf("Mobile Country Code (MCC): %s, Mobile Network Code (MNC): %s, TraceID: 0x%x, TraceRecordingSessionReference: 0x%x", 
			mcc, mnc, traceIDBytes, sessionRef)
		
		return value, rawValue
	}
	
	value := fmt.Sprintf("E-UTRAN-Trace-ID: %s", hexStr)
	rawValue := fmt.Sprintf("E-UTRAN Trace ID: %s", hexStr)
	
	return value, rawValue
}

// Fonction pour décoder TransportLayerAddress détaillé
func extractDetailedTransportLayerAddress(ie_ptr unsafe.Pointer) (string, string) {
	tla := (*C.TransportLayerAddress_t)(ie_ptr)
	
	if tla.size < 4 {
		return "Invalid IP", "Insufficient IP address data"
	}
	
	// Convertir en slice Go
	data := C.GoBytes(unsafe.Pointer(tla.buf), C.int(tla.size))
	
	// Calculer la longueur en bits
	bitLength := int(tla.bits_unused)
	totalBits := len(data)*8 - bitLength
	
	hexStr := hex.EncodeToString(data)
	
	if len(data) == 4 {
		// IPv4
		ip := net.IP(data)
		value := fmt.Sprintf("IP: %s", ip.String())
		rawValue := fmt.Sprintf("TransportLayerAddress: %s [bit length %d, %s decimal value %d]", 
			hexStr, totalBits, formatBinaryString(data), binary.BigEndian.Uint32(data))
		return value, rawValue
	} else if len(data) == 16 {
		// IPv6
		ip := net.IP(data)
		value := fmt.Sprintf("IP: %s", ip.String())
		rawValue := fmt.Sprintf("TransportLayerAddress: %s [bit length %d]", hexStr, totalBits)
		return value, rawValue
	}
	
	// Format générique
	value := fmt.Sprintf("TransportLayerAddress: %s", hexStr)
	rawValue := fmt.Sprintf("TransportLayerAddress: %s [bit length %d]", hexStr, totalBits)
	
	return value, rawValue
}

// Fonction pour formater une chaîne binaire avec espaces
func formatBinaryString(data []byte) string {
	var result strings.Builder
	for i, b := range data {
		if i > 0 {
			result.WriteString("  ")
		}
		result.WriteString(fmt.Sprintf("%08b", b))
	}
	return result.String()
}
