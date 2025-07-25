/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Descriptions"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_SuccessfulOutcome_H_
#define	_SuccessfulOutcome_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ProcedureCode.h"
#include "Criticality.h"
#include <ANY.h>
#include <asn_ioc.h>
#include "HandoverRequired.h"
#include "HandoverCommand.h"
#include "HandoverPreparationFailure.h"
#include "HandoverRequest.h"
#include "HandoverRequestAcknowledge.h"
#include "HandoverFailure.h"
#include "PathSwitchRequest.h"
#include "PathSwitchRequestAcknowledge.h"
#include "PathSwitchRequestFailure.h"
#include "E-RABSetupRequest.h"
#include "E-RABSetupResponse.h"
#include "E-RABModifyRequest.h"
#include "E-RABModifyResponse.h"
#include "E-RABReleaseCommand.h"
#include "E-RABReleaseResponse.h"
#include "InitialContextSetupRequest.h"
#include "InitialContextSetupResponse.h"
#include "InitialContextSetupFailure.h"
#include "HandoverCancel.h"
#include "HandoverCancelAcknowledge.h"
#include "KillRequest.h"
#include "KillResponse.h"
#include "Reset.h"
#include "ResetAcknowledge.h"
#include "S1SetupRequest.h"
#include "S1SetupResponse.h"
#include "S1SetupFailure.h"
#include "UEContextModificationRequest.h"
#include "UEContextModificationResponse.h"
#include "UEContextModificationFailure.h"
#include "UEContextReleaseCommand.h"
#include "UEContextReleaseComplete.h"
#include "ENBConfigurationUpdate.h"
#include "ENBConfigurationUpdateAcknowledge.h"
#include "ENBConfigurationUpdateFailure.h"
#include "MMEConfigurationUpdate.h"
#include "MMEConfigurationUpdateAcknowledge.h"
#include "MMEConfigurationUpdateFailure.h"
#include "WriteReplaceWarningRequest.h"
#include "WriteReplaceWarningResponse.h"
#include "UERadioCapabilityMatchRequest.h"
#include "UERadioCapabilityMatchResponse.h"
#include "E-RABModificationIndication.h"
#include "E-RABModificationConfirm.h"
#include "UEContextModificationIndication.h"
#include "UEContextModificationConfirm.h"
#include "UEContextSuspendRequest.h"
#include "UEContextSuspendResponse.h"
#include "UEContextResumeRequest.h"
#include "UEContextResumeResponse.h"
#include "UEContextResumeFailure.h"
#include "UERadioCapabilityIDMappingRequest.h"
#include "UERadioCapabilityIDMappingResponse.h"
#include "HandoverNotify.h"
#include "E-RABReleaseIndication.h"
#include "Paging.h"
#include "DownlinkNASTransport.h"
#include "InitialUEMessage.h"
#include "UplinkNASTransport.h"
#include "ErrorIndication.h"
#include "NASNonDeliveryIndication.h"
#include "UEContextReleaseRequest.h"
#include "DownlinkS1cdma2000tunnelling.h"
#include "UplinkS1cdma2000tunnelling.h"
#include "UECapabilityInfoIndication.h"
#include "ENBStatusTransfer.h"
#include "MMEStatusTransfer.h"
#include "DeactivateTrace.h"
#include "TraceStart.h"
#include "TraceFailureIndication.h"
#include "CellTrafficTrace.h"
#include "LocationReportingControl.h"
#include "LocationReportingFailureIndication.h"
#include "LocationReport.h"
#include "OverloadStart.h"
#include "OverloadStop.h"
#include "ENBDirectInformationTransfer.h"
#include "MMEDirectInformationTransfer.h"
#include "ENBConfigurationTransfer.h"
#include "MMEConfigurationTransfer.h"
#include "PrivateMessage.h"
#include "DownlinkUEAssociatedLPPaTransport.h"
#include "UplinkUEAssociatedLPPaTransport.h"
#include "DownlinkNonUEAssociatedLPPaTransport.h"
#include "UplinkNonUEAssociatedLPPaTransport.h"
#include "PWSRestartIndication.h"
#include "RerouteNASRequest.h"
#include "PWSFailureIndication.h"
#include "ConnectionEstablishmentIndication.h"
#include "NASDeliveryIndication.h"
#include "RetrieveUEInformation.h"
#include "UEInformationTransfer.h"
#include "ENBCPRelocationIndication.h"
#include "MMECPRelocationIndication.h"
#include "SecondaryRATDataUsageReport.h"
#include "HandoverSuccess.h"
#include "ENBEarlyStatusTransfer.h"
#include "MMEEarlyStatusTransfer.h"
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SuccessfulOutcome__value_PR {
	SuccessfulOutcome__value_PR_NOTHING,	/* No components present */
	SuccessfulOutcome__value_PR_HandoverCommand,
	SuccessfulOutcome__value_PR_HandoverRequestAcknowledge,
	SuccessfulOutcome__value_PR_PathSwitchRequestAcknowledge,
	SuccessfulOutcome__value_PR_E_RABSetupResponse,
	SuccessfulOutcome__value_PR_E_RABModifyResponse,
	SuccessfulOutcome__value_PR_E_RABReleaseResponse,
	SuccessfulOutcome__value_PR_InitialContextSetupResponse,
	SuccessfulOutcome__value_PR_HandoverCancelAcknowledge,
	SuccessfulOutcome__value_PR_KillResponse,
	SuccessfulOutcome__value_PR_ResetAcknowledge,
	SuccessfulOutcome__value_PR_S1SetupResponse,
	SuccessfulOutcome__value_PR_UEContextModificationResponse,
	SuccessfulOutcome__value_PR_UEContextReleaseComplete,
	SuccessfulOutcome__value_PR_ENBConfigurationUpdateAcknowledge,
	SuccessfulOutcome__value_PR_MMEConfigurationUpdateAcknowledge,
	SuccessfulOutcome__value_PR_WriteReplaceWarningResponse,
	SuccessfulOutcome__value_PR_UERadioCapabilityMatchResponse,
	SuccessfulOutcome__value_PR_E_RABModificationConfirm,
	SuccessfulOutcome__value_PR_UEContextModificationConfirm,
	SuccessfulOutcome__value_PR_UEContextSuspendResponse,
	SuccessfulOutcome__value_PR_UEContextResumeResponse,
	SuccessfulOutcome__value_PR_UERadioCapabilityIDMappingResponse
} SuccessfulOutcome__value_PR;

/* SuccessfulOutcome */
typedef struct SuccessfulOutcome {
	ProcedureCode_t	 procedureCode;
	Criticality_t	 criticality;
	struct SuccessfulOutcome__value {
		SuccessfulOutcome__value_PR present;
		union SuccessfulOutcome__value_u {
			HandoverCommand_t	 HandoverCommand;
			HandoverRequestAcknowledge_t	 HandoverRequestAcknowledge;
			PathSwitchRequestAcknowledge_t	 PathSwitchRequestAcknowledge;
			E_RABSetupResponse_t	 E_RABSetupResponse;
			E_RABModifyResponse_t	 E_RABModifyResponse;
			E_RABReleaseResponse_t	 E_RABReleaseResponse;
			InitialContextSetupResponse_t	 InitialContextSetupResponse;
			HandoverCancelAcknowledge_t	 HandoverCancelAcknowledge;
			KillResponse_t	 KillResponse;
			ResetAcknowledge_t	 ResetAcknowledge;
			S1SetupResponse_t	 S1SetupResponse;
			UEContextModificationResponse_t	 UEContextModificationResponse;
			UEContextReleaseComplete_t	 UEContextReleaseComplete;
			ENBConfigurationUpdateAcknowledge_t	 ENBConfigurationUpdateAcknowledge;
			MMEConfigurationUpdateAcknowledge_t	 MMEConfigurationUpdateAcknowledge;
			WriteReplaceWarningResponse_t	 WriteReplaceWarningResponse;
			UERadioCapabilityMatchResponse_t	 UERadioCapabilityMatchResponse;
			E_RABModificationConfirm_t	 E_RABModificationConfirm;
			UEContextModificationConfirm_t	 UEContextModificationConfirm;
			UEContextSuspendResponse_t	 UEContextSuspendResponse;
			UEContextResumeResponse_t	 UEContextResumeResponse;
			UERadioCapabilityIDMappingResponse_t	 UERadioCapabilityIDMappingResponse;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} value;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SuccessfulOutcome_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SuccessfulOutcome;
extern asn_SEQUENCE_specifics_t asn_SPC_SuccessfulOutcome_specs_1;
extern asn_TYPE_member_t asn_MBR_SuccessfulOutcome_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _SuccessfulOutcome_H_ */
#include <asn_internal.h>
