/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Descriptions"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_S1AP_PDU_H_
#define	_S1AP_PDU_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum S1AP_PDU_PR {
	S1AP_PDU_PR_NOTHING,	/* No components present */
	S1AP_PDU_PR_initiatingMessage,
	S1AP_PDU_PR_successfulOutcome,
	S1AP_PDU_PR_unsuccessfulOutcome
	/* Extensions may appear below */
	
} S1AP_PDU_PR;

/* Forward declarations */
struct InitiatingMessage;
struct SuccessfulOutcome;
struct UnsuccessfulOutcome;

/* S1AP-PDU */
typedef struct S1AP_PDU {
	S1AP_PDU_PR present;
	union S1AP_PDU_u {
		struct InitiatingMessage	*initiatingMessage;
		struct SuccessfulOutcome	*successfulOutcome;
		struct UnsuccessfulOutcome	*unsuccessfulOutcome;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} S1AP_PDU_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_S1AP_PDU;

#ifdef __cplusplus
}
#endif

#endif	/* _S1AP_PDU_H_ */
#include <asn_internal.h>
