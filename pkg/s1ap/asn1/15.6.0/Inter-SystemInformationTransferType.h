/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_Inter_SystemInformationTransferType_H_
#define	_Inter_SystemInformationTransferType_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RIMTransfer.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Inter_SystemInformationTransferType_PR {
	Inter_SystemInformationTransferType_PR_NOTHING,	/* No components present */
	Inter_SystemInformationTransferType_PR_rIMTransfer
	/* Extensions may appear below */
	
} Inter_SystemInformationTransferType_PR;

/* Inter-SystemInformationTransferType */
typedef struct Inter_SystemInformationTransferType {
	Inter_SystemInformationTransferType_PR present;
	union Inter_SystemInformationTransferType_u {
		RIMTransfer_t	 rIMTransfer;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Inter_SystemInformationTransferType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Inter_SystemInformationTransferType;

#ifdef __cplusplus
}
#endif

#endif	/* _Inter_SystemInformationTransferType_H_ */
#include <asn_internal.h>
