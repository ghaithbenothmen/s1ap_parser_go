/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SonTransfer-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_MultiCellLoadReportingResponse_H_
#define	_MultiCellLoadReportingResponse_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MultiCellLoadReportingResponse_Item;

/* MultiCellLoadReportingResponse */
typedef struct MultiCellLoadReportingResponse {
	A_SEQUENCE_OF(struct MultiCellLoadReportingResponse_Item) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MultiCellLoadReportingResponse_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MultiCellLoadReportingResponse;
extern asn_SET_OF_specifics_t asn_SPC_MultiCellLoadReportingResponse_specs_1;
extern asn_TYPE_member_t asn_MBR_MultiCellLoadReportingResponse_1[1];
extern asn_per_constraints_t asn_PER_type_MultiCellLoadReportingResponse_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MultiCellLoadReportingResponse-Item.h"

#endif	/* _MultiCellLoadReportingResponse_H_ */
#include <asn_internal.h>
