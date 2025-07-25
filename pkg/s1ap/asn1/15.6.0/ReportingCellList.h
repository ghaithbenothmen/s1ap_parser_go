/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SonTransfer-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_ReportingCellList_H_
#define	_ReportingCellList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ReportingCellList_Item;

/* ReportingCellList */
typedef struct ReportingCellList {
	A_SEQUENCE_OF(struct ReportingCellList_Item) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ReportingCellList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ReportingCellList;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ReportingCellList-Item.h"

#endif	/* _ReportingCellList_H_ */
#include <asn_internal.h>
