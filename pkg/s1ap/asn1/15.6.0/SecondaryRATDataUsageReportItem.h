/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_SecondaryRATDataUsageReportItem_H_
#define	_SecondaryRATDataUsageReportItem_H_


#include <asn_application.h>

/* Including external dependencies */
#include "E-RAB-ID.h"
#include "SecondaryRATType.h"
#include "E-RABUsageReportList.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* SecondaryRATDataUsageReportItem */
typedef struct SecondaryRATDataUsageReportItem {
	E_RAB_ID_t	 e_RAB_ID;
	SecondaryRATType_t	 secondaryRATType;
	E_RABUsageReportList_t	 e_RABUsageReportList;
	struct ProtocolExtensionContainer	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SecondaryRATDataUsageReportItem_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SecondaryRATDataUsageReportItem;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ProtocolExtensionContainer.h"

#endif	/* _SecondaryRATDataUsageReportItem_H_ */
#include <asn_internal.h>
