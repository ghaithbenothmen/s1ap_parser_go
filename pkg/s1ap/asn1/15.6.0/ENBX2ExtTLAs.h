/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_ENBX2ExtTLAs_H_
#define	_ENBX2ExtTLAs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ENBX2ExtTLA;

/* ENBX2ExtTLAs */
typedef struct ENBX2ExtTLAs {
	A_SEQUENCE_OF(struct ENBX2ExtTLA) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ENBX2ExtTLAs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ENBX2ExtTLAs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ENBX2ExtTLA.h"

#endif	/* _ENBX2ExtTLAs_H_ */
#include <asn_internal.h>
