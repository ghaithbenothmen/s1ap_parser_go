/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-Containers"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_PrivateIE_Field_H_
#define	_PrivateIE_Field_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PrivateIE-ID.h"
#include "Criticality.h"
#include <ANY.h>
#include <asn_ioc.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PrivateIE_Field_7346P0__value_PR {
	PrivateIE_Field_7346P0__value_PR_NOTHING,	/* No components present */
	
} PrivateIE_Field_7346P0__value_PR;

/* PrivateIE-Field */
typedef struct PrivateIE_Field_7346P0 {
	PrivateIE_ID_t	 id;
	Criticality_t	 criticality;
	struct PrivateIE_Field_7346P0__value {
		PrivateIE_Field_7346P0__value_PR present;
		union PrivateIE_Field_7346P0__value_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} value;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PrivateIE_Field_7346P0_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PrivateIE_Field_7346P0;
extern asn_SEQUENCE_specifics_t asn_SPC_PrivateIE_Field_7346P0_specs_1;
extern asn_TYPE_member_t asn_MBR_PrivateIE_Field_7346P0_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _PrivateIE_Field_H_ */
#include <asn_internal.h>
