/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_HandoverNotify_H_
#define	_HandoverNotify_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ProtocolIE-Container.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HandoverNotify */
typedef struct HandoverNotify {
	ProtocolIE_Container_7276P0_t	 protocolIEs;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HandoverNotify_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HandoverNotify;
extern asn_SEQUENCE_specifics_t asn_SPC_HandoverNotify_specs_1;
extern asn_TYPE_member_t asn_MBR_HandoverNotify_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _HandoverNotify_H_ */
#include <asn_internal.h>
