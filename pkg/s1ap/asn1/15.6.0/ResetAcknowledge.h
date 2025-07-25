/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_ResetAcknowledge_H_
#define	_ResetAcknowledge_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ProtocolIE-Container.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ResetAcknowledge */
typedef struct ResetAcknowledge {
	ProtocolIE_Container_7276P0_t	 protocolIEs;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ResetAcknowledge_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ResetAcknowledge;
extern asn_SEQUENCE_specifics_t asn_SPC_ResetAcknowledge_specs_1;
extern asn_TYPE_member_t asn_MBR_ResetAcknowledge_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _ResetAcknowledge_H_ */
#include <asn_internal.h>
