/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SonTransfer-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_CandidatePCI_H_
#define	_CandidatePCI_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <OCTET_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CandidatePCI */
typedef struct CandidatePCI {
	long	 pCI;
	OCTET_STRING_t	 eARFCN;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CandidatePCI_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CandidatePCI;
extern asn_SEQUENCE_specifics_t asn_SPC_CandidatePCI_specs_1;
extern asn_TYPE_member_t asn_MBR_CandidatePCI_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _CandidatePCI_H_ */
#include <asn_internal.h>
