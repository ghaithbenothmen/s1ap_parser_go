/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_GNB_H_
#define	_GNB_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Global-GNB-ID.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* GNB */
typedef struct GNB {
	Global_GNB_ID_t	 global_gNB_ID;
	struct ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} GNB_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_GNB;
extern asn_SEQUENCE_specifics_t asn_SPC_GNB_specs_1;
extern asn_TYPE_member_t asn_MBR_GNB_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _GNB_H_ */
#include <asn_internal.h>
