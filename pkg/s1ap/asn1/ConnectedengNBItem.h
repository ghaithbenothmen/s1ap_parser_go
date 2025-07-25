/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_ConnectedengNBItem_H_
#define	_ConnectedengNBItem_H_


#include <asn_application.h>

/* Including external dependencies */
#include "En-gNB-ID.h"
#include "SupportedTAs.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* ConnectedengNBItem */
typedef struct ConnectedengNBItem {
	En_gNB_ID_t	 en_gNB_ID;
	SupportedTAs_t	 supportedTAs;
	struct ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ConnectedengNBItem_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ConnectedengNBItem;
extern asn_SEQUENCE_specifics_t asn_SPC_ConnectedengNBItem_specs_1;
extern asn_TYPE_member_t asn_MBR_ConnectedengNBItem_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _ConnectedengNBItem_H_ */
#include <asn_internal.h>
