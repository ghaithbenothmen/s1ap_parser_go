/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_X2TNLConfigurationInfo_H_
#define	_X2TNLConfigurationInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ENBX2TLAs.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* X2TNLConfigurationInfo */
typedef struct X2TNLConfigurationInfo {
	ENBX2TLAs_t	 eNBX2TransportLayerAddresses;
	struct ProtocolExtensionContainer	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} X2TNLConfigurationInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_X2TNLConfigurationInfo;
extern asn_SEQUENCE_specifics_t asn_SPC_X2TNLConfigurationInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_X2TNLConfigurationInfo_1[2];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ProtocolExtensionContainer.h"

#endif	/* _X2TNLConfigurationInfo_H_ */
#include <asn_internal.h>
