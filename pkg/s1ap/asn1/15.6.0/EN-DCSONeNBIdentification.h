/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_EN_DCSONeNBIdentification_H_
#define	_EN_DCSONeNBIdentification_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Global-ENB-ID.h"
#include "TAI.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* EN-DCSONeNBIdentification */
typedef struct EN_DCSONeNBIdentification {
	Global_ENB_ID_t	 globaleNBID;
	TAI_t	 selectedTAI;
	struct ProtocolExtensionContainer	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} EN_DCSONeNBIdentification_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_EN_DCSONeNBIdentification;
extern asn_SEQUENCE_specifics_t asn_SPC_EN_DCSONeNBIdentification_specs_1;
extern asn_TYPE_member_t asn_MBR_EN_DCSONeNBIdentification_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ProtocolExtensionContainer.h"

#endif	/* _EN_DCSONeNBIdentification_H_ */
#include <asn_internal.h>
