/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_GNB_Identity_H_
#define	_GNB_Identity_H_


#include <asn_application.h>

/* Including external dependencies */
#include "GNB-ID.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum GNB_Identity_PR {
	GNB_Identity_PR_NOTHING,	/* No components present */
	GNB_Identity_PR_gNB_ID
	/* Extensions may appear below */
	
} GNB_Identity_PR;

/* GNB-Identity */
typedef struct GNB_Identity {
	GNB_Identity_PR present;
	union GNB_Identity_u {
		GNB_ID_t	 gNB_ID;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} GNB_Identity_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_GNB_Identity;
extern asn_CHOICE_specifics_t asn_SPC_GNB_Identity_specs_1;
extern asn_TYPE_member_t asn_MBR_GNB_Identity_1[1];
extern asn_per_constraints_t asn_PER_type_GNB_Identity_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _GNB_Identity_H_ */
#include <asn_internal.h>
