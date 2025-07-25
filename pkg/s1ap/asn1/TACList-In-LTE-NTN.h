/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_TACList_In_LTE_NTN_H_
#define	_TACList_In_LTE_NTN_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TAC.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TACList-In-LTE-NTN */
typedef struct TACList_In_LTE_NTN {
	A_SEQUENCE_OF(TAC_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TACList_In_LTE_NTN_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TACList_In_LTE_NTN;
extern asn_SET_OF_specifics_t asn_SPC_TACList_In_LTE_NTN_specs_1;
extern asn_TYPE_member_t asn_MBR_TACList_In_LTE_NTN_1[1];
extern asn_per_constraints_t asn_PER_type_TACList_In_LTE_NTN_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _TACList_In_LTE_NTN_H_ */
#include <asn_internal.h>
