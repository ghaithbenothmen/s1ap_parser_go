/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_RAT_Type_H_
#define	_RAT_Type_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RAT_Type {
	RAT_Type_nbiot	= 0,
	/*
	 * Enumeration is extensible
	 */
	RAT_Type_nbiot_leo	= 1,
	RAT_Type_nbiot_meo	= 2,
	RAT_Type_nbiot_geo	= 3,
	RAT_Type_nbiot_othersat	= 4,
	RAT_Type_eutran_leo	= 5,
	RAT_Type_eutran_meo	= 6,
	RAT_Type_eutran_geo	= 7,
	RAT_Type_eutran_othersat	= 8
} e_RAT_Type;

/* RAT-Type */
typedef long	 RAT_Type_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RAT_Type_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RAT_Type;
extern const asn_INTEGER_specifics_t asn_SPC_RAT_Type_specs_1;
asn_struct_free_f RAT_Type_free;
asn_struct_print_f RAT_Type_print;
asn_constr_check_f RAT_Type_constraint;
xer_type_decoder_f RAT_Type_decode_xer;
xer_type_encoder_f RAT_Type_encode_xer;
jer_type_encoder_f RAT_Type_encode_jer;
per_type_decoder_f RAT_Type_decode_aper;
per_type_encoder_f RAT_Type_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RAT_Type_H_ */
#include <asn_internal.h>
