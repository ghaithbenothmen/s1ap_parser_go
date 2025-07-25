/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_Range_H_
#define	_Range_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Range {
	Range_m50	= 0,
	Range_m80	= 1,
	Range_m180	= 2,
	Range_m200	= 3,
	Range_m350	= 4,
	Range_m400	= 5,
	Range_m500	= 6,
	Range_m700	= 7,
	Range_m1000	= 8
	/*
	 * Enumeration is extensible
	 */
} e_Range;

/* Range */
typedef long	 Range_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_Range_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_Range;
extern const asn_INTEGER_specifics_t asn_SPC_Range_specs_1;
asn_struct_free_f Range_free;
asn_struct_print_f Range_print;
asn_constr_check_f Range_constraint;
xer_type_decoder_f Range_decode_xer;
xer_type_encoder_f Range_encode_xer;
jer_type_encoder_f Range_encode_jer;
per_type_decoder_f Range_decode_aper;
per_type_encoder_f Range_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _Range_H_ */
#include <asn_internal.h>
