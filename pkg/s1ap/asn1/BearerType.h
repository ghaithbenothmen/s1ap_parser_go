/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_BearerType_H_
#define	_BearerType_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum BearerType {
	BearerType_non_IP	= 0
	/*
	 * Enumeration is extensible
	 */
} e_BearerType;

/* BearerType */
typedef long	 BearerType_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_BearerType_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_BearerType;
extern const asn_INTEGER_specifics_t asn_SPC_BearerType_specs_1;
asn_struct_free_f BearerType_free;
asn_struct_print_f BearerType_print;
asn_constr_check_f BearerType_constraint;
xer_type_decoder_f BearerType_decode_xer;
xer_type_encoder_f BearerType_encode_xer;
jer_type_encoder_f BearerType_encode_jer;
per_type_decoder_f BearerType_decode_aper;
per_type_encoder_f BearerType_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _BearerType_H_ */
#include <asn_internal.h>
