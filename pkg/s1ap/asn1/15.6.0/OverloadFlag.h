/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SonTransfer-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_OverloadFlag_H_
#define	_OverloadFlag_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum OverloadFlag {
	OverloadFlag_overload	= 0
	/*
	 * Enumeration is extensible
	 */
} e_OverloadFlag;

/* OverloadFlag */
typedef long	 OverloadFlag_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_OverloadFlag_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_OverloadFlag;
extern const asn_INTEGER_specifics_t asn_SPC_OverloadFlag_specs_1;
asn_struct_free_f OverloadFlag_free;
asn_struct_print_f OverloadFlag_print;
asn_constr_check_f OverloadFlag_constraint;
ber_type_decoder_f OverloadFlag_decode_ber;
der_type_encoder_f OverloadFlag_encode_der;
xer_type_decoder_f OverloadFlag_decode_xer;
xer_type_encoder_f OverloadFlag_encode_xer;
oer_type_decoder_f OverloadFlag_decode_oer;
oer_type_encoder_f OverloadFlag_encode_oer;
per_type_decoder_f OverloadFlag_decode_uper;
per_type_encoder_f OverloadFlag_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _OverloadFlag_H_ */
#include <asn_internal.h>
