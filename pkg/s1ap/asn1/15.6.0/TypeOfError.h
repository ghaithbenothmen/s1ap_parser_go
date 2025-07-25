/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_TypeOfError_H_
#define	_TypeOfError_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TypeOfError {
	TypeOfError_not_understood	= 0,
	TypeOfError_missing	= 1
	/*
	 * Enumeration is extensible
	 */
} e_TypeOfError;

/* TypeOfError */
typedef long	 TypeOfError_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_TypeOfError_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_TypeOfError;
extern const asn_INTEGER_specifics_t asn_SPC_TypeOfError_specs_1;
asn_struct_free_f TypeOfError_free;
asn_struct_print_f TypeOfError_print;
asn_constr_check_f TypeOfError_constraint;
ber_type_decoder_f TypeOfError_decode_ber;
der_type_encoder_f TypeOfError_encode_der;
xer_type_decoder_f TypeOfError_decode_xer;
xer_type_encoder_f TypeOfError_encode_xer;
oer_type_decoder_f TypeOfError_decode_oer;
oer_type_encoder_f TypeOfError_encode_oer;
per_type_decoder_f TypeOfError_decode_uper;
per_type_encoder_f TypeOfError_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _TypeOfError_H_ */
#include <asn_internal.h>
