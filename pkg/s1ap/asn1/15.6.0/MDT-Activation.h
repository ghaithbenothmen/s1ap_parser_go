/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_MDT_Activation_H_
#define	_MDT_Activation_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MDT_Activation {
	MDT_Activation_immediate_MDT_only	= 0,
	MDT_Activation_immediate_MDT_and_Trace	= 1,
	MDT_Activation_logged_MDT_only	= 2,
	/*
	 * Enumeration is extensible
	 */
	MDT_Activation_logged_MBSFN_MDT	= 3
} e_MDT_Activation;

/* MDT-Activation */
typedef long	 MDT_Activation_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_MDT_Activation_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_MDT_Activation;
extern const asn_INTEGER_specifics_t asn_SPC_MDT_Activation_specs_1;
asn_struct_free_f MDT_Activation_free;
asn_struct_print_f MDT_Activation_print;
asn_constr_check_f MDT_Activation_constraint;
ber_type_decoder_f MDT_Activation_decode_ber;
der_type_encoder_f MDT_Activation_encode_der;
xer_type_decoder_f MDT_Activation_decode_xer;
xer_type_encoder_f MDT_Activation_encode_xer;
oer_type_decoder_f MDT_Activation_decode_oer;
oer_type_encoder_f MDT_Activation_encode_oer;
per_type_decoder_f MDT_Activation_decode_uper;
per_type_encoder_f MDT_Activation_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _MDT_Activation_H_ */
#include <asn_internal.h>
