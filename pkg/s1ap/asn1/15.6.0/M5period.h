/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_M5period_H_
#define	_M5period_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum M5period {
	M5period_ms1024	= 0,
	M5period_ms2048	= 1,
	M5period_ms5120	= 2,
	M5period_ms10240	= 3,
	M5period_min1	= 4
	/*
	 * Enumeration is extensible
	 */
} e_M5period;

/* M5period */
typedef long	 M5period_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_M5period_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_M5period;
extern const asn_INTEGER_specifics_t asn_SPC_M5period_specs_1;
asn_struct_free_f M5period_free;
asn_struct_print_f M5period_print;
asn_constr_check_f M5period_constraint;
ber_type_decoder_f M5period_decode_ber;
der_type_encoder_f M5period_encode_der;
xer_type_decoder_f M5period_decode_xer;
xer_type_encoder_f M5period_encode_xer;
oer_type_decoder_f M5period_decode_oer;
oer_type_encoder_f M5period_encode_oer;
per_type_decoder_f M5period_decode_uper;
per_type_encoder_f M5period_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _M5period_H_ */
#include <asn_internal.h>
