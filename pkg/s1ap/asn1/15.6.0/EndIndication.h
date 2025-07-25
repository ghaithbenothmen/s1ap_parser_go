/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_EndIndication_H_
#define	_EndIndication_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum EndIndication {
	EndIndication_no_further_data	= 0,
	EndIndication_further_data_exists	= 1
	/*
	 * Enumeration is extensible
	 */
} e_EndIndication;

/* EndIndication */
typedef long	 EndIndication_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_EndIndication;
asn_struct_free_f EndIndication_free;
asn_struct_print_f EndIndication_print;
asn_constr_check_f EndIndication_constraint;
ber_type_decoder_f EndIndication_decode_ber;
der_type_encoder_f EndIndication_encode_der;
xer_type_decoder_f EndIndication_decode_xer;
xer_type_encoder_f EndIndication_encode_xer;
oer_type_decoder_f EndIndication_decode_oer;
oer_type_encoder_f EndIndication_encode_oer;
per_type_decoder_f EndIndication_decode_uper;
per_type_encoder_f EndIndication_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _EndIndication_H_ */
#include <asn_internal.h>
