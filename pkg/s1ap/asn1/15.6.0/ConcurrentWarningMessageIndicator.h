/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_ConcurrentWarningMessageIndicator_H_
#define	_ConcurrentWarningMessageIndicator_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ConcurrentWarningMessageIndicator {
	ConcurrentWarningMessageIndicator_true	= 0
} e_ConcurrentWarningMessageIndicator;

/* ConcurrentWarningMessageIndicator */
typedef long	 ConcurrentWarningMessageIndicator_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ConcurrentWarningMessageIndicator;
asn_struct_free_f ConcurrentWarningMessageIndicator_free;
asn_struct_print_f ConcurrentWarningMessageIndicator_print;
asn_constr_check_f ConcurrentWarningMessageIndicator_constraint;
ber_type_decoder_f ConcurrentWarningMessageIndicator_decode_ber;
der_type_encoder_f ConcurrentWarningMessageIndicator_encode_der;
xer_type_decoder_f ConcurrentWarningMessageIndicator_decode_xer;
xer_type_encoder_f ConcurrentWarningMessageIndicator_encode_xer;
oer_type_decoder_f ConcurrentWarningMessageIndicator_decode_oer;
oer_type_encoder_f ConcurrentWarningMessageIndicator_encode_oer;
per_type_decoder_f ConcurrentWarningMessageIndicator_decode_uper;
per_type_encoder_f ConcurrentWarningMessageIndicator_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _ConcurrentWarningMessageIndicator_H_ */
#include <asn_internal.h>
