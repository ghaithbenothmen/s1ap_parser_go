/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_SecondaryRATDataUsageRequest_H_
#define	_SecondaryRATDataUsageRequest_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SecondaryRATDataUsageRequest {
	SecondaryRATDataUsageRequest_requested	= 0
	/*
	 * Enumeration is extensible
	 */
} e_SecondaryRATDataUsageRequest;

/* SecondaryRATDataUsageRequest */
typedef long	 SecondaryRATDataUsageRequest_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SecondaryRATDataUsageRequest;
asn_struct_free_f SecondaryRATDataUsageRequest_free;
asn_struct_print_f SecondaryRATDataUsageRequest_print;
asn_constr_check_f SecondaryRATDataUsageRequest_constraint;
ber_type_decoder_f SecondaryRATDataUsageRequest_decode_ber;
der_type_encoder_f SecondaryRATDataUsageRequest_encode_der;
xer_type_decoder_f SecondaryRATDataUsageRequest_decode_xer;
xer_type_encoder_f SecondaryRATDataUsageRequest_encode_xer;
oer_type_decoder_f SecondaryRATDataUsageRequest_decode_oer;
oer_type_encoder_f SecondaryRATDataUsageRequest_encode_oer;
per_type_decoder_f SecondaryRATDataUsageRequest_decode_uper;
per_type_encoder_f SecondaryRATDataUsageRequest_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _SecondaryRATDataUsageRequest_H_ */
#include <asn_internal.h>
