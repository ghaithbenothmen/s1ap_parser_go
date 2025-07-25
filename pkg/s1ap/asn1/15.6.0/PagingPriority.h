/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_PagingPriority_H_
#define	_PagingPriority_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PagingPriority {
	PagingPriority_priolevel1	= 0,
	PagingPriority_priolevel2	= 1,
	PagingPriority_priolevel3	= 2,
	PagingPriority_priolevel4	= 3,
	PagingPriority_priolevel5	= 4,
	PagingPriority_priolevel6	= 5,
	PagingPriority_priolevel7	= 6,
	PagingPriority_priolevel8	= 7
	/*
	 * Enumeration is extensible
	 */
} e_PagingPriority;

/* PagingPriority */
typedef long	 PagingPriority_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PagingPriority;
asn_struct_free_f PagingPriority_free;
asn_struct_print_f PagingPriority_print;
asn_constr_check_f PagingPriority_constraint;
ber_type_decoder_f PagingPriority_decode_ber;
der_type_encoder_f PagingPriority_encode_der;
xer_type_decoder_f PagingPriority_decode_xer;
xer_type_encoder_f PagingPriority_encode_xer;
oer_type_decoder_f PagingPriority_decode_oer;
oer_type_encoder_f PagingPriority_encode_oer;
per_type_decoder_f PagingPriority_decode_uper;
per_type_encoder_f PagingPriority_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _PagingPriority_H_ */
#include <asn_internal.h>
