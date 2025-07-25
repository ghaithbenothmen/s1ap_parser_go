/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_PagingAttemptCount_H_
#define	_PagingAttemptCount_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PagingAttemptCount */
typedef long	 PagingAttemptCount_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_PagingAttemptCount_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_PagingAttemptCount;
asn_struct_free_f PagingAttemptCount_free;
asn_struct_print_f PagingAttemptCount_print;
asn_constr_check_f PagingAttemptCount_constraint;
xer_type_decoder_f PagingAttemptCount_decode_xer;
xer_type_encoder_f PagingAttemptCount_encode_xer;
jer_type_encoder_f PagingAttemptCount_encode_jer;
per_type_decoder_f PagingAttemptCount_decode_aper;
per_type_encoder_f PagingAttemptCount_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _PagingAttemptCount_H_ */
#include <asn_internal.h>
