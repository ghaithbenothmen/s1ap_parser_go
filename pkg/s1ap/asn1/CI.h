/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_CI_H_
#define	_CI_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CI */
typedef OCTET_STRING_t	 CI_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_CI_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_CI;
asn_struct_free_f CI_free;
asn_struct_print_f CI_print;
asn_constr_check_f CI_constraint;
xer_type_decoder_f CI_decode_xer;
xer_type_encoder_f CI_encode_xer;
jer_type_encoder_f CI_encode_jer;
per_type_decoder_f CI_decode_aper;
per_type_encoder_f CI_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _CI_H_ */
#include <asn_internal.h>
