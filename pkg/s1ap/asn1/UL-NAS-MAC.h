/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_UL_NAS_MAC_H_
#define	_UL_NAS_MAC_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UL-NAS-MAC */
typedef BIT_STRING_t	 UL_NAS_MAC_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_UL_NAS_MAC_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_UL_NAS_MAC;
asn_struct_free_f UL_NAS_MAC_free;
asn_struct_print_f UL_NAS_MAC_print;
asn_constr_check_f UL_NAS_MAC_constraint;
xer_type_decoder_f UL_NAS_MAC_decode_xer;
xer_type_encoder_f UL_NAS_MAC_encode_xer;
jer_type_encoder_f UL_NAS_MAC_encode_jer;
per_type_decoder_f UL_NAS_MAC_decode_aper;
per_type_encoder_f UL_NAS_MAC_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _UL_NAS_MAC_H_ */
#include <asn_internal.h>
