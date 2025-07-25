/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_NRrestrictioninEPSasSecondaryRAT_H_
#define	_NRrestrictioninEPSasSecondaryRAT_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NRrestrictioninEPSasSecondaryRAT {
	NRrestrictioninEPSasSecondaryRAT_nRrestrictedinEPSasSecondaryRAT	= 0
	/*
	 * Enumeration is extensible
	 */
} e_NRrestrictioninEPSasSecondaryRAT;

/* NRrestrictioninEPSasSecondaryRAT */
typedef long	 NRrestrictioninEPSasSecondaryRAT_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NRrestrictioninEPSasSecondaryRAT;
asn_struct_free_f NRrestrictioninEPSasSecondaryRAT_free;
asn_struct_print_f NRrestrictioninEPSasSecondaryRAT_print;
asn_constr_check_f NRrestrictioninEPSasSecondaryRAT_constraint;
ber_type_decoder_f NRrestrictioninEPSasSecondaryRAT_decode_ber;
der_type_encoder_f NRrestrictioninEPSasSecondaryRAT_encode_der;
xer_type_decoder_f NRrestrictioninEPSasSecondaryRAT_decode_xer;
xer_type_encoder_f NRrestrictioninEPSasSecondaryRAT_encode_xer;
oer_type_decoder_f NRrestrictioninEPSasSecondaryRAT_decode_oer;
oer_type_encoder_f NRrestrictioninEPSasSecondaryRAT_encode_oer;
per_type_decoder_f NRrestrictioninEPSasSecondaryRAT_decode_uper;
per_type_encoder_f NRrestrictioninEPSasSecondaryRAT_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _NRrestrictioninEPSasSecondaryRAT_H_ */
#include <asn_internal.h>
