/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_TransportLayerAddress_H_
#define	_TransportLayerAddress_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TransportLayerAddress */
typedef BIT_STRING_t	 TransportLayerAddress_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_TransportLayerAddress_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_TransportLayerAddress;
asn_struct_free_f TransportLayerAddress_free;
asn_struct_print_f TransportLayerAddress_print;
asn_constr_check_f TransportLayerAddress_constraint;
ber_type_decoder_f TransportLayerAddress_decode_ber;
der_type_encoder_f TransportLayerAddress_encode_der;
xer_type_decoder_f TransportLayerAddress_decode_xer;
xer_type_encoder_f TransportLayerAddress_encode_xer;
oer_type_decoder_f TransportLayerAddress_decode_oer;
oer_type_encoder_f TransportLayerAddress_encode_oer;
per_type_decoder_f TransportLayerAddress_decode_uper;
per_type_encoder_f TransportLayerAddress_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _TransportLayerAddress_H_ */
#include <asn_internal.h>
