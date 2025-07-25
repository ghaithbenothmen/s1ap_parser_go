/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_IAB_Node_Indication_H_
#define	_IAB_Node_Indication_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum IAB_Node_Indication {
	IAB_Node_Indication_true	= 0
	/*
	 * Enumeration is extensible
	 */
} e_IAB_Node_Indication;

/* IAB-Node-Indication */
typedef long	 IAB_Node_Indication_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_IAB_Node_Indication_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_IAB_Node_Indication;
extern const asn_INTEGER_specifics_t asn_SPC_IAB_Node_Indication_specs_1;
asn_struct_free_f IAB_Node_Indication_free;
asn_struct_print_f IAB_Node_Indication_print;
asn_constr_check_f IAB_Node_Indication_constraint;
xer_type_decoder_f IAB_Node_Indication_decode_xer;
xer_type_encoder_f IAB_Node_Indication_encode_xer;
jer_type_encoder_f IAB_Node_Indication_encode_jer;
per_type_decoder_f IAB_Node_Indication_decode_aper;
per_type_encoder_f IAB_Node_Indication_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _IAB_Node_Indication_H_ */
#include <asn_internal.h>
