/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_TraceDepth_H_
#define	_TraceDepth_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TraceDepth {
	TraceDepth_minimum	= 0,
	TraceDepth_medium	= 1,
	TraceDepth_maximum	= 2,
	TraceDepth_minimumWithoutVendorSpecificExtension	= 3,
	TraceDepth_mediumWithoutVendorSpecificExtension	= 4,
	TraceDepth_maximumWithoutVendorSpecificExtension	= 5
	/*
	 * Enumeration is extensible
	 */
} e_TraceDepth;

/* TraceDepth */
typedef long	 TraceDepth_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_TraceDepth_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_TraceDepth;
extern const asn_INTEGER_specifics_t asn_SPC_TraceDepth_specs_1;
asn_struct_free_f TraceDepth_free;
asn_struct_print_f TraceDepth_print;
asn_constr_check_f TraceDepth_constraint;
xer_type_decoder_f TraceDepth_decode_xer;
xer_type_encoder_f TraceDepth_encode_xer;
jer_type_encoder_f TraceDepth_encode_jer;
per_type_decoder_f TraceDepth_decode_aper;
per_type_encoder_f TraceDepth_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _TraceDepth_H_ */
#include <asn_internal.h>
