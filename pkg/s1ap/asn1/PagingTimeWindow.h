/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_PagingTimeWindow_H_
#define	_PagingTimeWindow_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PagingTimeWindow {
	PagingTimeWindow_s1	= 0,
	PagingTimeWindow_s2	= 1,
	PagingTimeWindow_s3	= 2,
	PagingTimeWindow_s4	= 3,
	PagingTimeWindow_s5	= 4,
	PagingTimeWindow_s6	= 5,
	PagingTimeWindow_s7	= 6,
	PagingTimeWindow_s8	= 7,
	PagingTimeWindow_s9	= 8,
	PagingTimeWindow_s10	= 9,
	PagingTimeWindow_s11	= 10,
	PagingTimeWindow_s12	= 11,
	PagingTimeWindow_s13	= 12,
	PagingTimeWindow_s14	= 13,
	PagingTimeWindow_s15	= 14,
	PagingTimeWindow_s16	= 15
	/*
	 * Enumeration is extensible
	 */
} e_PagingTimeWindow;

/* PagingTimeWindow */
typedef long	 PagingTimeWindow_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_PagingTimeWindow_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_PagingTimeWindow;
extern const asn_INTEGER_specifics_t asn_SPC_PagingTimeWindow_specs_1;
asn_struct_free_f PagingTimeWindow_free;
asn_struct_print_f PagingTimeWindow_print;
asn_constr_check_f PagingTimeWindow_constraint;
xer_type_decoder_f PagingTimeWindow_decode_xer;
xer_type_encoder_f PagingTimeWindow_encode_xer;
jer_type_encoder_f PagingTimeWindow_encode_jer;
per_type_decoder_f PagingTimeWindow_decode_aper;
per_type_encoder_f PagingTimeWindow_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _PagingTimeWindow_H_ */
#include <asn_internal.h>
