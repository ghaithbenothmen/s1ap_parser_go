/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_Paging_eDRX_Cycle_H_
#define	_Paging_eDRX_Cycle_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Paging_eDRX_Cycle {
	Paging_eDRX_Cycle_hfhalf	= 0,
	Paging_eDRX_Cycle_hf1	= 1,
	Paging_eDRX_Cycle_hf2	= 2,
	Paging_eDRX_Cycle_hf4	= 3,
	Paging_eDRX_Cycle_hf6	= 4,
	Paging_eDRX_Cycle_hf8	= 5,
	Paging_eDRX_Cycle_hf10	= 6,
	Paging_eDRX_Cycle_hf12	= 7,
	Paging_eDRX_Cycle_hf14	= 8,
	Paging_eDRX_Cycle_hf16	= 9,
	Paging_eDRX_Cycle_hf32	= 10,
	Paging_eDRX_Cycle_hf64	= 11,
	Paging_eDRX_Cycle_hf128	= 12,
	Paging_eDRX_Cycle_hf256	= 13
	/*
	 * Enumeration is extensible
	 */
} e_Paging_eDRX_Cycle;

/* Paging-eDRX-Cycle */
typedef long	 Paging_eDRX_Cycle_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_Paging_eDRX_Cycle_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_Paging_eDRX_Cycle;
extern const asn_INTEGER_specifics_t asn_SPC_Paging_eDRX_Cycle_specs_1;
asn_struct_free_f Paging_eDRX_Cycle_free;
asn_struct_print_f Paging_eDRX_Cycle_print;
asn_constr_check_f Paging_eDRX_Cycle_constraint;
xer_type_decoder_f Paging_eDRX_Cycle_decode_xer;
xer_type_encoder_f Paging_eDRX_Cycle_encode_xer;
jer_type_encoder_f Paging_eDRX_Cycle_encode_jer;
per_type_decoder_f Paging_eDRX_Cycle_decode_aper;
per_type_encoder_f Paging_eDRX_Cycle_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _Paging_eDRX_Cycle_H_ */
#include <asn_internal.h>
