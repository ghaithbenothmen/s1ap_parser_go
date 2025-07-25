/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SonTransfer-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#include "RequestedCellList.h"

static asn_oer_constraints_t asn_OER_type_RequestedCellList_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..128)) */};
asn_per_constraints_t asn_PER_type_RequestedCellList_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 7,  7,  1,  128 }	/* (SIZE(1..128)) */,
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_RequestedCellList_1[] = {
	{ ATF_POINTER, 0, 0,
		-1 /* Ambiguous tag (CHOICE?) */,
		0,
		&asn_DEF_IRAT_Cell_ID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_RequestedCellList_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_SET_OF_specifics_t asn_SPC_RequestedCellList_specs_1 = {
	sizeof(struct RequestedCellList),
	offsetof(struct RequestedCellList, _asn_ctx),
	2,	/* XER encoding is XMLValueList */
};
asn_TYPE_descriptor_t asn_DEF_RequestedCellList = {
	"RequestedCellList",
	"RequestedCellList",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_RequestedCellList_tags_1,
	sizeof(asn_DEF_RequestedCellList_tags_1)
		/sizeof(asn_DEF_RequestedCellList_tags_1[0]), /* 1 */
	asn_DEF_RequestedCellList_tags_1,	/* Same as above */
	sizeof(asn_DEF_RequestedCellList_tags_1)
		/sizeof(asn_DEF_RequestedCellList_tags_1[0]), /* 1 */
	{ &asn_OER_type_RequestedCellList_constr_1, &asn_PER_type_RequestedCellList_constr_1, SEQUENCE_OF_constraint },
	asn_MBR_RequestedCellList_1,
	1,	/* Single element */
	&asn_SPC_RequestedCellList_specs_1	/* Additional specs */
};

