/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#include "UEPagingID.h"

static asn_oer_constraints_t asn_OER_type_UEPagingID_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_UEPagingID_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  1,  1,  0,  1 }	/* (0..1,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_UEPagingID_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UEPagingID, choice.s_TMSI),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_S_TMSI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"s-TMSI"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UEPagingID, choice.iMSI),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IMSI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iMSI"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_UEPagingID_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* s-TMSI */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* iMSI */
};
static asn_CHOICE_specifics_t asn_SPC_UEPagingID_specs_1 = {
	sizeof(struct UEPagingID),
	offsetof(struct UEPagingID, _asn_ctx),
	offsetof(struct UEPagingID, present),
	sizeof(((struct UEPagingID *)0)->present),
	asn_MAP_UEPagingID_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	2	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_UEPagingID = {
	"UEPagingID",
	"UEPagingID",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_UEPagingID_constr_1, &asn_PER_type_UEPagingID_constr_1, CHOICE_constraint },
	asn_MBR_UEPagingID_1,
	2,	/* Elements count */
	&asn_SPC_UEPagingID_specs_1	/* Additional specs */
};

