/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#include "EN-DCSONConfigurationTransfer.h"

static asn_TYPE_member_t asn_MBR_EN_DCSONConfigurationTransfer_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct EN_DCSONConfigurationTransfer, transfertype),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_EN_DCSONTransferType,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"transfertype"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct EN_DCSONConfigurationTransfer, sONInformation),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_SONInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sONInformation"
		},
	{ ATF_POINTER, 2, offsetof(struct EN_DCSONConfigurationTransfer, x2TNLConfigInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_X2TNLConfigurationInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"x2TNLConfigInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct EN_DCSONConfigurationTransfer, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ProtocolExtensionContainer_7327P0,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_EN_DCSONConfigurationTransfer_oms_1[] = { 2, 3 };
static const ber_tlv_tag_t asn_DEF_EN_DCSONConfigurationTransfer_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_EN_DCSONConfigurationTransfer_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* transfertype */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* sONInformation */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* x2TNLConfigInfo */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_EN_DCSONConfigurationTransfer_specs_1 = {
	sizeof(struct EN_DCSONConfigurationTransfer),
	offsetof(struct EN_DCSONConfigurationTransfer, _asn_ctx),
	asn_MAP_EN_DCSONConfigurationTransfer_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_EN_DCSONConfigurationTransfer_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	4,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_EN_DCSONConfigurationTransfer = {
	"EN-DCSONConfigurationTransfer",
	"EN-DCSONConfigurationTransfer",
	&asn_OP_SEQUENCE,
	asn_DEF_EN_DCSONConfigurationTransfer_tags_1,
	sizeof(asn_DEF_EN_DCSONConfigurationTransfer_tags_1)
		/sizeof(asn_DEF_EN_DCSONConfigurationTransfer_tags_1[0]), /* 1 */
	asn_DEF_EN_DCSONConfigurationTransfer_tags_1,	/* Same as above */
	sizeof(asn_DEF_EN_DCSONConfigurationTransfer_tags_1)
		/sizeof(asn_DEF_EN_DCSONConfigurationTransfer_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_EN_DCSONConfigurationTransfer_1,
	4,	/* Elements count */
	&asn_SPC_EN_DCSONConfigurationTransfer_specs_1	/* Additional specs */
};

