/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#include "AssistanceDataForCECapableUEs.h"

#include "ProtocolExtensionContainer.h"
asn_TYPE_member_t asn_MBR_AssistanceDataForCECapableUEs_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AssistanceDataForCECapableUEs, cellIdentifierAndCELevelForCECapableUEs),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellIdentifierAndCELevelForCECapableUEs,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"cellIdentifierAndCELevelForCECapableUEs"
		},
	{ ATF_POINTER, 1, offsetof(struct AssistanceDataForCECapableUEs, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ProtocolExtensionContainer_8194P23,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_AssistanceDataForCECapableUEs_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_AssistanceDataForCECapableUEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_AssistanceDataForCECapableUEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* cellIdentifierAndCELevelForCECapableUEs */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* iE-Extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_AssistanceDataForCECapableUEs_specs_1 = {
	sizeof(struct AssistanceDataForCECapableUEs),
	offsetof(struct AssistanceDataForCECapableUEs, _asn_ctx),
	asn_MAP_AssistanceDataForCECapableUEs_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_AssistanceDataForCECapableUEs_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_AssistanceDataForCECapableUEs = {
	"AssistanceDataForCECapableUEs",
	"AssistanceDataForCECapableUEs",
	&asn_OP_SEQUENCE,
	asn_DEF_AssistanceDataForCECapableUEs_tags_1,
	sizeof(asn_DEF_AssistanceDataForCECapableUEs_tags_1)
		/sizeof(asn_DEF_AssistanceDataForCECapableUEs_tags_1[0]), /* 1 */
	asn_DEF_AssistanceDataForCECapableUEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_AssistanceDataForCECapableUEs_tags_1)
		/sizeof(asn_DEF_AssistanceDataForCECapableUEs_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_AssistanceDataForCECapableUEs_1,
	2,	/* Elements count */
	&asn_SPC_AssistanceDataForCECapableUEs_specs_1	/* Additional specs */
};

