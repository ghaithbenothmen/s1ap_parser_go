/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#include "UESecurityCapabilities.h"

static asn_TYPE_member_t asn_MBR_UESecurityCapabilities_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UESecurityCapabilities, encryptionAlgorithms),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_EncryptionAlgorithms,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"encryptionAlgorithms"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UESecurityCapabilities, integrityProtectionAlgorithms),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IntegrityProtectionAlgorithms,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"integrityProtectionAlgorithms"
		},
	{ ATF_POINTER, 1, offsetof(struct UESecurityCapabilities, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ProtocolExtensionContainer_7327P0,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_UESecurityCapabilities_oms_1[] = { 2 };
static const ber_tlv_tag_t asn_DEF_UESecurityCapabilities_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UESecurityCapabilities_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* encryptionAlgorithms */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* integrityProtectionAlgorithms */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_UESecurityCapabilities_specs_1 = {
	sizeof(struct UESecurityCapabilities),
	offsetof(struct UESecurityCapabilities, _asn_ctx),
	asn_MAP_UESecurityCapabilities_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_UESecurityCapabilities_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UESecurityCapabilities = {
	"UESecurityCapabilities",
	"UESecurityCapabilities",
	&asn_OP_SEQUENCE,
	asn_DEF_UESecurityCapabilities_tags_1,
	sizeof(asn_DEF_UESecurityCapabilities_tags_1)
		/sizeof(asn_DEF_UESecurityCapabilities_tags_1[0]), /* 1 */
	asn_DEF_UESecurityCapabilities_tags_1,	/* Same as above */
	sizeof(asn_DEF_UESecurityCapabilities_tags_1)
		/sizeof(asn_DEF_UESecurityCapabilities_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UESecurityCapabilities_1,
	3,	/* Elements count */
	&asn_SPC_UESecurityCapabilities_specs_1	/* Additional specs */
};

