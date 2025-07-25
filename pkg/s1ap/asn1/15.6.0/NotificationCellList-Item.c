/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SonTransfer-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#include "NotificationCellList-Item.h"

asn_TYPE_member_t asn_MBR_NotificationCellList_Item_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct NotificationCellList_Item, cell_ID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OCTET_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cell-ID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NotificationCellList_Item, notifyFlag),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NotifyFlag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"notifyFlag"
		},
};
static const ber_tlv_tag_t asn_DEF_NotificationCellList_Item_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_NotificationCellList_Item_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* cell-ID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* notifyFlag */
};
asn_SEQUENCE_specifics_t asn_SPC_NotificationCellList_Item_specs_1 = {
	sizeof(struct NotificationCellList_Item),
	offsetof(struct NotificationCellList_Item, _asn_ctx),
	asn_MAP_NotificationCellList_Item_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_NotificationCellList_Item = {
	"NotificationCellList-Item",
	"NotificationCellList-Item",
	&asn_OP_SEQUENCE,
	asn_DEF_NotificationCellList_Item_tags_1,
	sizeof(asn_DEF_NotificationCellList_Item_tags_1)
		/sizeof(asn_DEF_NotificationCellList_Item_tags_1[0]), /* 1 */
	asn_DEF_NotificationCellList_Item_tags_1,	/* Same as above */
	sizeof(asn_DEF_NotificationCellList_Item_tags_1)
		/sizeof(asn_DEF_NotificationCellList_Item_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_NotificationCellList_Item_1,
	2,	/* Elements count */
	&asn_SPC_NotificationCellList_Item_specs_1	/* Additional specs */
};

