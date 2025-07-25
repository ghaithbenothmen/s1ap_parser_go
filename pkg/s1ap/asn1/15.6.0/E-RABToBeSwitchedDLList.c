/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#include "E-RABToBeSwitchedDLList.h"

int
E_RABToBeSwitchedDLList_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 256)) {
		/* Perform validation of the inner elements */
		return SEQUENCE_OF_constraint(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

/*
 * This type is implemented using E_RAB_IE_ContainerList_1197P0,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_E_RABToBeSwitchedDLList_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..256)) */};
static asn_per_constraints_t asn_PER_type_E_RABToBeSwitchedDLList_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 8,  8,  1,  256 }	/* (SIZE(1..256)) */,
	0, 0	/* No PER value map */
};
static const ber_tlv_tag_t asn_DEF_E_RABToBeSwitchedDLList_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_E_RABToBeSwitchedDLList = {
	"E-RABToBeSwitchedDLList",
	"E-RABToBeSwitchedDLList",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_E_RABToBeSwitchedDLList_tags_1,
	sizeof(asn_DEF_E_RABToBeSwitchedDLList_tags_1)
		/sizeof(asn_DEF_E_RABToBeSwitchedDLList_tags_1[0]), /* 1 */
	asn_DEF_E_RABToBeSwitchedDLList_tags_1,	/* Same as above */
	sizeof(asn_DEF_E_RABToBeSwitchedDLList_tags_1)
		/sizeof(asn_DEF_E_RABToBeSwitchedDLList_tags_1[0]), /* 1 */
	{ &asn_OER_type_E_RABToBeSwitchedDLList_constr_1, &asn_PER_type_E_RABToBeSwitchedDLList_constr_1, E_RABToBeSwitchedDLList_constraint },
	asn_MBR_ProtocolIE_ContainerList_7313P0_1,
	1,	/* Single element */
	&asn_SPC_ProtocolIE_ContainerList_7313P0_specs_1	/* Additional specs */
};

