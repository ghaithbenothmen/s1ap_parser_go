/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#include "CauseRadioNetwork.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_CauseRadioNetwork_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  6,  6,  0,  35 }	/* (0..35,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static const asn_INTEGER_enum_map_t asn_MAP_CauseRadioNetwork_value2enum_1[] = {
	{ 0,	11,	"unspecified" },
	{ 1,	22,	"tx2relocoverall-expiry" },
	{ 2,	19,	"successful-handover" },
	{ 3,	38,	"release-due-to-eutran-generated-reason" },
	{ 4,	18,	"handover-cancelled" },
	{ 5,	16,	"partial-handover" },
	{ 6,	45,	"ho-failure-in-target-EPC-eNB-or-target-system" },
	{ 7,	21,	"ho-target-not-allowed" },
	{ 8,	22,	"tS1relocoverall-expiry" },
	{ 9,	19,	"tS1relocprep-expiry" },
	{ 10,	18,	"cell-not-available" },
	{ 11,	16,	"unknown-targetID" },
	{ 12,	43,	"no-radio-resources-available-in-target-cell" },
	{ 13,	22,	"unknown-mme-ue-s1ap-id" },
	{ 14,	22,	"unknown-enb-ue-s1ap-id" },
	{ 15,	23,	"unknown-pair-ue-s1ap-id" },
	{ 16,	35,	"handover-desirable-for-radio-reason" },
	{ 17,	22,	"time-critical-handover" },
	{ 18,	30,	"resource-optimisation-handover" },
	{ 19,	27,	"reduce-load-in-serving-cell" },
	{ 20,	15,	"user-inactivity" },
	{ 21,	29,	"radio-connection-with-ue-lost" },
	{ 22,	27,	"load-balancing-tau-required" },
	{ 23,	21,	"cs-fallback-triggered" },
	{ 24,	31,	"ue-not-available-for-ps-service" },
	{ 25,	29,	"radio-resources-not-available" },
	{ 26,	36,	"failure-in-radio-interface-procedure" },
	{ 27,	23,	"invalid-qos-combination" },
	{ 28,	20,	"interrat-redirection" },
	{ 29,	32,	"interaction-with-other-procedure" },
	{ 30,	16,	"unknown-E-RAB-ID" },
	{ 31,	27,	"multiple-E-RAB-ID-instances" },
	{ 32,	63,	"encryption-and-or-integrity-protection-algorithms-not-supported" },
	{ 33,	34,	"s1-intra-system-handover-triggered" },
	{ 34,	34,	"s1-inter-system-handover-triggered" },
	{ 35,	21,	"x2-handover-triggered" },
	{ 36,	25,	"redirection-towards-1xRTT" },
	{ 37,	23,	"not-supported-QCI-value" },
	{ 38,	14,	"invalid-CSG-Id" },
	{ 39,	26,	"release-due-to-pre-emption" },
	{ 40,	27,	"n26-interface-not-available" },
	{ 41,	28,	"insufficient-ue-capabilities" },
	{ 42,	40,	"maximum-bearer-pre-emption-rate-exceeded" },
	{ 43,	36,	"up-integrity-protection-not-possible" }
	/* This list is extensible */
};
static const unsigned int asn_MAP_CauseRadioNetwork_enum2value_1[] = {
	10,	/* cell-not-available(10) */
	23,	/* cs-fallback-triggered(23) */
	32,	/* encryption-and-or-integrity-protection-algorithms-not-supported(32) */
	26,	/* failure-in-radio-interface-procedure(26) */
	4,	/* handover-cancelled(4) */
	16,	/* handover-desirable-for-radio-reason(16) */
	6,	/* ho-failure-in-target-EPC-eNB-or-target-system(6) */
	7,	/* ho-target-not-allowed(7) */
	41,	/* insufficient-ue-capabilities(41) */
	29,	/* interaction-with-other-procedure(29) */
	28,	/* interrat-redirection(28) */
	38,	/* invalid-CSG-Id(38) */
	27,	/* invalid-qos-combination(27) */
	22,	/* load-balancing-tau-required(22) */
	42,	/* maximum-bearer-pre-emption-rate-exceeded(42) */
	31,	/* multiple-E-RAB-ID-instances(31) */
	40,	/* n26-interface-not-available(40) */
	12,	/* no-radio-resources-available-in-target-cell(12) */
	37,	/* not-supported-QCI-value(37) */
	5,	/* partial-handover(5) */
	21,	/* radio-connection-with-ue-lost(21) */
	25,	/* radio-resources-not-available(25) */
	36,	/* redirection-towards-1xRTT(36) */
	19,	/* reduce-load-in-serving-cell(19) */
	3,	/* release-due-to-eutran-generated-reason(3) */
	39,	/* release-due-to-pre-emption(39) */
	18,	/* resource-optimisation-handover(18) */
	34,	/* s1-inter-system-handover-triggered(34) */
	33,	/* s1-intra-system-handover-triggered(33) */
	2,	/* successful-handover(2) */
	8,	/* tS1relocoverall-expiry(8) */
	9,	/* tS1relocprep-expiry(9) */
	17,	/* time-critical-handover(17) */
	1,	/* tx2relocoverall-expiry(1) */
	24,	/* ue-not-available-for-ps-service(24) */
	30,	/* unknown-E-RAB-ID(30) */
	14,	/* unknown-enb-ue-s1ap-id(14) */
	13,	/* unknown-mme-ue-s1ap-id(13) */
	15,	/* unknown-pair-ue-s1ap-id(15) */
	11,	/* unknown-targetID(11) */
	0,	/* unspecified(0) */
	43,	/* up-integrity-protection-not-possible(43) */
	20,	/* user-inactivity(20) */
	35	/* x2-handover-triggered(35) */
	/* This list is extensible */
};
const asn_INTEGER_specifics_t asn_SPC_CauseRadioNetwork_specs_1 = {
	asn_MAP_CauseRadioNetwork_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_CauseRadioNetwork_enum2value_1,	/* N => "tag"; sorted by N */
	44,	/* Number of elements in the maps */
	37,	/* Extensions before this member */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_CauseRadioNetwork_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_CauseRadioNetwork = {
	"CauseRadioNetwork",
	"CauseRadioNetwork",
	&asn_OP_NativeEnumerated,
	asn_DEF_CauseRadioNetwork_tags_1,
	sizeof(asn_DEF_CauseRadioNetwork_tags_1)
		/sizeof(asn_DEF_CauseRadioNetwork_tags_1[0]), /* 1 */
	asn_DEF_CauseRadioNetwork_tags_1,	/* Same as above */
	sizeof(asn_DEF_CauseRadioNetwork_tags_1)
		/sizeof(asn_DEF_CauseRadioNetwork_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_CauseRadioNetwork_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
		NativeEnumerated_constraint
	},
	0, 0,	/* Defined elsewhere */
	&asn_SPC_CauseRadioNetwork_specs_1	/* Additional specs */
};

