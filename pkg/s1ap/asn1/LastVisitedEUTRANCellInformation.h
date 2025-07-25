/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "r17.3.0/36413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-OER -no-gen-UPER -gen-XER`
 */

#ifndef	_LastVisitedEUTRANCellInformation_H_
#define	_LastVisitedEUTRANCellInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include "EUTRAN-CGI.h"
#include "CellType.h"
#include "Time-UE-StayedInCell.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* LastVisitedEUTRANCellInformation */
typedef struct LastVisitedEUTRANCellInformation {
	EUTRAN_CGI_t	 global_Cell_ID;
	CellType_t	 cellType;
	Time_UE_StayedInCell_t	 time_UE_StayedInCell;
	struct ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LastVisitedEUTRANCellInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LastVisitedEUTRANCellInformation;
extern asn_SEQUENCE_specifics_t asn_SPC_LastVisitedEUTRANCellInformation_specs_1;
extern asn_TYPE_member_t asn_MBR_LastVisitedEUTRANCellInformation_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _LastVisitedEUTRANCellInformation_H_ */
#include <asn_internal.h>
