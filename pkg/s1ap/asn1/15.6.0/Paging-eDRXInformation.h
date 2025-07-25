/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_Paging_eDRXInformation_H_
#define	_Paging_eDRXInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Paging-eDRX-Cycle.h"
#include "PagingTimeWindow.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* Paging-eDRXInformation */
typedef struct Paging_eDRXInformation {
	Paging_eDRX_Cycle_t	 paging_eDRX_Cycle;
	PagingTimeWindow_t	*pagingTimeWindow	/* OPTIONAL */;
	struct ProtocolExtensionContainer	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Paging_eDRXInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Paging_eDRXInformation;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ProtocolExtensionContainer.h"

#endif	/* _Paging_eDRXInformation_H_ */
#include <asn_internal.h>
