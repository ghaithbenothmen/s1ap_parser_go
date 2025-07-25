/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_BroadcastCancelledAreaList_H_
#define	_BroadcastCancelledAreaList_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CellID-Cancelled.h"
#include "TAI-Cancelled.h"
#include "EmergencyAreaID-Cancelled.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum BroadcastCancelledAreaList_PR {
	BroadcastCancelledAreaList_PR_NOTHING,	/* No components present */
	BroadcastCancelledAreaList_PR_cellID_Cancelled,
	BroadcastCancelledAreaList_PR_tAI_Cancelled,
	BroadcastCancelledAreaList_PR_emergencyAreaID_Cancelled
	/* Extensions may appear below */
	
} BroadcastCancelledAreaList_PR;

/* BroadcastCancelledAreaList */
typedef struct BroadcastCancelledAreaList {
	BroadcastCancelledAreaList_PR present;
	union BroadcastCancelledAreaList_u {
		CellID_Cancelled_t	 cellID_Cancelled;
		TAI_Cancelled_t	 tAI_Cancelled;
		EmergencyAreaID_Cancelled_t	 emergencyAreaID_Cancelled;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} BroadcastCancelledAreaList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_BroadcastCancelledAreaList;

#ifdef __cplusplus
}
#endif

#endif	/* _BroadcastCancelledAreaList_H_ */
#include <asn_internal.h>
