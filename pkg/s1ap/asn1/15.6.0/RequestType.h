/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "s1ap-15.6.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -no-gen-example`
 */

#ifndef	_RequestType_H_
#define	_RequestType_H_


#include <asn_application.h>

/* Including external dependencies */
#include "EventType.h"
#include "ReportArea.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtocolExtensionContainer;

/* RequestType */
typedef struct RequestType {
	EventType_t	 eventType;
	ReportArea_t	 reportArea;
	struct ProtocolExtensionContainer	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RequestType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RequestType;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ProtocolExtensionContainer.h"

#endif	/* _RequestType_H_ */
#include <asn_internal.h>
