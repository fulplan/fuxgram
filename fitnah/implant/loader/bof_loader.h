/**
 * bof_loader.h — In-process COFF/BOF loader public header
 * Adapted from HavocFramework/Havoc CoffeeLdr (MIT)
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * BofExecute — parse, load, and run a COFF BOF in-process.
 *
 * @param coff_data   Raw COFF bytes
 * @param coff_size   COFF size
 * @param args        Argument pack (DATAP-formatted, may be NULL)
 * @param args_len    Length of args
 * @param out_buf     Receives malloc'd output string (caller LocalFree)
 * @param out_len     Receives output length
 */
BOOL BofExecute(
    const BYTE *coff_data, SIZE_T coff_size,
    char *args, int args_len,
    char **out_buf, SIZE_T *out_len);

/* Beacon API — available to BOF authors */
void  BeaconPrintf(int type, const char *fmt, ...);
void  BeaconOutput(int type, const char *data, int len);
BOOL  BeaconIsAdmin(void);
BOOL  BeaconUseToken(HANDLE tok);
void  BeaconRevertToken(void);
BOOL  BeaconGetSpawnTo(BOOL x86, char *buf, int len);

typedef struct { char *original; char *buffer; int length; int size; } DATAP;
void  BeaconDataParse(DATAP *p, char *data, int sz);
int   BeaconDataInt(DATAP *p);
short BeaconDataShort(DATAP *p);
char *BeaconDataExtract(DATAP *p, int *sz);
int   BeaconDataLength(DATAP *p);

#ifdef __cplusplus
}
#endif
