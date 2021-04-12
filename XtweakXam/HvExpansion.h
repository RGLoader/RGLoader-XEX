#ifndef HVEXPANSION_H
#define HVEXPANSION_H
#include "stdafx.h"
//#include "xecrypt.h"
#include <xstring>
using namespace std;

BOOL installExpansion();
BOOL loadApplyHV(string path);
BOOL loadKV(string path);
VOID writeHVPriv( BYTE* src, UINT64 dest, DWORD size);
void readHVPriv( UINT64 src, BYTE* dest, DWORD size);

#endif

