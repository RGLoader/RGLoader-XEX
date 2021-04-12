#pragma once

#ifndef UTIL_H
#define UTIL_H

#include "stdafx.h"
#include <string>
//#include "XexLoadImage.h"
//#include "KernelExports.h"


#ifdef __cplusplus
extern "C" {
#endif
     //   UINT32 __stdcall XexGetModuleHandle(char* module, PVOID hand);
     //   UINT32 __stdcall XexGetProcedureAddress(UINT32 hand ,UINT32, PVOID);
#ifdef __cplusplus
}
#endif

#define setmemdm(addr, data) { DWORD d = data; memcpy((LPVOID)addr, &d, 4); }


UINT32 __declspec() HvxSetState(UINT32 mode);
#define PROTECT_OFF		0
#define PROTECT_ON		1
#define SET_PROT_OFF	2
#define SET_PROT_ON		3


void Mount(char* dev, char* mnt);

#define __isync()		__emit(0x4C00012C)

#define doSync(addr) \
	do { \
	__dcbst(0, addr); \
	__sync(); \
	__isync(); \
	} while (0)

#define doLightSync(addr) \
	do { \
	__dcbst(0, addr); \
	__sync(); \
	} while (0)

DWORD resolveFunct(char* modname, DWORD ord);

DWORD interpretBranchDest(DWORD currAddr, DWORD brInst);
VOID hookFunctionStart(PDWORD addr, PDWORD saveStub, PDWORD oldData, DWORD dest);
VOID unhookFunctionStart(PDWORD addr, PDWORD oldData);
DWORD relinkGPLR(int offset, PDWORD saveStubAddr, PDWORD orgAddr);
DWORD findInterpretBranch(PDWORD startAddr, DWORD maxSearch);
DWORD findInterpretBranchOrd(PCHAR modname, DWORD ord, DWORD maxSearch);
VOID patchInJump(DWORD* addr, DWORD dest, BOOL linked);
BOOL hookImpStubDebug(char* modname, char* impmodname, DWORD ord, DWORD patchAddr);

DWORD makeBranch(DWORD branchAddr, DWORD destination, BOOL linked=false);
BOOL FileExists(LPCSTR lpFileName);


void dprintf(const char* s, ...);


void swap_endian(BYTE* src, DWORD size);



void LaunchXshell(void);



//DMHRAPI DmSetMemory(LPVOID lpbAddr, DWORD cb, LPCVOID lpbBuf, LPDWORD pcbRet);
          //lpbAddr = address
		  //cb = size
          //lpbBuf = patch data
          //pcbRet = return?


HRESULT doDeleteLink(const char* szDrive, const char* sysStr);
HRESULT deleteLink(const char* szDrive, BOOL both);
HRESULT MountPath(const char* szDrive, const char* szDevice, BOOL both);

int DeleteDirectory(const std::string &refcstrRootDirectory, bool bDeleteSubdirectories = true);
BOOL IsFileExist(const char* path);
BOOL WriteBufToFile(const char* szPath, PBYTE pbData, DWORD dwLen, BOOL wRemoveExisting);
PBYTE ReadFileToBuf(const char* szPath, PDWORD size);
int CopyDirectory(const std::string &refcstrSourceDirectory,
                  const std::string &refcstrDestinationDirectory);

#endif