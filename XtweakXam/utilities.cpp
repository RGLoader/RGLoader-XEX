#include "utilities.h"
#include <ppcintrinsics.h>
#include <string>
//#include <xfilecache.h>


void Mount(char* dev, char* mnt)
{
	ANSI_STRING asDevice, asMount;
    RtlInitAnsiString(&asDevice, dev);
	RtlInitAnsiString(&asMount, mnt);
	ObCreateSymbolicLink(&asMount, &asDevice);
}

void dprintf(const char* s, ...)
{
	va_list argp;
	char temp[512];

	va_start(argp, s);
	vsnprintf_s(temp, 512,512, s, argp);
	va_end(argp);
	//console.Display(temp);
	OutputDebugStringA(temp);
	//DbgPrint("%s", temp);
}


DWORD resolveFunct(char* modname, DWORD ord)
{
        UINT32 ptr32=0, ret=0, ptr2=0;
        ret = XexGetModuleHandle(modname, (PHANDLE)&ptr32); //xboxkrnl.exe xam.dll?
        if(ret == 0)
        {
                ret = XexGetProcedureAddress((HANDLE)ptr32, ord, &ptr2 );
                if(ptr2 != 0)
                        return ptr2;
        }
        return 0; // function not found
}

UINT32 __declspec(naked) HvxSetState(UINT32 mode){ //2 = protection off, 3 = protection on
	__asm {
		li      r0, 0x7B
		sc
		blr
	}
}

VOID __declspec(naked) GLPR_FUN(VOID)
{
	__asm{
		std     r14, -0x98(sp)
		std     r15, -0x90(sp)
		std     r16, -0x88(sp)
		std     r17, -0x80(sp)
		std     r18, -0x78(sp)
		std     r19, -0x70(sp)
		std     r20, -0x68(sp)
		std     r21, -0x60(sp)
		std     r22, -0x58(sp)
		std     r23, -0x50(sp)
		std     r24, -0x48(sp)
		std     r25, -0x40(sp)
		std     r26, -0x38(sp)
		std     r27, -0x30(sp)
		std     r28, -0x28(sp)
		std     r29, -0x20(sp)
		std     r30, -0x18(sp)
		std     r31, -0x10(sp)
		stw     r12, -0x8(sp)
		blr
	}
}

DWORD interpretBranchDest(DWORD currAddr, DWORD brInst)
{
	DWORD ret;
	int destOff = brInst&0x3FFFFFC;
	int currOff = currAddr&~0x80000000; // make it a positive int
	if(brInst&0x2000000) // backward branch
		destOff = destOff|0xFC000000; // sign extend
	ret = (DWORD)(currOff+destOff);
	return (ret|(currAddr&0x80000000)); // put back the bit if it was used
}

DWORD findInterpretBranch(PDWORD startAddr, DWORD maxSearch)
{
	DWORD i;
	DWORD ret = 0;
	for(i = 0; i < maxSearch; i++)
	{
		if((startAddr[i]&0xFC000000) == 0x48000000)
		{
			ret = interpretBranchDest((DWORD)&startAddr[i], startAddr[i]);
			i = maxSearch;
		}
	}
	return ret;
}

DWORD relinkGPLR(int offset, PDWORD saveStubAddr, PDWORD orgAddr)
{
	DWORD saver[0x30];

	memcpy(saver, GLPR_FUN, 0x30 * 4);


	DWORD inst = 0, repl=0;
	int i;
	// if the msb is set in the instruction, set the rest of the bits to make the int negative
	if(offset&0x2000000)
		offset = offset|0xFC000000;
	//DbgPrint("frame save offset: %08x\n", offset);
	//repl = orgTemp[offset/4];
	memcpy(&repl, &orgAddr[((DWORD)offset)/4], 4);
	//DbgPrint("replacing %08x\n", repl);
	for(i = 0; i < 20; i++)
	{
		if(repl == saver[i])
		{
			int newOffset = (int)((PDWORD)(GLPR_FUN)+(DWORD)i)-(int)saveStubAddr;
			inst = 0x48000001|(newOffset&0x3FFFFFC);
			//DbgPrint("saver addr: %08x savestubaddr: %08x\n", &saver[i], saveStubAddr);
		}
	}
	//DbgPrint("new instruction: %08x\n", inst);
	return inst;
}


VOID hookFunctionStart(PDWORD addr, PDWORD saveStub, PDWORD oldData, DWORD dest)
{
	DWORD temp[0x10];
	DWORD addrtemp[0x10];
	memcpy( addrtemp, addr, 0x10 * 4);

	if((saveStub != NULL)&&(addr != NULL))
	{
		int i;
		DWORD addrReloc = (DWORD)(&addr[4]);// replacing 4 instructions with a jump, this is the stub return address
		//DbgPrint("hooking addr: %08x savestub: %08x dest: %08x addreloc: %08x\n", addr, saveStub, dest, addrReloc);
		// build the stub
		// make a jump to go to the original function start+4 instructions
		if(addrReloc & 0x8000){ // If bit 16 is 1
			//setmemdm( &saveStub[0], (0x3D600000 + (((addrReloc >> 16) & 0xFFFF) + 1)));
			temp[0] = 0x3D600000 + (((addrReloc >> 16) & 0xFFFF) + 1); // lis %r11, dest>>16 + 1printf("  - one\r\n");
		}else{
			//setmemdm( &saveStub[0], (0x3D600000 + (((addrReloc >> 16) & 0xFFFF) + 1)));
			temp[0] = 0x3D600000 + ((addrReloc >> 16) & 0xFFFF); // lis %r11, dest>>16
		}


		temp[1] = 0x396B0000 + (addrReloc & 0xFFFF); // addi %r11, %r11, dest&0xFFFF
		temp[2] = 0x7D6903A6; // mtctr %r11
		// instructions [3] through [6] are replaced with the original instructions from the function hook
		// copy original instructions over, relink stack frame saves to local ones
		if(oldData != NULL)
		{
			for(i = 0; i<4; i++)
				oldData[i] = addrtemp[i];
		}
		for(i = 0; i<4; i++)
		{
			if((addrtemp[i]&0x48000003) == 0x48000001) // branch with link
			{
				//DbgPrint("relink %08x\n", addr[i]);
				temp[i+3] = relinkGPLR((addrtemp[i]&~0x48000003), &saveStub[i+3], &addr[i]);
			}
			else
			{
				//DbgPrint("copy %08x\n", addr[i]);
				temp[i+3] = addrtemp[i];
			}
		}

		temp[7] = 0x4E800420; // bctr
		//doSync(temp);
		//DbgPrint("savestub:\n");
		//for(i = 0; i < 8; i++)
		//{
		//	DbgPrint("PatchDword(0x%08x, 0x%08x);\n", &saveStub[i], saveStub[i]);
		//}
		// patch the actual function to jump to our replaced one
		memcpy( saveStub, temp, 8 * 4); 
		patchInJump(addr, dest, FALSE);
	}
}

VOID unhookFunctionStart(PDWORD addr, PDWORD oldData)
{
	if((addr != NULL)&&(oldData != NULL))
	{
		int i;
		for(i = 0; i < 4; i++)
		{
			addr[i] = oldData[i];
		}
		doSync(addr);
	}
}

DWORD findInterpretBranchOrd(PCHAR modname, DWORD ord, DWORD maxSearch)
{
	DWORD ret = 0;
	PDWORD search = (PDWORD)resolveFunct(modname, ord);
	if(search != NULL)
		ret = findInterpretBranch(search, maxSearch);
	return ret;
}




VOID patchInJump(DWORD* addr, DWORD dest, BOOL linked){
	DWORD temp[4];

	if(dest & 0x8000) // If bit 16 is 1
		temp[0] = 0x3D600000 + (((dest >> 16) & 0xFFFF) + 1); // lis 	%r11, dest>>16 + 1
	else
		temp[0] = 0x3D600000 + ((dest >> 16) & 0xFFFF); // lis 	%r11, dest>>16

	temp[1] = 0x396B0000 + (dest & 0xFFFF); // addi	%r11, %r11, dest&0xFFFF
	temp[2] = 0x7D6903A6; // mtctr	%r11

	if(linked)
		temp[3] = 0x4E800421; // bctrl
	else
		temp[3] = 0x4E800420; // bctr
	
	memcpy(addr,temp, 0x10);
}

////////////////////////////////////////////////////////////////////////
// This is the modified version of hookImpStub
// modified to work with Devkits

BOOL hookImpStubDebug(char* modname, char* impmodname, DWORD ord, DWORD patchAddr)
{
	DWORD orgAddr;
	PLDR_DATA_TABLE_ENTRY ldat;
	int i, j;
	BOOL ret = FALSE;
	// get the address of the actual function that is jumped to
	orgAddr = resolveFunct(impmodname, ord);
	if(orgAddr != 0)
	{
		// find where kmod info is stowed
		ldat = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle(modname);
		if(ldat != NULL)
		{
			// use kmod info to find xex header in memory
			PXEX_IMPORT_DESCRIPTOR imps = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(ldat->XexHeaderBase, 0x000103FF);
			if(imps != NULL)
			{
				char* impName = (char*)(imps+1);
				PXEX_IMPORT_TABLE impTbl = (PXEX_IMPORT_TABLE)(impName + imps->NameTableSize);
				for(i = 0; i < (int)(imps->ModuleCount); i++)
				{
					// use import descriptor strings to refine table
					for(j = 0; j < impTbl->ImportCount; j++)
					{
						PDWORD add = (PDWORD)impTbl->ImportStubAddr[j];
						if(add[0] == orgAddr)
						{
							HRESULT hr;
							hr = (HRESULT) memcpy(add, (LPCVOID)patchAddr, 4);
							//DbgPrint("XTW: 2 hr = 0x%008X | at addr: 0x%08X\n", hr, add);
							BYTE data[0x10];
							patchInJump((PDWORD)data, patchAddr, FALSE);
							hr = (HRESULT)memcpy((PDWORD)(impTbl->ImportStubAddr[j+1]), (LPCVOID)data, 0x10);
							//memcpy((PDWORD)(impTbl->ImportStubAddr[j+1]), data, 0x10);
							//DbgPrint("XTW: 2 hr = 0x%008X | at addr: 0x%08X\n", hr, (PDWORD)(impTbl->ImportStubAddr[j+1]));
							//DbgPrint("%s %s tbl %d has ord %x at tstub %d location %08x\n", modname, impName, i, ord, j, impTbl->ImportStubAddr[j+1]);
							//patchInJump((PDWORD)(impTbl->ImportStubAddr[j+1]), patchAddr, FALSE);
							j = impTbl->ImportCount;
							ret = TRUE;
						}
					}
					impTbl = (PXEX_IMPORT_TABLE)((BYTE*)impTbl+impTbl->TableSize);
					impName = impName+strlen(impName);
					while((impName[0]&0xFF) == 0x0)
						impName++;
				}
			}		
			//else DbgPrint("could not find import descriptor for mod %s\n", modname);
		}
		//else DbgPrint("could not find data table for mod %s\n", modname);
	}
	//else DbgPrint("could not find ordinal %d in mod %s\n", ord, impmodname);

	return ret;
}

DWORD makeBranch(DWORD branchAddr, DWORD destination, BOOL linked) {
	return (0x48000000)|((destination-branchAddr)&0x03FFFFFF)|(DWORD)linked;
}


void swap_endian(BYTE* src, DWORD size)
{

	BYTE* temp = new BYTE[size];
	for(int i=size-4, b=0; i>=0; i-=4, b+=4){
		*(DWORD*)&temp[b]=(DWORD)src[i];
	}
	memcpy(src, temp, size);
	delete[size] temp;
}

HRESULT cOzMount(const char* szDrive, const char* szDevice, const char* sysStr)
    {
            STRING DeviceName, LinkName;
            CHAR szDestinationDrive[MAX_PATH];
            sprintf_s(szDestinationDrive, MAX_PATH, sysStr, szDrive);
            RtlInitAnsiString((PANSI_STRING)&DeviceName, szDevice);
            RtlInitAnsiString((PANSI_STRING)&LinkName, szDestinationDrive);
            ObDeleteSymbolicLink((PANSI_STRING)&LinkName);
            return (HRESULT)ObCreateSymbolicLink((PANSI_STRING)&LinkName, (PANSI_STRING)&DeviceName);
    }




void reLaunchXshell(void){

	printf("[RGLOADER]: Thread ---------!\n");

	if(KeGetCurrentProcessType() == PROC_SYSTEM){
		printf("[RGLOADER]: Thread is still system!\n");
	}else printf("[RGLOADER]: Attempting to launch xshell! Mounting drives..\n");


	/*XFlushUtilityDrive();
    XFileCacheInit(XFILECACHE_CLEAR_ALL,0,XFILECACHE_DEFAULT_THREAD,0,1);
    XFileCacheShutdown();
    XFlushUtilityDrive();*/


	XSetLaunchData( NULL, 0 );
	XamLoaderLaunchTitleEx("\\SystemRoot\\dash.xex", NULL, NULL, 0);
	//XLaunchNewImage( XLAUNCH_KEYWORD_DEFAULT_APP, 0);

     /*if(cOzMount("rgl:", "\\SystemRoot", "\\??\\%s")!= 0) 
		 printf("ERROR[RGLOADER]: Error mounting drive.\n"); // for sys threads use "\\System??\\%s"
	 if(cOzMount("rgl2:", "\\SystemRoot", "\\System??\\%s") != 0) 
		 printf("ERROR[RGLOADER]: Error mounting drive2.\n"); // for sys threads use "\\System??\\%s"

	 XLaunchNewImage("rgl2:\\dash.xex", 0);
     XLaunchNewImage("rgl:\\dash.xex", 0);*/

}
     
    void LaunchXshell(void)
    {
            if(KeGetCurrentProcessType() == PROC_SYSTEM)
            {
				/*HMODULE handle = GetModuleHandle("hud.xex");
				if(!handle) printf("ERROR[RGLOADER]: Could not get handle to hud.xex\n");
				else{
					printf("[RGLOADER]: Freeing Hud.xex library\n");
					FreeLibraryAndExitThread(handle, 1);
				}*/
				printf("[RGLOADER]: System thread, attempting to launch xshell.\n");
				XSetLaunchData( NULL, 0 );

				//XamLoaderLaunchTitleEx("\\Device\\Harddisk0\\Partition1\\DEVKIT\\Utilities\\DashSelector\\DashSelector.xex", "\\Device\\Harddisk0\\Partition1\\DEVKIT\\Utilities\\DashSelector", NULL, 0);
				XamLoaderLaunchTitleEx("\\Device\\Flash\\xshell.xex", "\\Device\\Flash", NULL, 0);

				/*printf("[RGLOADER]: System thread, creating retail thread to launch xshell.\n");
                HANDLE hThread;
                DWORD dwThreadId;
                hThread = CreateThread( 0, 0, (LPTHREAD_START_ROUTINE)reLaunchXshell, 0, CREATE_SUSPENDED, &dwThreadId );
				printf("[RGLOADER]: System thread, setting processor.\n");
                XSetThreadProcessor(hThread, 4);
			    SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
				printf("[RGLOADER]: System thread, resuming thread.\n");
                ResumeThread(hThread);
				printf("[RGLOADER]: System thread, closing handle.\n");
                CloseHandle(hThread);*/
            }
            else
            {
				printf("[RGLOADER]: Launching xshell!");
                reLaunchXshell();
            }
    }

BOOL FileExists(LPCSTR lpFileName) {

	if(GetFileAttributes(lpFileName) == -1) {
		DWORD lastError = GetLastError();
		if(lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_PATH_NOT_FOUND)
			return FALSE;
	}

	return TRUE;
}




int DeleteDirectory(const std::string &refcstrRootDirectory,
                    bool              bDeleteSubdirectories)
{
  bool            bSubdirectory = false;       // Flag, indicating whether
                                               // subdirectories have been found
  HANDLE          hFile;                       // Handle to directory
  std::string     strFilePath;                 // Filepath
  std::string     strPattern;                  // Pattern
  WIN32_FIND_DATA FileInformation;             // File information


  strPattern = refcstrRootDirectory + "\\*.*";
  hFile = ::FindFirstFile(strPattern.c_str(), &FileInformation);
  if(hFile != INVALID_HANDLE_VALUE)
  {
    do
    {
      if(FileInformation.cFileName[0] != '.')
      {
        strFilePath.erase();
        strFilePath = refcstrRootDirectory + "\\" + FileInformation.cFileName;

        if(FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
          if(bDeleteSubdirectories)
          {
            // Delete subdirectory
            int iRC = DeleteDirectory(strFilePath, bDeleteSubdirectories);
            if(iRC)
              return iRC;
          }
          else
            bSubdirectory = true;
        }
        else
        {
          // Set file attributes
          if(::SetFileAttributes(strFilePath.c_str(),
                                 FILE_ATTRIBUTE_NORMAL) == FALSE)
            return ::GetLastError();

          // Delete file
          if(::DeleteFile(strFilePath.c_str()) == FALSE)
            return ::GetLastError();
        }
      }
    } while(::FindNextFile(hFile, &FileInformation) == TRUE);

    // Close handle
    ::FindClose(hFile);

    DWORD dwError = ::GetLastError();
    if(dwError != ERROR_NO_MORE_FILES)
      return dwError;
    else
    {
      if(!bSubdirectory)
      {
        // Set directory attributes
        if(::SetFileAttributes(refcstrRootDirectory.c_str(),
                               FILE_ATTRIBUTE_NORMAL) == FALSE)
          return ::GetLastError();

        // Delete directory
        if(::RemoveDirectory(refcstrRootDirectory.c_str()) == FALSE)
          return ::GetLastError();
      }
    }
  }

  return 0;
}

BOOL IsFileExist(const char* path)
{
	HANDLE file = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(file == INVALID_HANDLE_VALUE)
	{
		if(GetLastError() != 5) // inaccessible means it exists but is probably open somewhere else
			return FALSE;
	}
	else
		CloseHandle(file);
	return TRUE;
}

HRESULT doDeleteLink(const char* szDrive, const char* sysStr)
{
	STRING LinkName;
	CHAR szDestinationDrive[MAX_PATH];
	sprintf_s(szDestinationDrive, MAX_PATH, sysStr, szDrive);
	RtlInitAnsiString(&LinkName, szDestinationDrive);
	return ObDeleteSymbolicLink(&LinkName);
}

HRESULT deleteLink(const char* szDrive, BOOL both)
{
	HRESULT res = -1;
	if(both)
	{
		res = doDeleteLink(szDrive, OBJ_SYS_STRING);
		res |= doDeleteLink(szDrive, OBJ_USR_STRING);
	}
	else
	{
		if(KeGetCurrentProcessType() == PROC_SYSTEM)
			res = doDeleteLink(szDrive, OBJ_SYS_STRING);
		else
			res = doDeleteLink(szDrive, OBJ_USR_STRING);
	}
	return res;
}


HRESULT doMountPath(const char* szDrive, const char* szDevice, const char* sysStr)
{
	STRING DeviceName, LinkName;
	CHAR szDestinationDrive[MAX_PATH];
	sprintf_s(szDestinationDrive, MAX_PATH, sysStr, szDrive);
	RtlInitAnsiString(&DeviceName, szDevice);
	RtlInitAnsiString(&LinkName, szDestinationDrive);
	ObDeleteSymbolicLink(&LinkName);
	return (HRESULT)ObCreateSymbolicLink(&LinkName, &DeviceName);
}

HRESULT MountPath(const char* szDrive, const char* szDevice, BOOL both)
{
	HRESULT res = -1;
	if(both)
	{
		res = doMountPath(szDrive, szDevice, OBJ_SYS_STRING);
		res |= doMountPath(szDrive, szDevice, OBJ_USR_STRING);
	}
	else
	{
		if(KeGetCurrentProcessType() == PROC_SYSTEM)
			res = doMountPath(szDrive, szDevice, OBJ_SYS_STRING);
		else
			res = doMountPath(szDrive, szDevice, OBJ_USR_STRING);
	}
	return res;
}

PBYTE ReadFileToBuf(const char* szPath, PDWORD size)
{
	if(IsFileExist(szPath))
	{
		HANDLE hFile = CreateFile(szPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if(hFile != INVALID_HANDLE_VALUE)
		{
			DWORD dwRead;
			PBYTE buf;
			*size = GetFileSize(hFile, NULL);
			if(*size != 0)
			{
				buf = new BYTE[*size];
				ReadFile(hFile, buf, *size, &dwRead, NULL);
				CloseHandle(hFile);
				return buf;
			}
		}
	}
	return NULL;
}

BOOL WriteBufToFile(const char* szPath, PBYTE pbData, DWORD dwLen, BOOL wRemoveExisting)
{
	if(wRemoveExisting)
	{
		if(IsFileExist(szPath))
			DeleteFileA(szPath);
	}
	HANDLE hFile = CreateFile(szPath, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwWrote = 0;
		DWORD currPos = 0;
		while(dwLen > 0)
		{
			WriteFile(hFile, &pbData[currPos], dwLen, &dwWrote, NULL);
			currPos+= dwWrote;
			dwLen -= dwWrote;
		}
		return TRUE;
	}
	return FALSE;
}

int CopyDirectory(const std::string &refcstrSourceDirectory,
                  const std::string &refcstrDestinationDirectory)
{
  std::string     strSource;               // Source file
  std::string     strDestination;          // Destination file
  std::string     strPattern;              // Pattern
  HANDLE          hFile;                   // Handle to file
  WIN32_FIND_DATA FileInformation;         // File information


  strPattern = refcstrSourceDirectory + "\\*.*";

  // Create destination directory
  ::CreateDirectory(refcstrDestinationDirectory.c_str(), 0);
   

  hFile = ::FindFirstFile(strPattern.c_str(), &FileInformation);
  if(hFile != INVALID_HANDLE_VALUE)
  {
    do
    {
      if(FileInformation.cFileName[0] != '.')
      {
        strSource.erase();
        strDestination.erase();

        strSource      = refcstrSourceDirectory + "\\" + FileInformation.cFileName;
        strDestination = refcstrDestinationDirectory + "\\" + FileInformation.cFileName;

        if(FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
          // Copy subdirectory
          if(CopyDirectory(strSource, strDestination))
            return 1;
        }
        else
        {
          // Copy file
          if(::CopyFile(strSource.c_str(), strDestination.c_str(), TRUE) == FALSE)
            return ::GetLastError();
        }
      }
    } while(::FindNextFile(hFile, &FileInformation) == TRUE);

    // Close handle
    ::FindClose(hFile);

    DWORD dwError = ::GetLastError();
    if(dwError != ERROR_NO_MORE_FILES)
      return dwError;
  }

  return 0;
}