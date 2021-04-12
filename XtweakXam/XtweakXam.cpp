// XtweakXam.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include <xbdm.h>
#include <fstream>
#include <string>
#include <stdio.h>
#include "INIReader.h"
#include "xam.h"
#include "HUD.h"
#include "xshell.h"
#include "HvExpansion.h"
#include "OffsetManager.h"
#include "sysext.h"
using namespace std;

static bool fKeepMemory=true;
static bool fExpansionEnabled = false;
static INIReader* reader;
static OffsetManager offsetmanager;

#define setmem(addr, data) { DWORD d = data; memcpy((LPVOID)addr, &d, 4);}

/*void setmem(DWORD addr, DWORD data) {
	UINT64 d = data;
	if(addr < 0x40000)
	{
		// hv patch
		if(fExpansionEnabled)
		{
			printf("     (hv patch)\n");
			addr = addr | 0x8000000000000000ULL;
			BYTE* newdata = (BYTE*)XPhysicalAlloc(sizeof(DWORD), MAXULONG_PTR, 0, PAGE_READWRITE);
			memcpy(newdata, &d, sizeof(DWORD));
			writeHVPriv(newdata, addr, sizeof(DWORD));
			XPhysicalFree(newdata);
		}
		else
			printf("     (hv patch, but expansion didn't install :( )\n");
	}
	else
		DmSetMemory((LPVOID)addr, 4, &d, NULL);
}*/

void patch_BLOCK_LIVE(){
	{
		printf(" * Blocking xbox live DNS\r\n");

		char* nullStr = "NO.%sNO.NO\0";
		DWORD nullStrSize = 18;

		XAMOffsets* offsets = offsetmanager.getXamOffsets();
		if(!offsets)
		{
			printf("Failed to load dns offsets!\r\n");
			return;
		}

		//null out xbox live dns tags
		if(offsets->live_siflc)//FIXME: check the others
			memcpy( (LPVOID)offsets->live_siflc, (LPCVOID)nullStr, nullStrSize);
		memcpy( (LPVOID)offsets->live_piflc, (LPCVOID)nullStr, nullStrSize);
		memcpy( (LPVOID)offsets->live_notice, (LPCVOID)nullStr, nullStrSize);
		memcpy( (LPVOID)offsets->live_xexds, (LPCVOID)nullStr, nullStrSize);
		memcpy( (LPVOID)offsets->live_xetgs, (LPCVOID)nullStr, nullStrSize);
		memcpy( (LPVOID)offsets->live_xeas, (LPCVOID)nullStr, nullStrSize);
		memcpy( (LPVOID)offsets->live_xemacs, (LPCVOID)nullStr, nullStrSize);

	}

}

// Enable USBMASS0-2 in neighborhood
void patch_MAP_USB(void){

	XBDMOffsets* offsets = offsetmanager.getXbdmOffsets();
	if(!offsets)
	{
		printf("Failed to load xbdm offsets!\n");
		return;
	}

	printf(" * Adding extra devices to xbox neighborhood\r\n");
	{
		//add usb devices to xbn
		setmem(offsets->mass0_obname_ptr, offsets->mass0_obname);
		setmem(offsets->mass1_obname_ptr, offsets->mass1_obname);
		setmem(offsets->mass2_obname_ptr, offsets->mass2_obname);
		setmem(offsets->mass0_enable, 0x01);
		setmem(offsets->mass1_enable, 0x01);
		setmem(offsets->mass2_enable, 0x01);

		//add flash to xbn
		setmem(offsets->flash_obname_ptr, offsets->flash_obname);
		setmem(offsets->flash_enable, 0x01);

		//add hdd system ext partition  to xbn
		setmem(offsets->hddsysext_obname_ptr, offsets->hddsysext_obname);
		setmem(offsets->hddsysext_enable, 0x01);

		//add intusb system ext partition to xbn
		setmem(offsets->intusbsysext_obname_ptr, offsets->intusbsysext_obname);
		setmem(offsets->intusbsysext_enable, 0x01);

		//add intusb system ext partition to xbn
		setmem(offsets->hddsysaux_obname_ptr, offsets->hddsysaux_obname);
		setmem(offsets->hddsysaux_enable, 0x01);

		//nop drivemap internal check (always be 1)
		setmem(offsets->map_internal_check, 0x60000000);
	}

}

//21076
// Changes the default dashboard
void patch_default_dash(string path){

	printf(" * Reconfiguring default dash to: %s\r\n", path);
	
	ofstream dashxbx;

	//dashxbx.open("Hdd:\\Filesystems\14719-dev\dashboard.xbx", ofstream::out);
	dashxbx.open("Root:\\dashboard.xbx", ofstream::out);

	if(dashxbx.is_open()){
		
		dashxbx<<path;
		for(int i=path.length(); i<0x100; i++) dashxbx<<'\0';
		dashxbx.close();
	}else{
		printf("   ERROR: unable to write dashboard.xbx\r\n");
	}
	
}




static string xexNamestr = "";
static int backslash = 0;
static string rTemp="";


bool strCompare(char* one, char* two, int len){
	int i=0;
	for(i=0; i<len; i++){
		if(i>0 && (one[i]=='\0' || two[i]=='\0')) return true; 
		if(one[i]!=two[i]) return false;
		
	}
	return true;
}



VOID __declspec(naked) XexpLoadImageSaveVar(VOID)
{
	__asm{
		li r3, 454 //make this unique for each hook
		nop
		nop
		nop
		nop
		nop
		nop
		blr
	}
}

#define XexLoadExecutableOrd 408

#define XexLoadImageOrd 409

#define XEXLOADIMAGE_MAX_SEARCH		9

NTSTATUS XexpLoadImageHook(LPCSTR xexName, DWORD typeInfo, DWORD ver, PHANDLE modHandle);
typedef NTSTATUS (*XEXPLOADIMAGEFUN)(LPCSTR xexName, DWORD typeInfo, DWORD ver, PHANDLE modHandle); // XexpLoadImage
static DWORD xexLoadOld[4];

int patch_hook_xexload(void){
	//printf(" * Hooking xeximageload for persistant patches\n");
	//hookImpStubDebug("xam.xex", "xboxkrnl.exe", XexLoadExecutableOrd, (DWORD)XexLoadExecutableHook);
	//hookImpStubDebug("xam.xex", "xboxkrnl.exe", XexLoadImageOrd, (DWORD)XexLoadImageHook);
	
	PDWORD xexLoadHookAddr = (PDWORD)findInterpretBranchOrd("xboxkrnl.exe", XexLoadImageOrd, XEXLOADIMAGE_MAX_SEARCH);
	printf("  - Found addr\r\n");
	if(xexLoadHookAddr != NULL)
	{
		//printf("  - Applying hook at %08X  with  save @ %08X\r\n", xexLoadHookAddr, (PDWORD)XexpLoadImageSaveVar);
		hookFunctionStart(xexLoadHookAddr, (PDWORD)XexpLoadImageSaveVar, xexLoadOld, (DWORD)XexpLoadImageHook);

	}

	return 1;
}

#define XEXLOAD_DASH	"\\Device\\Flash\\dash.xex"
#define XEXLOAD_DASH2	"\\SystemRoot\\dash.xex"
#define XEXLOAD_SIGNIN	"signin.xex"
#define XEXLOAD_CREATE	"createprofile.xex"
#define XEXLOAD_HUD		"hud.xex"

XEXPLOADIMAGEFUN XexpLoadImageSave = (XEXPLOADIMAGEFUN)XexpLoadImageSaveVar;
NTSTATUS XexpLoadImageHook(LPCSTR xexName, DWORD typeInfo, DWORD ver, PHANDLE modHandle){

	//printf(" * PERSISTENT XEX PATCHER\r\n");

	NTSTATUS ret = XexpLoadImageSave(xexName, typeInfo, ver, modHandle);

	//printf(" * Checking strings\r\n");
	
	//printf("\n\n ***RGLoader.xex  -Checking typeInfo: %08X!\n\n", xexLoadParams.typeInfo);
	//printf("Checking name: %s \r\nFirst loop!\r\n", xexName);
	
	//UINT32 titleID = XamGetCurrentTitleId();
    /*if ( titleID == BlackOpsID )
		{
		if (strstr(xexName, "default_mp") != 0)
		{
			DbgPrint("Hooking into Black Ops MP xex\n");
			// MP GSC/CSC hook*/


	if(ret >= 0){

		if(stricmp(xexName, XEXLOAD_HUD) == 0){
			printf("\n\n ***RGLoader.xex*** \n   -Re-applying patches to: %s!\n\n", xexName);
			
			rTemp = reader->Get("Expansion", "HUD_Jump_To_XShell", "NOTFOUND");
			if(rTemp != "NOTFOUND" && (rTemp == "1" || rTemp == "true" || rTemp=="on")){
				printf("     * Replacing family settings button with \"Jump to XShell\"");
				patch_HUD_ReturnToXshell();
			}
		
		}

		const char * xshellName = "xshell.xex";
		if(strlen(xexName) >= 10)
		{
			if(stricmp(xexName + strlen(xexName) - 10, xshellName) == 0){
				printf("\n\n ***RGLoader.xex*** \n   -Re-applying patches to: %s!\n\n", xexName);
	
				rTemp = reader->Get("Config", "Redirect_Xshell_Start_But", "NOTFOUND");
				if(rTemp != "NOTFOUND" && (rTemp != "1" && rTemp != "true" && rTemp!="on")  && (rTemp != "0" && rTemp != "false" && rTemp!="off")){
					printf("     * Remapping xshell start button to %s.\n\n", rTemp.c_str());
					patch_Xshell_start_path(rTemp);
				}
			}
		}
		else if(stricmp(xexName, XEXLOAD_SIGNIN) == 0){
			printf("\n\n ***RGLoader.xex*** \n   -Re-applying patches to: %s!\n", xexName);

			rTemp = reader->Get("Config", "No_Sign_Notice", "NOTFOUND");
			if(rTemp == "NOTFOUND" || (rTemp == "1" || rTemp == "true" || rTemp=="on")){
				printf("     * Disabling xbox live sign in notice.\n\n");
				SIGNINOffsets* offsets = offsetmanager.getSigninOffsets();
				if(offsets != NULL)
				{
					setmem(offsets->NoSignNotice, 0x38600000);
				}
				else
				{
					printf("Failed to load signin offsets!\r\n");
				}
			}
		
		}
	}
	return ret;
}

	

//function called at the end of xexloadimage
/*void __declspec( naked ) runtime_patches(void){
	

	__asm
        {
			mr   r3, r31
			blr
		}
}

#define XEXLOADIMAGE_HOOK 0x800A3A98
#define XEXLOADIMAGE_JUMP 0x801AA114  //empty space

int patch_hook_xexload(void){
	printf(" * Hooking xeximageload for persistant patches\n");
	BYTE data[0x10];
	patchInJump((PDWORD)data, (DWORD)runtime_patches, FALSE);
	HRESULT hr;
	hr = DmSetMemory((PDWORD)(XEXLOADIMAGE_JUMP), 0x10, (LPCVOID)data, 0);
	DWORD patch = (DWORD)(((0x48000000)|((XEXLOADIMAGE_JUMP-XEXLOADIMAGE_HOOK)&0x03FFFFFF))|1);
	//printf("   -Patching to %08X\n", patch);
	setmem((DWORD)XEXLOADIMAGE_HOOK, patch);
	return hr;
}*/

//######################################


int patch_apply_binary(string filepath){

	FILE* patches;
	BYTE* buffer;
	long size=0, patchesApplied=0;

	patches= fopen(filepath.c_str(), "rb");
	if(!patches) return false;

	fseek(patches, 0, SEEK_END);
	size = ftell(patches);
	if(size%4!=0) {
		printf("   ERROR: Invalid patch size\n");
		fclose(patches);
		return 0;
	}
	//rewind(patches);
	fseek(patches, 0, SEEK_SET);
	buffer = new BYTE[size];
	fread(buffer, 1, size, patches);
	//swap_endian((BYTE*)buffer, size);

	DWORD offset=0;
	if(*(DWORD*)&buffer[offset]==0x52474C50) offset+=4;
	DWORD dest=*(DWORD*)&buffer[offset];
	offset+=4;

	while(dest!=0xFFFFFFFF && offset<size){
		DWORD numPatches = *(DWORD*)&buffer[offset];
		offset+=4;
		for(int i=0; i<numPatches; i++, offset+=4, dest+=4){
			//printf("     %08X  -> 0x%08X\n", dest, *(DWORD*)&buffer[offset]);
			setmem(dest, *(DWORD*)&buffer[offset]);
		}
		dest=*(DWORD*)&buffer[offset];
		offset+=4;
		patchesApplied++;
	}
	fclose(patches);
	return patchesApplied;
}


void patch_search_binary(void){
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;

	printf(" * Searching for additional RGLP binary patch files\n");

	hFind = FindFirstFile("Root:\\*.rglp", &FindFileData);
	while(hFind!= INVALID_HANDLE_VALUE){
		printf("  **located binary: %s\n", FindFileData.cFileName);
		
		if(patch_apply_binary("Root:\\"+(string)FindFileData.cFileName)<=0) printf("  ERROR: Cannot apply patch\n");

		if(!FindNextFile(hFind, &FindFileData))hFind=INVALID_HANDLE_VALUE;
	}
}

VOID loadPlugins(){

	//Turn off xex load blocking
	//*((DWORD*)0x801CDD70) = 0;

	string temp = reader->Get("Plugins", "Plugin1", "NOTFOUND");
	if(temp!="NOTFOUND" && temp!="none"){
		if(XexLoadImage(temp.c_str(),8,0,NULL))
			printf(" ERROR: Failed to load %s", temp.c_str());
	}
	temp = reader->Get("Plugins", "Plugin2", "NOTFOUND");
	if(temp!="NOTFOUND" && temp!="none"){
		if(XexLoadImage(temp.c_str(),8,0,NULL))
			printf(" ERROR: Failed to load %s", temp.c_str());
	}
	temp = reader->Get("Plugins", "Plugin3", "NOTFOUND");
	if(temp!="NOTFOUND" && temp!="none"){
		if(XexLoadImage(temp.c_str(),8,0,NULL))
			printf(" ERROR: Failed to load %s", temp.c_str());
	}
	temp = reader->Get("Plugins", "Plugin4", "NOTFOUND");
	if(temp!="NOTFOUND" && temp!="none"){
		if(XexLoadImage(temp.c_str(),8,0,NULL))
			printf(" ERROR: Failed to load %s", temp.c_str());
	}
	temp = reader->Get("Plugins", "Plugin5", "NOTFOUND");
	if(temp!="NOTFOUND" && temp!="none"){
		if(XexLoadImage(temp.c_str(),8,0,NULL))
			printf(" ERROR: Failed to load %s", temp.c_str());
	}
}


BOOL Initialize(HANDLE hModule){

	printf("===RGLoader Runtime Patcher - Version 02===\r\n\r\n");

	Mount("\\Device\\Harddisk0\\Partition1", "\\System??\\Hdd:");
	Mount("\\Device\\Harddisk0\\Partition1", "\\System??\\HDD:");
	Mount("\\Device\\Mass0", "\\System??\\Mass0:");
	Mount("\\Device\\Mass1", "\\System??\\Mass1:");
	Mount("\\Device\\Mass2", "\\System??\\Mass2:");

	Mount("\\SystemRoot", "\\System??\\Root:");

	// EXPANSION!
	//fExpansionEnabled = installExpansion();


	
	reader = new INIReader("Mass0:\\rgloader.ini");
	if(reader->ParseError() < 0) reader = new INIReader("Mass1:\\rgloader.ini");
	if(reader->ParseError() < 0) reader = new INIReader("Mass2:\\rgloader.ini");
	if(reader->ParseError() < 0) reader= new INIReader("Hdd:\\rgloader.ini");

	if(reader->ParseError() < 0) {
		printf("ERROR: Unable to open ini file!\r\n");
		patch_MAP_USB();
		fKeepMemory=false;
		return 0;
	}

	string temp = reader->Get("Filters", "Block_Live_DNS", "NOTFOUND");
	if (temp != "NOTFOUND" && (temp == "1" || temp == "true" || temp == "on")) {
		patch_BLOCK_LIVE();
	}

	//search for extra binary patches
	temp = reader->Get("Config", "NoRGLP", "NOTFOUND");
	if (temp == "NOTFOUND" || temp != "FALSE" || temp != "false") {
		patch_search_binary();
	}

	char* SysExtPath = "HDD:\\Filesystems\\17489-dev\\$SystemUpdate";
	if (FileExists(SysExtPath)) {
		printf(" * Attemping to install system extended partion from %s\n", SysExtPath);

		if (setupSysPartitions(SysExtPath) == ERROR_SEVERITY_SUCCESS)
			printf("  -Success!\n");
		else
			printf("  -Failed\n");

		printf(" * Fixing XAM FEATURES\n");
#define XamFeatureEnableDisable 0x817483A8
		((void(*)(...))XamFeatureEnableDisable)(1, 2);
		((void(*)(...))XamFeatureEnableDisable)(1, 3);
		((void(*)(...))XamFeatureEnableDisable)(1, 4);

		((void(*)(...))XamFeatureEnableDisable)(0, 1);
		((void(*)(...))XamFeatureEnableDisable)(0, 5);
		((void(*)(...))XamFeatureEnableDisable)(0, 6);
		((void(*)(...))XamFeatureEnableDisable)(0, 7);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x21);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x22);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x23);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x24);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x26);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x27);

		
	}
	else {
		printf(" * No system extended files found, skipping..\n");
	}


	

	printf(" Patches successfully applied! \r\n\r\n");

	loadPlugins();

	/*{  //uncomment to make it only run on the first boot, then will be disabled.  Good for debugging things that crash.
		FILE* temp;
		temp= fopen("Hdd:\\test.test", "rb");
		if(temp){
			printf(" * ALREADY BOOTED ONCE! Quitting Rgloader.xex!\r\n");
			fclose(temp);
			return 0;
		}
	}
	{
		FILE* temp;
		temp= fopen("Hdd:\\test.test", "w");
		fclose(temp);
	}*/

	//while(1);

	

	temp = reader->Get("Expansion", "Map_USB_Mass", "NOTFOUND");
	if(temp == "1" || temp == "true" || temp=="on"){
		patch_MAP_USB();
	}
	temp = reader->Get("Expansion", "Persistent_Patches", "NOTFOUND");
	if(temp == "1" || temp == "true" || temp=="on"){
		patch_hook_xexload();
	}
	
	temp = reader->Get("Config", "Default_Dashboard", "NOTFOUND");
	if(temp!="NOTFOUND"){
		patch_default_dash(temp);
	}

	temp = reader->Get("Expansion", "Boot_Animation", "NOTFOUND");
	if(temp!="NOTFOUND" && (temp == "1" || temp == "true") && FileExists("Root:\\RGL_bootanim.xex")){
		patch_default_dash("\\SystemRoot\\RGL_bootanim.xex");
	}

	temp = reader->Get("Expansion", "Retail_Profile_Encryption", "NOTFOUND");
	if(temp == "1" || temp == "true" || temp=="on"){
		printf(" * Setting up retail profile encryption\n");
		Xam_Profile_Crypto_Hook_Setup();
	}

	if(fExpansionEnabled)
	{
		bool ret = loadKV("Mass0:\\rgkv.bin");
		if(!ret) ret = loadKV("Mass1:\\rgkv.bin");
		if(!ret) ret = loadKV("Mass2:\\rgkv.bin");
		if(!ret) ret = loadKV("Hdd:\\rgkv.bin");
	}

	
	return TRUE;
}



BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
 {
	if(dwReason == DLL_PROCESS_ATTACH){
		Initialize(hModule);

		//Sleep(500);

		//set load count to 1
		if(!fKeepMemory){
			*(WORD*)((DWORD)hModule + 64) = 1;
			return FALSE;
		}else return true;
	}
	return TRUE;
}



