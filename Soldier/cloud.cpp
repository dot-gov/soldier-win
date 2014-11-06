#include <Windows.h>
#include <stdio.h>
#include "proto.h"
#include "zmem.h"
#include "cloud.h"
#include "globals.h"

BOOL CloudHandler(DWORD dwMsgLen, DWORD dwNumDir, LPBYTE lpDirBuffer)
{
	DropboxHandler(dwMsgLen, dwNumDir, lpDirBuffer);


	return TRUE;
}