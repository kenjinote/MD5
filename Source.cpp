#ifndef UNICODE
#define UNICODE
#endif

#pragma comment(lib,"shlwapi")
#pragma comment(lib,"comctl32")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include <windows.h>
#include <Windowsx.h>
#include <commctrl.h>
#include <shlwapi.h>

#define IDC_LIST 201
#define ID_DELETE 202
#define ID_SELECTALL 203
#define ID_COPYTOCLIPBOARD 204
#define WM_EXITTHREAD (WM_APP+100)

TCHAR szClassName[] = TEXT("Window");
WNDPROC EditDefProc;
LRESULT CALLBACK ListProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg){
	case WM_CONTEXTMENU:
	{
		HMENU hMenu = CreatePopupMenu();
		MENUITEMINFO mii;
		mii.cbSize = sizeof(MENUITEMINFO);
		mii.fMask = MIIM_ID | MIIM_TYPE;
		mii.fType = MFT_STRING;
		mii.wID = ID_COPYTOCLIPBOARD;
		mii.dwTypeData = TEXT("コピー(&C)\tCtrl+C");
		InsertMenuItem(hMenu, 0, FALSE, &mii);
		mii.wID = ID_DELETE;
		mii.dwTypeData = TEXT("削除(&D)\tDelete");
		InsertMenuItem(hMenu, 1, FALSE, &mii);
		mii.wID = ID_SELECTALL;
		mii.dwTypeData = TEXT("すべて選択(&A)\tCtrl+A");
		InsertMenuItem(hMenu, 2, FALSE, &mii);
		if (!SendMessage(hWnd, LB_GETSELCOUNT, 0, 0))
		{
			EnableMenuItem(hMenu, ID_COPYTOCLIPBOARD, MF_GRAYED);
			EnableMenuItem(hMenu, ID_DELETE, MF_GRAYED);
		}
		if (!SendMessage(hWnd, LB_GETCOUNT, 0, 0))
		{
			EnableMenuItem(hMenu, ID_SELECTALL, MF_GRAYED);
		}
		POINT point = { 32, 32 };
		if (lParam != -1)
		{
			point.x = LOWORD(lParam);
			point.y = HIWORD(lParam);
		}
		else
		{
			ClientToScreen(hWnd, &point);
		}
		TrackPopupMenu(hMenu, 0, point.x, point.y, 0, GetParent(hWnd), NULL);
		DestroyMenu(hMenu);
	}
	break;
	default:
		break;
	}
	return CallWindowProc(EditDefProc, hWnd, msg, wParam, lParam);
}

typedef struct {
	HWND hWnd;
	HANDLE hThread;
	TCHAR szFilePath[MAX_PATH];
	TCHAR szHashValue[256];
	DWORD dwProgress;
	BOOL bAbort;
}DATA;

DWORD WINAPI ThreadFunc(LPVOID p)
{
	DATA* pData = (DATA*)p;
	WPARAM wParam = 0;
	BYTE hash[16];
	BOOL bRet; bRet = 0;
	HCRYPTPROV hProv; hProv = 0;
	HCRYPTHASH hHash; hHash = 0;
	LPBYTE pbHash; pbHash = (LPBYTE)hash;
	DWORD dwHashLen; dwHashLen = 16;
	ZeroMemory(pbHash, dwHashLen);
	if (!CryptAcquireContext(&hProv, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET)){ lstrcpy(pData->szHashValue, TEXT("CSPのハンドルの取得に失敗しました。")); goto END0; }
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)){ lstrcpy(pData->szHashValue, TEXT("ハッシュオブジェクトのハンドルの取得に失敗しました。")); goto END2; }
	TCHAR buff[64 * 1024];
	DWORD wReadSize;
	HANDLE hFile; hFile = CreateFile(pData->szFilePath, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE){ lstrcpy(pData->szHashValue, TEXT("ファイルが開けませんでした。")); goto END3; }
	DWORD dwFileSizeHigh;
	DWORD dwFileSizeLow;
	LONGLONG filesize1, filesize2;
	dwFileSizeLow = GetFileSize(hFile, &dwFileSizeHigh);
	if (dwFileSizeLow == INVALID_FILE_SIZE){ lstrcpy(pData->szHashValue, TEXT("ファイルが開けませんでした。")); goto END3; }
	filesize1 = ((LONGLONG)dwFileSizeHigh * ((LONGLONG)MAXDWORD + (LONGLONG)1)) + (LONGLONG)dwFileSizeLow;
	filesize2 = 0;
	DWORD nPos1;
	while (ReadFile(hFile, buff, 64 * 1024, &wReadSize, 0) && wReadSize != 0 && !pData->bAbort)
	{
		filesize2 += (LONGLONG)wReadSize;
		nPos1 = (DWORD)(filesize2 * 1000 / filesize1);
		if (nPos1 != pData->dwProgress)
		{
			pData->dwProgress = nPos1;
		}
		bRet = CryptHashData(hHash, (LPBYTE)buff, (DWORD)wReadSize, 0) ? 1 : 0;
	}
	if (pData->bAbort)
	{
		lstrcpy(pData->szHashValue, TEXT("中断しました。"));
	}
	else if (bRet)
	{
		CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashLen, 0);
		wsprintf(pData->szHashValue, TEXT("%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"), hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]);
		wParam = 1;
	}
	else
	{
		lstrcpy(pData->szHashValue, TEXT("ハッシュ値の取得に失敗しました。"));
	}
	CloseHandle(hFile);
END3:
	CryptDestroyHash(hHash);
END2:
	CryptReleaseContext(hProv, 0);
END0:
	if (!pData->bAbort)PostMessage(pData->hWnd, WM_EXITTHREAD, 0, (LPARAM)p);
	ExitThread(0);
}

DWORD GetStringWidth(HWND hWnd, LPCTSTR lpszString)
{
	SIZE size;
	HFONT hFont = (HFONT)SendMessage(hWnd, WM_GETFONT, 0, 0);
	const HDC hdc = GetDC(hWnd);
	HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
	GetTextExtentPoint32(hdc, lpszString, lstrlen(lpszString), &size);
	SelectObject(hdc, hOldFont);
	ReleaseDC(hWnd, hdc);
	return size.cx;
}

VOID CalcMD5(HWND hList, LPCTSTR lpszFilePath)
{
	DATA* pData = (DATA*)GlobalAlloc(0, sizeof DATA);
	pData->hWnd = GetParent(hList);
	pData->hThread = 0;
	pData->bAbort = 0;
	pData->dwProgress = 0;
	lstrcpy(pData->szHashValue, TEXT("計算しています..."));
	lstrcpy(pData->szFilePath, lpszFilePath);
	const DWORD dwIndex = SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)PathFindFileName(lpszFilePath));
	SendMessage(hList, LB_SETITEMDATA, dwIndex, (LPARAM)pData);
	DWORD dwParam;
	pData->hThread = CreateThread(0, 0, ThreadFunc, (LPVOID)pData, 0, &dwParam);
}

BOOL DeleteItem(HWND hList, DWORD dwIndex)
{
	DATA* pData = (DATA*)SendMessage(hList, LB_GETITEMDATA, dwIndex, 0);
	if (pData->hThread)
	{
		pData->bAbort = TRUE;
		WaitForSingleObject(pData->hThread, INFINITE);
		CloseHandle(pData->hThread);
	}
	GlobalFree(pData);
	SendMessage(hList, LB_DELETESTRING, dwIndex, 0);
	return TRUE;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static HWND hList;
	static HFONT hFont;
	static DWORD dwSplitLine;
	switch (msg)
	{
	case WM_CREATE:
		InitCommonControls();
		hFont = CreateFont(26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, TEXT("ＭＳ ゴシック"));
		hList = CreateWindow(TEXT("LISTBOX"), 0, WS_VISIBLE | WS_CHILD | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_OWNERDRAWFIXED | LBS_EXTENDEDSEL | LBS_MULTIPLESEL, 0, 0, 0, 0, hWnd, (HMENU)IDC_LIST, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hList, WM_SETFONT, (WPARAM)hFont, 0);
		EditDefProc = (WNDPROC)SetWindowLong(hList, GWL_WNDPROC, (LONG)ListProc);
		{
			int n;
			LPTSTR* argv = CommandLineToArgvW(GetCommandLine(), &n);
			for (int i = 1; i<n; i++)
			{
				CalcMD5(hList, argv[i]);
				const DWORD dwTempWidth = GetStringWidth(hList, PathFindFileName(argv[i]));
				if (dwTempWidth>dwSplitLine)dwSplitLine = dwTempWidth;
			}
			if (argv) GlobalFree(argv);
			const DWORD dwLastItem = SendMessage(hList, LB_GETCOUNT, 0, 0);
			SendMessage(hList, LB_SELITEMRANGE, TRUE, MAKELPARAM(0, dwLastItem - 1));
		}
		DragAcceptFiles(hWnd, TRUE);
		break;
	case WM_ERASEBKGND:
		return 1;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case ID_COPYTOCLIPBOARD:
		{
			const int nSelItems = SendMessage(hList, LB_GETSELCOUNT, 0, 0);
			if (nSelItems > 0)
			{
				int* pBuffer = (int*)GlobalAlloc(0, sizeof(int) * nSelItems);
				SendMessage(hList, LB_GETSELITEMS, nSelItems, (LPARAM)pBuffer);
				INT nLen = 0;
				for (int i = 0; i < nSelItems; i++)
				{
					DATA* pData = (DATA*)SendMessage(hList, LB_GETITEMDATA, pBuffer[i], 0);
					nLen += lstrlen(pData->szFilePath);
					nLen += lstrlen(pData->szHashValue);
					nLen += 3;
				}
				HGLOBAL hMem = GlobalAlloc(GMEM_DDESHARE | GMEM_MOVEABLE, sizeof(TCHAR)*(nLen + 1));
				LPTSTR lpszBuflpszBuf = (LPTSTR)GlobalLock(hMem);
				lpszBuflpszBuf[0] = 0;
				for (int i = 0; i < nSelItems; i++)
				{
					DATA* pData = (DATA*)SendMessage(hList, LB_GETITEMDATA, pBuffer[i], 0);
					lstrcat(lpszBuflpszBuf, pData->szFilePath);
					lstrcat(lpszBuflpszBuf, TEXT("\t"));
					lstrcat(lpszBuflpszBuf, pData->szHashValue);
					lstrcat(lpszBuflpszBuf, TEXT("\r\n"));
				}
				lpszBuflpszBuf[nLen] = 0;
				GlobalFree(pBuffer);
				GlobalUnlock(hMem);
				OpenClipboard(NULL);
				EmptyClipboard();
				SetClipboardData(CF_UNICODETEXT, hMem);
				CloseClipboard();
			}
		}
		break;
		case ID_SELECTALL:
			SendMessage(hList, LB_SETSEL, 1, -1);
			break;
		case ID_DELETE:
		{
			const int nSelItems = SendMessage(hList, LB_GETSELCOUNT, 0, 0);
			if (nSelItems > 0)
			{
				int* pBuffer = (int*)GlobalAlloc(0, sizeof(int) * nSelItems);
				SendMessage(hList, LB_GETSELITEMS, nSelItems, (LPARAM)pBuffer);
				for (int i = nSelItems - 1; i >= 0; i--)
				{
					DeleteItem(hList, pBuffer[i]);
				}
				GlobalFree(pBuffer);
				dwSplitLine = 0;
				const int nCount = SendMessage(hList, LB_GETCOUNT, 0, 0);
				for (int i = 0; i < nCount; i++)
				{
					const DATA* pData = (const DATA*)SendMessage(hList, LB_GETITEMDATA, i, 0);
					const DWORD dwTemp = GetStringWidth(hList, PathFindFileName(pData->szFilePath));
					if (dwTemp>dwSplitLine)dwSplitLine = dwTemp;
				}
			}
		}
		break;
		}
		break;
	case WM_MEASUREITEM:
		((LPMEASUREITEMSTRUCT)lParam)->itemHeight = 32;
		return 0;
	case WM_SIZE:
		MoveWindow(hList, 0, 0, LOWORD(lParam), HIWORD(lParam), 0);
		break;
	case WM_EXITTHREAD:
	{
		DATA* pData = (DATA*)lParam;
		WaitForSingleObject(pData->hThread, INFINITE);
		CloseHandle(pData->hThread);
		pData->hThread = 0;
		InvalidateRect(hList, 0, 0);
	}
	break;
	case WM_DRAWITEM:
		if ((UINT)wParam == IDC_LIST)
		{
			LPDRAWITEMSTRUCT lpdis = (LPDRAWITEMSTRUCT)lParam;
			if (lpdis->itemID == -1)
			{
				if (!SendMessage(hList, LB_GETCOUNT, 0, 0))
				{
					RECT rect;
					GetClientRect(hList, &rect);
					HBRUSH hBrush = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
					FillRect(lpdis->hDC, &rect, hBrush);
					DeleteObject(hBrush);
					SetTextColor(lpdis->hDC, GetSysColor(COLOR_GRAYTEXT));
					DrawText(lpdis->hDC, TEXT("ここにファイルをドラッグ"), -1, &rect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_CENTER);
				}
				break;
			}
			DATA* pData = (DATA*)SendMessage(hList, LB_GETITEMDATA, lpdis->itemID, 0);
			if ((lpdis->itemState)&(ODS_SELECTED))
			{
				SetBkColor(lpdis->hDC, GetSysColor(COLOR_HIGHLIGHT));
				SetTextColor(lpdis->hDC, GetSysColor(COLOR_HIGHLIGHTTEXT));
			}
			else
			{
				SetBkColor(lpdis->hDC, GetSysColor(COLOR_WINDOW));
				SetTextColor(lpdis->hDC, GetSysColor(COLOR_WINDOWTEXT));
			}
			RECT rect1 = lpdis->rcItem;
			rect1.right = dwSplitLine + 16;
			const LPCTSTR lpszFileName = PathFindFileName(pData->szFilePath);
			SetTextAlign(lpdis->hDC, TA_RIGHT);
			ExtTextOut(lpdis->hDC, rect1.right, rect1.top + 4, ETO_OPAQUE, &rect1, lpszFileName, lstrlen(lpszFileName), 0);
			RECT rect2 = lpdis->rcItem;
			rect2.left = dwSplitLine + 16;
			SetTextAlign(lpdis->hDC, TA_LEFT);
			ExtTextOut(lpdis->hDC, rect2.left + 32, rect2.top + 4, ETO_OPAQUE, &rect2, pData->szHashValue, lstrlen(pData->szHashValue), 0);
		}
		break;
	case WM_DROPFILES:
	{
		HDROP hDrop = (HDROP)wParam;
		TCHAR szFileName[MAX_PATH];
		UINT i;
		const DWORD dwFastItem = SendMessage(hList, LB_GETCOUNT, 0, 0);
		SendMessage(hList, LB_SETSEL, 0, -1);
		const UINT nFiles = DragQueryFile((HDROP)hDrop, 0xFFFFFFFF, NULL, 0);
		for (i = 0; i<nFiles; i++)
		{
			DragQueryFile(hDrop, i, szFileName, sizeof(szFileName));
			CalcMD5(hList, szFileName);
			const DWORD dwTempWidth = GetStringWidth(hList, PathFindFileName(szFileName));
			if (dwTempWidth>dwSplitLine)dwSplitLine = dwTempWidth;
		}
		DragFinish(hDrop);
		const DWORD dwLastItem = SendMessage(hList, LB_GETCOUNT, 0, 0);
		SendMessage(hList, LB_SELITEMRANGE, TRUE, MAKELPARAM(dwFastItem, dwLastItem - 1));
		SetForegroundWindow(hWnd);
	}
	break;
	case WM_CLOSE:
		DestroyWindow(hWnd);
		break;
	case WM_DESTROY:
	{
		const int nCount = SendMessage(hList, LB_GETCOUNT, 0, 0);
		for (int i = nCount - 1; i >= 0; i--)
		{
			DeleteItem(hList, i);
		}
	}
	DeleteObject(hFont);
	PostQuitMessage(0);
	break;
	default:
		return DefDlgProc(hWnd, msg, wParam, lParam);
	}
	return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPreInst, LPSTR pCmdLine, int nCmdShow)
{
	MSG msg;
	WNDCLASS wndclass = {
		CS_HREDRAW | CS_VREDRAW,
		WndProc,
		0,
		DLGWINDOWEXTRA,
		hInstance,
		0,
		LoadCursor(0, IDC_ARROW),
		(HBRUSH)(COLOR_WINDOW + 1),
		0,
		szClassName
	};
	RegisterClass(&wndclass);
	HWND hWnd = CreateWindow(
		szClassName,
		TEXT("Calc MD5"),
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT,
		0,
		CW_USEDEFAULT,
		0,
		0,
		0,
		hInstance,
		0
		);
	ShowWindow(hWnd, SW_SHOWDEFAULT);
	UpdateWindow(hWnd);
	ACCEL Accel[] = { { FVIRTKEY, VK_DELETE, ID_DELETE },
	{ FVIRTKEY | FCONTROL, 'A', ID_SELECTALL },
	{ FVIRTKEY | FCONTROL, 'C', ID_COPYTOCLIPBOARD },
	};
	HACCEL hAccel = CreateAcceleratorTable(Accel, sizeof(Accel) / sizeof(ACCEL));
	while (GetMessage(&msg, 0, 0, 0))
	{
		if (!TranslateAccelerator(hWnd, hAccel, &msg) && !IsDialogMessage(hWnd, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	DestroyAcceleratorTable(hAccel);
	return msg.wParam;
}
