.386
MODEL FLAT, STDCALL
JUMPS
LOCALS

UNICODE=0

INCLUDE	WIN.INC
INCLUDE C:\TASM\W32.INC
INCLUDE PE.INC

EXTRN	_wsprintfA		: PROC
EXTRN	RtlMoveMemory	: PROC

wsprintf	EQU		<_wsprintfA>

.DATA

szAppName			db "PE-nfo v1.0 by HaRdLoCk",0
szInformation		db "Information",0
szFileFilter		db "All Files (*.*)",0,"*.*",0,0
.DATA?
szFileName			db MAX_PATH	dup (?)
szFileTitle			db MAX_PATH dup (?)
szSectionFile		db MAX_PATH dup (?)
szNewSectionName	db 9 dup (?)
szOutput			db 50 dup (?)
szSection			db 13 dup (?)
.DATA
szFmatx				db "%08lX",0
szFmats				db "%s",0
szFmat				db "%lu",0
szFmatHex			db "EntryPoint@Raw Offset 0x%X patched! The replaced byte was 0x%X",0
szOpenError			db "FILE OPEN ERROR",0
szSaveError			db "FILE SAVE ERROR",0
szNoPeError			db "IMAGE_NT_SIGNATURE FAILED",0
szNoMZError			db "IMAGE_DOS_SIGNATURE FAILED",0
szExtension			db "%s.bin",0
szFileSize			db "FileSize: 0x%lX bytes",0
szLoad				db "Open",0
szOk				db "Ok",0
szCode				db "CODE",0
szData				db "DATA",0

szSectionName		db "Section Name",0
szVirtualSize		db "Virtual Size",0
szVirtualOffset		db "Virtual Offset",0
szSizeOfRawData		db "Raw Size",0
szPointerToRawData	db "Raw Offset",0
szCharacteristics	db "Characteristics",0
szSectionDump		db "Save Section",0
szSectionEdit		db "Edit Section",0
szSectionReplace	db "Replace Section",0
szSectionAdd		db "Add Section",0
szSectionKill		db "Kill Section",0
szKillUseless		db "Save Space",0
szOptionalHeader	db "IMAGE_OPTIONAL_HEADER",0
szImageFileHeader	db "IMAGE_FILE_HEADER",0
szImageDataDiretory	db "IMAGE_DATA_DIRECTORY's",0
szImports			db "LIST IMPORTS",0
szUPX				db "FIX UPX",0
szFixVirtualRaw		db "FIX RAW OFFSETS",0

StatusArray			dd ?, -1

stOpenFile		OPENFILENAME			<>
stColumn		LV_COLUMN				<>
stList			LV_ITEM 				<>
stPoint			POINT					<>
stRect			RECT					<>

.DATA?

hApp		dd ?
hFile		dd ?
hMenu		dd ?
hDump		dd ?
hFileMap	dd ?
pFileMap	dd ?
bSaveFile	dd ?
bFileOpen	dd ?
hSection	dd ?
hHeader		dd ?
hTemp		dd ?
hMem		dd ?
bMenu		dd ?
bUseless	dd ?
hOptions	dd ?

ptrSection			dd ?
pMem				dd ?
ptrCmdLine			dd ?
ptrPeHeader			dd ?
ptrNewSection		dd ?
dwBuffer			dd ?
dwSectionCount		dd ?
dwFileSize			dd ?
dwSection			dd ?
dwImageBase			dd ?
dwRawOffset			dd ?
dwRawSize			dd ?
dwVirtualSize		dd ?
dwVirtualOffset		dd ?
dwCharacteristics	dd ?
dwSectionEnd		dd ?
dwNewFileSize		dd ?
dwSectionAlign		dd ?
dwFileAlign			dd ?
dwReturn			dd ?

.CODE

Start:

	call	GetModuleHandleA, NULL
	mov		hApp, eax
	call	InitCommonControls
	call	GetModuleFileNameA, NULL, offset szOutput, MAX_PATH
	call	GetCommandLineA
	.IF		byte ptr [eax]=='"'
		inc		eax
		.WHILE	!byte ptr [eax]=='"'
			inc		eax
		.ENDW
		add		eax, 2
		.IF		!byte ptr [eax]==0
			.IF byte ptr [eax]=='"'
				inc 	eax
				mov		ptrCmdLine, eax
				push	eax
				call	lstrlen, eax
				pop		edx
				add		edx, eax
				xor		al, al
				mov 	byte ptr [edx-1], al
			.ELSE
				mov		ptrCmdLine, eax
			.ENDIF
		.ENDIF
	.ELSE
		lea		edx, szOutput
		.WHILE	byte ptr [edx]>0
			inc		eax
			inc		edx
		.ENDW
		.IF		byte ptr [eax]==20h
			inc		eax
			mov		ptrCmdLine, eax
		.ENDIF
	.ENDIF
	call	DialogBoxParamA, hApp, IDD_DIALOG, NULL, offset DialogProc, NULL
	call	ExitProcess, NULL

DialogProc	PROC, hDlg:DWORD, uMsg:DWORD, wPara:DWORD, lPara:DWORD

	.IF		uMsg==WM_DESTROY || uMsg==WM_CLOSE
		call	EndDialog, hDlg, NULL
	.ELSEIF	uMsg==WM_NOTIFY
		mov		eax, lPara
		.IF		(NMHDR PTR [eax]).code==NM_RCLICK
			.IF		(NMHDR PTR [eax]).idFrom==IDC_LIST
				call	SendDlgItemMessage, hDlg, IDC_LIST, 1032h, NULL, NULL
				.IF		eax==TRUE
					call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_GETNEXTITEM, -1, LVNI_SELECTED
					push	eax
					call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_GETITEMCOUNT, NULL, NULL
					xchg	eax, edx
					pop		eax
					inc		eax
					.IF		eax==edx && bMenu==FALSE && bUseless==TRUE
						call	AppendMenuA, hMenu, MF_STRING, KILL_USELESS, offset szKillUseless
						mov		bMenu, TRUE
					.ELSEIF	!eax==edx && bMenu==TRUE || eax==edx && bMenu==TRUE && bUseless==FALSE
						call	RemoveMenu, hMenu, KILL_USELESS, MF_BYCOMMAND
						mov		bMenu, FALSE
					.ENDIF
					call	GetCursorPos, offset stPoint
					call 	TrackPopupMenu, hMenu, TPM_RIGHTBUTTON, stPoint.pt_x, stPoint.pt_y, NULL, hDlg, NULL
				.ENDIF
			.ENDIF
		.ELSEIF	(NMHDR PTR [eax]).code==NM_DBLCLK
			.IF		(NMHDR PTR [eax]).idFrom==IDC_LIST
				call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_GETNEXTITEM, -1, LVNI_SELECTED
				.IF		!eax==-1
					mov		dwSection, eax
					call	EditSection, hDlg
				.ENDIF
			.ENDIF
		.ENDIF
	.ELSEIF	uMsg==WM_INITDIALOG
		call	SetWindowText, hDlg, offset szAppName
		call	GetClientRect, hDlg, offset stRect
		mov		eax, stRect.rc_right
		mov		ecx, 2
		cdq
		idiv	ecx
		mov		[StatusArray], eax
		call	CreateStatusWindow, WS_VISIBLE+WS_CHILD, NULL, hDlg, IDS_STATUS
		call	SendDlgItemMessage, hDlg, IDS_STATUS, SB_SETPARTS, 2, offset StatusArray
		mov 	stColumn.imask, LVCF_FMT+LVCF_TEXT+LVCF_WIDTH+LVCF_SUBITEM
		mov 	stColumn.fmt, LVCFMT_LEFT
		call	GetDlgItem, hDlg, IDC_LIST
		call	GetClientRect, eax, offset stRect
		mov		eax, stRect.rc_right
		mov		ecx, 6
		cdq
		idiv	ecx
		mov 	stColumn.lx, eax
		mov 	stColumn.iSubItem, 0
		call	SetNewColumn, hDlg, offset szSectionName, 0
		call	SetNewColumn, hDlg, offset szVirtualSize, 1
		call	SetNewColumn, hDlg, offset szVirtualOffset, 2
		call	SetNewColumn, hDlg, offset szSizeOfRawData, 3
		call	SetNewColumn, hDlg, offset szPointerToRawData, 4
		call	SetNewColumn, hDlg, offset szCharacteristics, 5
		call	CreatePopupMenu
		mov		hMenu, eax
		call	AppendMenuA, hMenu, MF_STRING, SECTION_DUMP, offset szSectionDump
		call	AppendMenuA, hMenu, MF_STRING, SECTION_EDIT, offset szSectionEdit
		call	AppendMenuA, hMenu, MF_STRING, SECTION_REPLACE, offset szSectionReplace
		call	AppendMenuA, hMenu, MF_STRING, SECTION_ADD, offset szSectionAdd
		;call	AppendMenuA, hMenu, MF_STRING, SECTION_KILL, offset szSectionKill
		call	CreatePopupMenu
		mov		hHeader, eax
		call	AppendMenuA, hHeader, MF_STRING, FILE_HEADER, offset szImageFileHeader
		call	AppendMenuA, hHeader, MF_STRING, OPTIONAL_HEADER, offset szOptionalHeader
		call	AppendMenuA, hHeader, MF_STRING, DATA_DIRECTORY, offset szImageDataDiretory
		call	AppendMenuA, hHeader, MF_STRING, IMPORTS, offset szImports
		;call	AppendMenuA, hHeader, MF_SEPARATOR, NULL, NULL
		;call	AppendMenuA, hHeader, MF_STRING, FIX_UPX, offset szUPX
		call	EnableMenuItems, MF_GRAYED
		call	CreatePopupMenu
		mov		hOptions, eax
		call	AppendMenuA, hOptions, MF_STRING, 1111, offset szFixVirtualRaw
		call	AppendMenuA, hOptions, MF_STRING, 2222, offset szUPX

		mov		stOpenFile.on_lStructSize, size OPENFILENAME
		push	hDlg
		pop		stOpenFile.on_hwndOwner
		mov		stOpenFile.on_lpstrFileTitle, offset szFileTitle
		mov		stOpenFile.on_nMaxFile, MAX_PATH
	    mov		stOpenFile.on_Flags, OFN_EXPLORER+OFN_FILEMUSTEXIST+OFN_OVERWRITEPROMPT
	    mov		stOpenFile.on_lpstrInitialDir, NULL
		mov		stOpenFile.on_lpstrFilter, offset szFileFilter
	    call	LoadIcon, hApp, IDI_ICON
	    call	SendMessage, hDlg, WM_SETICON, ICON_SMALL, eax
	    .IF		byte ptr [ptrCmdLine]>0
	    	call	lstrcpy, offset szFileName, ptrCmdLine
	    	call	LoadFileAndSetList, hDlg
	    .ENDIF
	.ELSEIF	uMsg==WM_COMMAND
		.IF	wPara==IDC_OK
			mov		stOpenFile.on_lpstrFile, offset szFileName
		    call	GetOpenFileName, offset stOpenFile
		    .IF		!eax==0
		    	call	LoadFileAndSetList, hDlg
		    .ENDIF
		.ELSEIF	wPara==IDCANCEL
			call	SendMessage, hDlg, WM_CLOSE, NULL, NULL
		.ELSEIF	wPara==IDC_HEADER
			call	GetDlgItem, hDlg, IDC_HEADER
			call	GetWindowRect, eax, offset stRect
			call 	TrackPopupMenu, hHeader, TPM_RIGHTBUTTON, stRect.rc_left, stRect.rc_bottom, NULL, hDlg, NULL
		.ELSEIF	wPara==4
			call	GetDlgItem, hDlg, 4
			call	GetWindowRect, eax, offset stRect
			call 	TrackPopupMenu, hOptions, TPM_RIGHTBUTTON, stRect.rc_left, stRect.rc_bottom, NULL, hDlg, NULL	
		.ELSEIF wPara==1111	
			;int 3
			call	FixRawOffsets
			call	LoadFileAndSetList, hDlg
		.ELSEIF	wPara==OPTIONAL_HEADER
			call	DialogBoxParamA, hApp, IDD_OPTIONAL_HEADER, hDlg, offset OptionalHeaderProc, NULL
			.IF		bSaveFile==TRUE
				call	LoadFileAndSetList, hDlg
				mov		bSaveFile, FALSE
			.ENDIF
		.ELSEIF	wPara==FILE_HEADER
			call	DialogBoxParamA, hApp, IDD_FILE_HEADER, hDlg, offset FileHeaderProc, NULL
			.IF		bSaveFile==TRUE
				call	LoadFileAndSetList, hDlg
				mov		bSaveFile, FALSE
			.ENDIF
		.ELSEIF	wPara==DATA_DIRECTORY
			call	DialogBoxParamA, hApp, IDD_DATA_DIRECTORY, hDlg, offset DataDirectoryProc, NULL
			.IF		bSaveFile==TRUE
				call	LoadFileAndSetList, hDlg
				mov		bSaveFile, FALSE
			.ENDIF
		.ELSEIF	wPara==IMPORTS
			call	DialogBoxParamA, hApp, IDD_IMPORTS, hDlg, offset ImportsProc, NULL
			.IF		bSaveFile==TRUE
				call	LoadFileAndSetList, hDlg
				mov		bSaveFile, FALSE
			.ENDIF
		.ELSEIF	wPara==FIX_UPX
			call	KillUselessBytes
			call	MapFileAndSetPointer
			mov		eax, ptrSection			
			call	lstrcpy, eax, offset szCode
			mov		eax, ptrSection
			add		eax, size IMAGE_SECTION_HEADER
			call	lstrcpy, eax, offset szData
			call	CalcPESum, pFileMap, dwFileSize	
			lea		edx, ptrPeHeader	
			mov		(IMAGE_NT_HEADERS PTR [edx]).OptionalHeader.CheckSum, eax			
			call	UnMapAndCloseHandles
			call	LoadFileAndSetList, hDlg			
		.ELSEIF	wPara==SECTION_DUMP
		    call	MapFileAndSetPointer
			call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_GETNEXTITEM, -1, LVNI_SELECTED
			imul	eax, size IMAGE_SECTION_HEADER
			add		ptrSection, eax
			call	lstrcpyn, offset szSection, ptrSection, 9
			call	wsprintf, offset szOutput, offset szExtension, offset szSection
			add		esp, 12
			call	lstrcpy, offset szSection, offset szOutput
			mov		stOpenFile.on_lpstrFile, offset szSection
			call	GetSaveFileName, offset stOpenFile
			.IF		!eax==0
			    call	CreateFile, offset szSection, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ+FILE_SHARE_WRITE, \
				   		NULL, CREATE_ALWAYS, NULL, NULL
				mov		hDump, eax
				mov		eax, ptrSection
				mov		ecx, pFileMap
				add		ecx, (IMAGE_SECTION_HEADER PTR [eax]).PointerToRawData
				call	WriteFile, hDump, ecx, (IMAGE_SECTION_HEADER PTR [eax]).SizeOfRawData, offset dwBuffer, NULL
				.IF		eax==0
					call	MessageBoxA, hDlg, offset szSaveError, offset szInformation, MB_OK
				.ENDIF
				call	CloseHandle, hDump
			.ENDIF
			call	UnMapAndCloseHandles
		.ELSEIF	wPara==SECTION_EDIT
			call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_GETNEXTITEM, -1, LVNI_SELECTED
			.IF		!eax==-1
				mov		dwSection, eax
				call	EditSection, hDlg
			.ENDIF
		.ELSEIF	wPara==SECTION_REPLACE
			mov		stOpenFile.on_lpstrFile, offset szSectionFile
			call	GetOpenFileName, offset stOpenFile
			.IF		!eax==0
				call	MapFileAndSetPointer
				call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_GETNEXTITEM, -1, LVNI_SELECTED
				imul	eax, size IMAGE_SECTION_HEADER
				add		ptrSection, eax
				mov		eax, ptrSection
				mov		edx, (IMAGE_SECTION_HEADER PTR [eax]).SizeOfRawData
				mov		dwRawSize, edx
				mov		edx, (IMAGE_SECTION_HEADER PTR [eax]).PointerToRawData
				mov		dwRawOffset, edx
				call	UnMapAndCloseHandles
				call	CreateFile, offset szSectionFile, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ+FILE_SHARE_WRITE, \
			   			NULL, OPEN_EXISTING, NULL, NULL
				mov		hSection, eax
			   	.IF		!eax==0
					call	GetFileSize, eax, NULL
					call	CreateFileMappingA, hSection, NULL, PAGE_READWRITE, NULL, eax, NULL
					mov		hFileMap, eax
					call	MapViewOfFile, eax, FILE_MAP_READ, NULL, NULL, NULL
					mov		pFileMap, eax
		    		call	CreateFile, offset szFileName, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ+FILE_SHARE_WRITE, \
			   				NULL, OPEN_EXISTING, NULL, NULL
			   		mov		hFile, eax
			   		call	SetFilePointer, eax, dwRawOffset, NULL, FILE_BEGIN
			   		call	WriteFile, hFile, pFileMap, dwRawSize, offset dwBuffer, NULL
			   		call	CloseHandle, hFile
			   		call	UnmapViewOfFile, pFileMap
					call	CloseHandle, hFileMap
			   	.ELSE
			   		call	MessageBoxA, hDlg, offset szOpenError, NULL, MB_OK
			   	.ENDIF
			   	call	CloseHandle, hSection
			.ENDIF
		.ELSEIF	wPara==SECTION_ADD
			call	DialogBoxParamA, hApp, IDD_NEW_SECTION, hDlg, offset DialogNewSectionProc, NULL
			.IF		bSaveFile==TRUE
				call	LoadFileAndSetList, hDlg
				mov		bSaveFile, FALSE
			.ENDIF
		.ELSEIF	wPara==SECTION_KILL
			call	MapFileAndSetPointer
			dec		(IMAGE_NT_HEADERS PTR [eax]).FileHeader.NumberOfSections
			call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_GETNEXTITEM, -1, LVNI_SELECTED
			imul	eax, size IMAGE_SECTION_HEADER
			add		eax, ptrSection
			mov		edx, (IMAGE_SECTION_HEADER PTR [eax]).SizeOfRawData
			mov		dwRawSize, edx
			mov		edx, (IMAGE_SECTION_HEADER PTR [eax]).PointerToRawData
			mov		dwRawOffset, edx
			add		edx, dwRawSize
			mov		dwSectionEnd, edx
			sub		eax, dwSectionEnd
			call	MoveMemory, dwRawOffset, dwSectionEnd, eax
			mov		eax, dwFileSize
			sub		eax, dwSectionEnd
			mov		dwNewFileSize, eax
			call	GlobalAlloc, GMEM_FIXED+GMEM_ZEROINIT, dwNewFileSize
			mov		hMem, eax
			call	GlobalLock, eax
			mov		pMem, eax
			call	MoveMemory, eax, pFileMap, dwRawOffset
			mov		eax, pMem
			add		eax, dwRawOffset
			mov		ecx, pFileMap
			add		ecx, dwRawOffset
			add		ecx, dwRawSize
			mov		edx, dwFileSize
			sub		edx, ecx
			call	MoveMemory, eax, ecx, edx
			call	UnMapAndCloseHandles
			call	CreateFile, offset szAppName, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ+FILE_SHARE_WRITE, \
					NULL, CREATE_ALWAYS, NULL, NULL
			mov		hTemp, eax
			call	WriteFile, hTemp, pMem, dwNewFileSize, offset dwBuffer, NULL
			call	CloseHandle, hTemp
			call	GlobalUnlock, pMem
			call	GlobalFree, hMem
		.ELSEIF	wPara==KILL_USELESS
			call	KillUselessBytes
			call	LoadFileAndSetList, hDlg			
		.ENDIF
	.ENDIF
	xor		eax, eax
	ret

DialogProc ENDP

RVA2Offset	PROC	dwRVA:DWORD
	mov		edx, ptrSection
	mov		eax, dwRVA
	mov		ecx, dwSectionCount
	dec		ecx
	imul	ecx, size IMAGE_SECTION_HEADER
	add		edx, ecx
	.WHILE	(IMAGE_SECTION_HEADER PTR [edx]).SVirtualAddress>eax
		sub		edx, size IMAGE_SECTION_HEADER
	.ENDW
	sub		eax, (IMAGE_SECTION_HEADER PTR [edx]).SVirtualAddress
	add		eax, (IMAGE_SECTION_HEADER PTR [edx]).PointerToRawData
	ret
RVA2Offset	ENDP

KillUselessBytes	PROC
	call	MapFileAndSetPointer
	mov		eax, ptrPeHeader
	movsx	eax, (IMAGE_NT_HEADERS PTR [eax]).FileHeader.NumberOfSections
	and		eax, 0FFFFh
	dec		eax
	imul	eax, size IMAGE_SECTION_HEADER
	add		eax, ptrSection
	mov		edx, (IMAGE_SECTION_HEADER PTR [eax]).SizeOfRawData
	mov		ecx, (IMAGE_SECTION_HEADER PTR [eax]).PointerToRawData
	add		ecx, edx
	call	SetFilePointer, hFile, ecx, NULL, FILE_CURRENT	
	call	UnMapViewOfFile, pFileMap
	call	CloseHandle, hFileMap
	call	SetEndOfFile, hFile
	call	CloseHandle, hFile
	ret
KillUselessBytes	ENDP

FixRawOffsets	PROC
	call	MapFileAndSetPointer
	mov		eax, ptrSection
	.WHILE	dwSectionCount>0
		mov		edx, (IMAGE_SECTION_HEADER PTR [eax]).SVirtualSize
		mov 	(IMAGE_SECTION_HEADER PTR [eax]).SizeOfRawData, edx
		mov		edx, (IMAGE_SECTION_HEADER PTR [eax]).SVirtualAddress
		mov 	(IMAGE_SECTION_HEADER PTR [eax]).PointerToRawData, edx
		add		eax, size IMAGE_SECTION_HEADER
		dec		dwSectionCount
	.ENDW
	call	UnMapAndCloseHandles
	ret
FixRawOffsets	ENDP

LoadFileAndSetList	PROC	hDlg:DWORD
	call	ClearStatusBar, hDlg
	call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_DELETEALLITEMS, NULL, NULL
	call	CreateFile, offset szFileName, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ+FILE_SHARE_WRITE, \
			NULL, OPEN_EXISTING, NULL, NULL
	.IF		!eax==INVALID_HANDLE_VALUE
		mov		hFile, eax
		call	GetFileSize, hFile, NULL
		mov		dwFileSize, eax
		call	CreateFileMappingA, hFile, NULL, PAGE_READONLY, NULL, eax, NULL
		mov		hFileMap, eax
		call	MapViewOfFile, eax, FILE_MAP_READ, NULL, NULL, NULL
		mov		pFileMap, eax
		.IF		(IMAGE_DOS_HEADER PTR [eax]).e_magic==IMAGE_DOS_SIGNATURE
			add		eax, (IMAGE_DOS_HEADER PTR [eax]).e_lfanew
			mov		edx, eax
			sub		edx, pFileMap
			.IF		edx<dwFileSize && (IMAGE_NT_HEADERS PTR [eax]).Signature==IMAGE_NT_SIGNATURE
				xor		ecx, ecx
				mov		cx, (IMAGE_NT_HEADERS PTR [eax]).FileHeader.NumberOfSections
				mov		dwSectionCount, ecx
				mov		ecx, (IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.ImageBase
				mov		dwImageBase, ecx
				add		eax, size IMAGE_NT_HEADERS
	   			mov		ptrSection, eax
				call	SendDlgItemMessage, hDlg, IDS_STATUS, SB_SETTEXT, 0, offset szFileName
				call	wsprintf, offset szOutput, offset szFileSize, dwFileSize
				add		esp, 12
				call	SendDlgItemMessage, hDlg, IDS_STATUS, SB_SETTEXT, 1, offset szOutput
	   			mov 	stList.lv_iItem, -1
				mov 	stList.lv_imask, LVIF_TEXT
	   			.WHILE	dwSectionCount>0
					inc		stList.lv_iItem
					mov 	stList.lv_iSubItem, 0
					call	lstrcpyn, offset szSection, ptrSection, 9
					lea		eax, szSection
					mov		stList.lv_pszText, eax
					call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_INSERTITEM, 0, offset stList
					mov 	stList.lv_pszText, offset szOutput
					mov		eax, ptrSection
					call	ValueToListView, hDlg, (IMAGE_SECTION_HEADER PTR [eax]).SVirtualSize
					call	ValueToListView, hDlg, (IMAGE_SECTION_HEADER PTR [eax]).SVirtualAddress
					call	ValueToListView, hDlg, (IMAGE_SECTION_HEADER PTR [eax]).SizeOfRawData
					call	ValueToListView, hDlg, (IMAGE_SECTION_HEADER PTR [eax]).PointerToRawData
					call	ValueToListView, hDlg, (IMAGE_SECTION_HEADER PTR [eax]).Characteristics
					add		ptrSection, size IMAGE_SECTION_HEADER
					.IF		dwSectionCount==1
						mov		ecx, (IMAGE_SECTION_HEADER PTR [eax]).SizeOfRawData
						mov		edx, (IMAGE_SECTION_HEADER PTR [eax]).PointerToRawData
						add		ecx, edx
						.IF		ecx<dwFileSize
							mov		bUseless, TRUE
						.ELSE
							mov		bUseless, FALSE
						.ENDIF
					.ENDIF
					dec		dwSectionCount
				.ENDW
				call	EnableMenuItems, MF_ENABLED
			.ELSE
				call	ErrorMessage, hDlg, offset szNoPeError
			.ENDIF
		.ELSE
			call	ErrorMessage, hDlg, offset szNoMZError
		.ENDIF
		call	UnMapAndCloseHandles
	.ELSE
		call	ErrorMessage, hDlg, offset szOpenError
	.ENDIF
	ret

LoadFileAndSetList	ENDP

ErrorMessage	PROC	hDlg:DWORD, szError:DWORD
	call	MessageBoxA, hDlg, szError, NULL, MB_OK
	call	ClearStatusBar, hDlg
	call	EnableMenuItems, MF_GRAYED	
	ret
ErrorMessage	ENDP	

AlignIt	PROC	dwAlignment:DWORD, dwValue:DWORD
	mov		eax, dwValue
	mov		ecx, dwAlignment
	add		eax, ecx
	xor		edx, edx
	idiv	ecx
	.IF	edx==0 && dwValue>0
		dec	eax
	.ENDIF
	imul	eax, dwAlignment
	ret
AlignIt	ENDP

ValueToListView	PROC	hDlg:DWORD, dwValue:DWORD
	pushad
	call	ConvertHexToString, dwValue
	inc 	stList.lv_iSubItem
	call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_SETITEM, 0, offset stList
	popad
	ret
ValueToListView	ENDP

SetNewColumn	PROC	hDlg:DWORD, dwTextOffset:DWORD, dwCount:DWORD
	inc		stColumn.iSubItem
	push	dwTextOffset
	pop 	stColumn.pszText
	call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_INSERTCOLUMN, dwCount, offset stColumn
	ret
SetNewColumn	ENDP

ClearStatusBar	PROC	hDlg:DWORD
	call	SendDlgItemMessage, hDlg, IDS_STATUS, SB_SETTEXT, NULL, NULL
	call	SendDlgItemMessage, hDlg, IDS_STATUS, SB_SETTEXT, 1, NULL
	ret
ClearStatusBar	ENDP

EditSection		PROC	hDlg:DWORD
	call	DialogBoxParamA, hApp, IDD_SECTION, hDlg, offset DialogSectionProc, NULL
	.IF		bSaveFile==TRUE
		call	LoadFileAndSetList, hDlg
		mov		bSaveFile, FALSE
	.ENDIF
	ret
EditSection		ENDP

DialogSectionProc	PROC hDlg:DWORD, uMsg:DWORD, wPara:DWORD, lPara:DWORD

	.IF		uMsg==WM_DESTROY || uMsg==WM_CLOSE
		call	UnMapAndCloseHandles
		call	EndDialog, hDlg, NULL
	.ELSEIF	uMsg==WM_INITDIALOG
		call	SetEditBoxLimit, hDlg, IDC_CHARACTERISTICS, IDC_SECTION_NAME
		call	MapFileAndSetPointer
		mov		eax, dwSection
		imul	eax, size IMAGE_SECTION_HEADER
		add		ptrSection, eax
		call	lstrcpyn, offset szSection, ptrSection, 9
		call	SendDlgItemMessage, hDlg, IDC_SECTION_NAME, WM_SETTEXT, NULL, offset szSection
		mov		eax, ptrSection
		call	ConvertToHexAndSetEdit, hDlg, IDC_VIRTUAL_SIZE, (IMAGE_SECTION_HEADER PTR [eax]).SVirtualSize
		call	ConvertToHexAndSetEdit, hDlg, IDC_VIRTUAL_OFFSET, (IMAGE_SECTION_HEADER PTR [eax]).SVirtualAddress
		call	ConvertToHexAndSetEdit, hDlg, IDC_RAW_SIZE, (IMAGE_SECTION_HEADER PTR [eax]).SizeOfRawData
		call	ConvertToHexAndSetEdit, hDlg, IDC_RAW_OFFSET, (IMAGE_SECTION_HEADER PTR [eax]).PointerToRawData
		call	ConvertToHexAndSetEdit, hDlg, IDC_CHARACTERISTICS, (IMAGE_SECTION_HEADER PTR [eax]).Characteristics
	.ELSEIF	uMsg==WM_COMMAND
		.IF		wPara==IDCANCEL
			call	SendMessage, hDlg, WM_CLOSE, NULL, NULL
			mov		bSaveFile, FALSE
		.ELSEIF	wPara==IDC_OK
			call	SendDlgItemMessageA, hDlg, IDC_SECTION_NAME, WM_GETTEXT, 9, offset szOutput
			call	lstrcpy, ptrSection, offset szOutput
			call	GetEditBoxValue, hDlg, IDC_CHARACTERISTICS
			mov		(IMAGE_SECTION_HEADER PTR [eax]).Characteristics, edx
			call	GetEditBoxValue, hDlg, IDC_VIRTUAL_SIZE
			mov		(IMAGE_SECTION_HEADER PTR [eax]).SVirtualSize, edx
			call	GetEditBoxValue, hDlg, IDC_VIRTUAL_OFFSET
			mov		(IMAGE_SECTION_HEADER PTR [eax]).SVirtualAddress, edx
			call	GetEditBoxValue, hDlg, IDC_RAW_SIZE
			mov		(IMAGE_SECTION_HEADER PTR [eax]).SizeOfRawData, edx
			call	GetEditBoxValue, hDlg, IDC_RAW_OFFSET
			mov		(IMAGE_SECTION_HEADER PTR [eax]).PointerToRawData, edx
			call	SendMessage, hDlg, WM_CLOSE, NULL, NULL
			mov		bSaveFile, TRUE
		.ENDIF
	.ENDIF
	xor		eax, eax
	ret

DialogSectionProc	ENDP

ConvertStringToHex 	PROC ptrString:DWORD
    mov     esi, ptrString
    call	CharUpper, esi
    xor     edx,edx
@L1:
    xor     eax,eax
    lodsb
    test    eax,eax
    jz      @L3
    sub     al,30h
    cmp     al,9
    jle     @L2
    sub     al,7
@L2:
    shl     edx,4
    add     edx,eax
    jmp     @L1
@L3:
	mov		eax, ptrSection
	mov		ecx, ptrPeHeader
	ret
ConvertStringToHex	ENDP

MapFileAndSetPointer	PROC
	call	CreateFile, offset szFileName, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ+FILE_SHARE_WRITE, \
	   		NULL, OPEN_EXISTING, NULL, NULL
	mov		hFile, eax
	call	GetFileSize, hFile, NULL
	mov		dwFileSize, eax
	call	CreateFileMappingA, hFile, NULL, PAGE_READWRITE, NULL, eax, NULL
	mov		hFileMap, eax
	call	MapViewOfFile, eax, FILE_MAP_WRITE, NULL, NULL, NULL
	mov		pFileMap, eax
	add		eax, (IMAGE_DOS_HEADER PTR [eax]).e_lfanew
	mov		ptrPeHeader, eax
	xor		ecx, ecx
	mov		cx, (IMAGE_NT_HEADERS PTR [eax]).FileHeader.NumberOfSections
	mov		dwSectionCount, ecx	
	mov		edx, eax
	add		edx, size IMAGE_NT_HEADERS
	mov		ptrSection, edx
	ret
MapFileAndSetPointer	ENDP

MapFile	PROC	ptrFilename:DWORD
	call	CreateFile, ptrFileName, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ+FILE_SHARE_WRITE, \
	   		NULL, OPEN_EXISTING, NULL, NULL
	mov		hFile, eax
	call	GetFileSize, hFile, NULL
	mov		dwFileSize, eax
	call	CreateFileMappingA, hFile, NULL, PAGE_READWRITE, NULL, eax, NULL
	mov		hFileMap, eax
	call	MapViewOfFile, eax, FILE_MAP_READ, NULL, NULL, NULL
	mov		pFileMap, eax
	ret
MapFile	ENDP

UnMapAndCloseHandles	PROC
	call	UnmapViewOfFile, pFileMap
	call	CloseHandle, hFileMap
	call	CloseHandle, hFile
	ret
UnMapAndCloseHandles	ENDP

ConvertToHexAndSetEdit	PROC	hDlg:DWORD, dwControlID:DWORD, dwValue:DWORD
	pushad
	call	ConvertHexToString, dwValue
	call	SendDlgItemMessage, hDlg, dwControlID, WM_SETTEXT, NULL, offset szOutput
	popad
	ret
ConvertToHexAndSetEdit	ENDP

DialogNewSectionProc	PROC hDlg:DWORD, uMsg:DWORD, wPara:DWORD, lPara:DWORD

	.IF		uMsg==WM_DESTROY || uMsg==WM_CLOSE
		call	EndDialog, hDlg, NULL
	.ELSEIF	uMsg==WM_INITDIALOG
		call	SetEditBoxLimit, hDlg, IDC_CHARACTERISTICS, IDC_SECTION_NAME
	    call	CheckDlgButton, hDlg, IDC_NEW_SECTION, BST_CHECKED
	    call	MapFileAndSetPointer
		push	(IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.SectionAlignment
		pop		dwSectionAlign
		push	(IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.FileAlignment
		pop		dwFileAlign
		xor		edx, edx
		mov		dx, (IMAGE_NT_HEADERS PTR [eax]).FileHeader.NumberOfSections
		mov		dwSectionCount, edx
		call	ConvertToHexAndSetEdit, hDlg, IDC_VIRTUAL_OFFSET, (IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.SizeOfImage
		mov		edx, dwSectionCount
		sub		edx, 1
		imul	edx, size IMAGE_SECTION_HEADER
		add		edx, ptrSection
		xchg	eax, edx
		mov		edx, (IMAGE_SECTION_HEADER PTR [eax]).SizeOfRawData
		mov		ecx, (IMAGE_SECTION_HEADER PTR [eax]).PointerToRawData
		add		ecx, edx
		mov		dwRawOffset, ecx
		call	ConvertToHexAndSetEdit, hDlg, IDC_RAW_OFFSET, ecx
		call	ConvertToHexAndSetEdit, hDlg, IDC_CHARACTERISTICS, 0E0000020h
		call	UnMapAndCloseHandles
		call	SetDlgItemText, hDlg, IDC_OK, offset szOk
	    call	GetDlgItem, hDlg, IDC_SECTION_NAME
	    mov		hSection, eax
	    call	SetFocus, hSection
	.ELSEIF	uMsg==WM_COMMAND
		.IF		wPara==IDCANCEL
			call	SendMessage, hDlg, WM_CLOSE, NULL, NULL
		.ELSEIF	wPara==IDC_LOAD_SECTION && bFileOpen==FALSE
		    call	SetDlgItemText, hDlg, IDC_OK, offset szLoad
		.ELSEIF	wPara==IDC_NEW_SECTION
		    call	SetDlgItemText, hDlg, IDC_OK, offset szOk
		.ELSEIF	wPara==IDC_OK
			call	IsDlgButtonChecked, hDlg, IDC_LOAD_SECTION
			.IF		eax==1 && bFileOpen==FALSE
				mov		stOpenFile.on_lpstrFile, offset szSectionFile
				call	GetOpenFileName, offset stOpenFile
				.IF		!eax==0
					call	GetDlgItem, hDlg, IDC_NEW_SECTION
					call	EnableWindow, eax, FALSE
		    		call	SetDlgItemText, hDlg, IDC_OK, offset szOk
		    		call	MapFile, offset szSectionFile
		    		call	AlignIt, dwFileAlign, dwFileSize
					call	ConvertToHexAndSetEdit, hDlg, IDC_RAW_SIZE, eax
					call	AlignIt, dwSectionAlign, dwFileSize
					call	ConvertToHexAndSetEdit, hDlg, IDC_VIRTUAL_SIZE, eax
					call	SetFocus, hSection
					call	UnMapAndCloseHandles
					mov		bFileOpen, TRUE
		    	.ENDIF
		    .ELSEIF	eax==1 && bFileOpen==TRUE
				call	GetValuesAndSetToFile, hDlg
				call	AddNewSectionToFile
				call	SendMessage, hDlg, WM_CLOSE, NULL, NULL
				mov		bFileOpen, FALSE
				mov		bSaveFile, TRUE
			.ELSE
				call	GetValuesAndSetToFile, hDlg
				call	AddNewSectionToFile
				call	SendMessage, hDlg, WM_CLOSE, NULL, NULL
				mov		bSaveFile, TRUE
			.ENDIF
		.ENDIF
	.ENDIF
	xor		eax, eax
	ret

DialogNewSectionProc	ENDP

AddNewSectionToFile	PROC
	mov		eax, dwRawOffset
	add		eax, dwRawSize
	mov		dwNewFileSize, eax
	call	GlobalAlloc, GMEM_FIXED+GMEM_ZEROINIT, eax
	mov		hMem, eax
	call	GlobalLock, eax
	mov		pMem, eax
	call	CreateFile, offset szFileName, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ+FILE_SHARE_WRITE, \
			NULL, OPEN_EXISTING, NULL, NULL
	mov		hFile, eax
	call	ReadFile, hFile, pMem, dwFileSize, offset dwBuffer, NULL
	mov		eax, pMem
	add		eax, dwFileSize
	mov		ptrNewSection, eax
	.IF		bFileOpen==TRUE
		call	CreateFile, offset szSectionFile, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ+FILE_SHARE_WRITE, \
				NULL, OPEN_EXISTING, NULL, NULL
		mov		hTemp, eax
		call	GetFileSize, eax, NULL
		call	ReadFile, hTemp, ptrNewSection, eax, offset dwBuffer, NULL
		call	CloseHandle, hTemp
	.ENDIF
	call	SetFilePointer, hFile, NULL, NULL, FILE_BEGIN
	call	WriteFile, hFile, pMem, dwNewFileSize, offset dwBuffer, NULL
	call	CloseHandle, hFile
	call	GlobalUnlock, pMem
	call	GlobalFree, hMem
	ret
AddNewSectionToFile	ENDP

GetValuesAndSetToFile	PROC	hDlg:DWORD
	call	GetEditBoxValue, hDlg, IDC_VIRTUAL_SIZE
	call	AlignIt, dwSectionAlign, edx
	mov		dwVirtualSize, eax
	call	GetEditBoxValue, hDlg, IDC_VIRTUAL_OFFSET
	mov		dwVirtualOffset, edx
	call	GetEditBoxValue, hDlg, IDC_RAW_SIZE
	call	AlignIt, dwFileAlign, edx
	mov		dwRawSize, eax
	call	GetEditBoxValue, hDlg, IDC_RAW_OFFSET
	mov		dwRawOffset, edx
	call	GetEditBoxValue, hDlg, IDC_CHARACTERISTICS
	mov		dwCharacteristics, edx
	call	GetDlgItemTextA, hDlg, IDC_SECTION_NAME, offset szNewSectionName, MAX_PATH
	call	MapFileAndSetPointer
	movsx	edx, (IMAGE_NT_HEADERS PTR [eax]).FileHeader.NumberOfSections
	inc		(IMAGE_NT_HEADERS PTR [eax]).FileHeader.NumberOfSections
	mov		ecx, dwVirtualSize
	add		(IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.SizeOfImage, ecx
	mov		eax, ptrSection
	imul	edx, size IMAGE_SECTION_HEADER
	add		eax, edx
	push	dwRawSize
	pop		(IMAGE_SECTION_HEADER PTR [eax]).SizeOfRawData
	push	dwRawOffset
	pop		(IMAGE_SECTION_HEADER PTR [eax]).PointerToRawData
	push	dwVirtualSize
	pop		(IMAGE_SECTION_HEADER PTR [eax]).SVirtualSize
	push	dwVirtualOffset
	pop		(IMAGE_SECTION_HEADER PTR [eax]).SVirtualAddress
	push	dwCharacteristics
	pop		(IMAGE_SECTION_HEADER PTR [eax]).Characteristics
	call	lstrcpy, eax, offset szNewSectionName
	call	UnMapAndCloseHandles
	ret
GetValuesAndSetToFile	ENDP

ConvertHexToString	PROC	dwValue:DWORD
	pushad
	call	wsprintf, offset szOutput, offset szFmatx, dwValue
	add		esp, 12
	popad
	ret
ConvertHexToString	ENDP

OptionalHeaderProc	PROC hDlg:DWORD, uMsg:DWORD, wPara:DWORD, lPara:DWORD

	.IF		uMsg==WM_DESTROY || uMsg==WM_CLOSE
		call	UnMapAndCloseHandles
		call	EndDialog, hDlg, NULL
	.ELSEIF	uMsg==WM_INITDIALOG
		call	SetEditBoxLimit, hDlg, IDC_SUBSYSTEM, IDC_ADDRESSOFENTRYPOINT
		call	MapFileAndSetPointer
		call	ConvertToHexAndSetEdit, hDlg, IDC_ADDRESSOFENTRYPOINT, (IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.AddressOfEntryPoint
		call	ConvertToHexAndSetEdit, hDlg, IDC_IMAGEBASE, (IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.ImageBase
		call	ConvertToHexAndSetEdit, hDlg, IDC_SECTIONALIGNMENT, (IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.SectionAlignment
		call	ConvertToHexAndSetEdit, hDlg, IDC_FILEALIGNMENT, (IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.FileAlignment
		call	ConvertToHexAndSetEdit, hDlg, IDC_SIZEOFIMAGE, (IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.SizeOfImage
		call	ConvertToHexAndSetEdit, hDlg, IDC_SIZEOFHEADER, (IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.SizeOfHeaders
		call	ConvertToHexAndSetEdit, hDlg, IDC_CHECKSUM, (IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.CheckSum
		xor		edx, edx
		mov		dx, (IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.Subsystem
		call	ConvertToHexAndSetEdit, hDlg, IDC_SUBSYSTEM, edx
	.ELSEIF	uMsg==WM_COMMAND
		.IF		wPara==IDCANCEL
			call	SendMessage, hDlg, WM_CLOSE, NULL, NULL
		.ELSEIF	wPara==IDC_OK
			call	GetEditBoxValue, hDlg, IDC_ADDRESSOFENTRYPOINT
			mov		(IMAGE_NT_HEADERS PTR [ecx]).OptionalHeader.AddressOfEntryPoint, edx
			call	GetEditBoxValue, hDlg, IDC_IMAGEBASE
			mov		(IMAGE_NT_HEADERS PTR [ecx]).OptionalHeader.ImageBase, edx
			call	GetEditBoxValue, hDlg, IDC_SECTIONALIGNMENT
			mov		(IMAGE_NT_HEADERS PTR [ecx]).OptionalHeader.SectionAlignment, edx
			call	GetEditBoxValue, hDlg, IDC_FILEALIGNMENT
			mov		(IMAGE_NT_HEADERS PTR [ecx]).OptionalHeader.FileAlignment, edx
			call	GetEditBoxValue, hDlg, IDC_SIZEOFIMAGE
			mov		(IMAGE_NT_HEADERS PTR [ecx]).OptionalHeader.SizeOfImage, edx
			call	GetEditBoxValue, hDlg, IDC_SIZEOFHEADER
			mov		(IMAGE_NT_HEADERS PTR [ecx]).OptionalHeader.SizeOfHeaders, edx
			call	GetEditBoxValue, hDlg, IDC_CHECKSUM
			mov		(IMAGE_NT_HEADERS PTR [ecx]).OptionalHeader.CheckSum, edx
			call	GetEditBoxValue, hDlg, IDC_SUBSYSTEM
			mov		(IMAGE_NT_HEADERS PTR [ecx]).OptionalHeader.SubSystem, dx
			mov		bSaveFile, TRUE
			call	SendMessage, hDlg, WM_CLOSE, NULL, NULL
		.ELSEIF	wPara==IDB_CHECKSUM
			call	CalcPESum, pFileMap, dwFileSize
			call	ConvertToHexAndSetEdit, hDlg, IDC_CHECKSUM, eax			
		.ELSEIF	wPara==IDC_INT3
			mov		eax, ptrPeHeader
			mov		edx, (IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.AddressOfEntryPoint
			call	RVA2Offset, edx
			mov		ecx, eax
			add		eax, pFileMap
			xor		edx, edx
			mov		dl, byte ptr [eax]
			mov		byte ptr [eax], 0CCh
			call	_wsprintfA, offset szOutput, offset szFmatHex, ecx, edx
			add		esp, 3*4
			call	MessageBox, hDlg, offset szOutput, offset szInformation, MB_ICONINFORMATION
		.ENDIF
	.ENDIF
	xor 	eax,eax
	ret

OptionalHeaderProc	ENDP

CalcPESum proc lpImage:DWORD, ImageSize:DWORD ; code by the egoiste!
	uses	ebx, esi, edi
	mov	ecx, ImageSize
	shr	ecx, 1
	jc	@@err
	add	ecx, ecx
	jz	@@err		
	shr	ecx, 2
	sbb	edx, edx
	neg	edx
	xor	ebx, ebx
	mov	esi, lpImage
	cmp	word ptr [esi],	"ZM"
	jnz	@@err
	mov	eax, [esi+60]
	add	eax, esi
	cmp	dword ptr[eax], 00004550h
	jnz	@@err
	mov	edi, dword ptr[eax+88]	
@@l1:	lodsd
	adc	ebx, eax
	loop	@@l1
	adc	ebx, 0
	test	edx, edx
	jz	@@fin	
	xor	eax, eax
	lodsw
	add	ebx, eax
	adc	ebx, 0
@@fin:	mov	eax, ebx
	shr	ebx, 16
	and	eax, 0FFFFh
	add	eax, ebx
	mov	ebx, eax
	shr	ebx, 16
	add	eax, ebx
	and	eax, 0FFFFh
	mov	ebx, edi
	shr	ebx, 16					
	mov	ecx, edi
	cmp	ax, cx
	sbb	edx, edx
	neg	edx
	add	edx, ecx
	sub	eax, edx
	cmp	ax, bx
	sbb	edx, edx
	neg	edx
	mov	cx, bx
	add	edx, ecx
	sub	eax, edx
	and	eax, 0FFFFh
	add	eax, ImageSize
	clc
	RET
@@err:	xor	eax, eax
	stc
	RET
CalcPESum endp

FileHeaderProc	PROC hDlg:DWORD, uMsg:DWORD, wPara:DWORD, lPara:DWORD

	.IF		uMsg==WM_DESTROY || uMsg==WM_CLOSE
		call	UnMapAndCloseHandles
		call	EndDialog, hDlg, NULL
	.ELSEIF	uMsg==WM_INITDIALOG
		call	SetEditBoxLimit, hDlg, IDC_CHARACTERISTIC, IDC_MACHINE
		call	MapFileAndSetPointer
		xor		edx, edx
		mov		dx, (IMAGE_NT_HEADERS PTR [eax]).FileHeader.Machine
		call	ConvertToHexAndSetEdit, hDlg, IDC_MACHINE, edx
		xor		edx, edx
		mov		dx, (IMAGE_NT_HEADERS PTR [eax]).FileHeader.NumberOfSections
		call	ConvertToHexAndSetEdit, hDlg, IDC_NUMBEROFSECTIONS, edx
		call	ConvertToHexAndSetEdit, hDlg, IDC_TIMEDATESTAMP, (IMAGE_NT_HEADERS PTR [eax]).FileHeader.TimeDateStamp
		call	ConvertToHexAndSetEdit, hDlg, IDC_POINTERTOSYMBOLTABLE, (IMAGE_NT_HEADERS PTR [eax]).FileHeader.PointerToSymbolTable
		call	ConvertToHexAndSetEdit, hDlg, IDC_NUMBEROFSYMBOLS, (IMAGE_NT_HEADERS PTR [eax]).FileHeader.NumberOfSymbols
		xor		edx, edx
		mov		dx, (IMAGE_NT_HEADERS PTR [eax]).FileHeader.SizeOfOptionalHeader
		call	ConvertToHexAndSetEdit, hDlg, IDC_SIZEOFOPTIONALHEADER, edx
		xor		edx, edx
		mov		dx, (IMAGE_NT_HEADERS PTR [eax]).FileHeader.Characteristic
		call	ConvertToHexAndSetEdit, hDlg, IDC_CHARACTERISTIC, edx
	.ELSEIF	uMsg==WM_COMMAND
		.IF		wPara==IDCANCEL
			call	SendMessage, hDlg, WM_CLOSE, NULL, NULL
		.ELSEIF	wPara==IDC_OK
			call	GetEditBoxValue, hDlg, IDC_MACHINE
			mov		(IMAGE_NT_HEADERS PTR [ecx]).FileHeader.Machine, dx
			call	GetEditBoxValue, hDlg, IDC_NUMBEROFSECTIONS
			mov		(IMAGE_NT_HEADERS PTR [ecx]).FileHeader.NumberOfSections, dx
			call	GetEditBoxValue, hDlg, IDC_TIMEDATESTAMP
			mov		(IMAGE_NT_HEADERS PTR [ecx]).FileHeader.TimeDateStamp, edx
			call	GetEditBoxValue, hDlg, IDC_POINTERTOSYMBOLTABLE
			mov		(IMAGE_NT_HEADERS PTR [ecx]).FileHeader.PointerToSymbolTable, edx
			call	GetEditBoxValue, hDlg, IDC_NUMBEROFSYMBOLS
			mov		(IMAGE_NT_HEADERS PTR [ecx]).FileHeader.NumberOfSymbols, edx
			call	GetEditBoxValue, hDlg, IDC_SIZEOFOPTIONALHEADER
			mov		(IMAGE_NT_HEADERS PTR [ecx]).FileHeader.SizeOfOptionalHeader, dx
			call	GetEditBoxValue, hDlg, IDC_CHARACTERISTIC
			mov		(IMAGE_NT_HEADERS PTR [ecx]).FileHeader.Characteristic, dx
			mov		bSaveFile, TRUE
			call	SendMessage, hDlg, WM_CLOSE, NULL, NULL
		.ENDIF
	.ENDIF
	xor 	eax,eax
	ret

FileHeaderProc	ENDP

GetEditBoxValue	PROC	hDlg:DWORD, dwEditID:DWORD
	call	SendDlgItemMessageA, hDlg, dwEditID, WM_GETTEXT, 9, offset szOutput
	call	ConvertStringToHex, offset szOutput
	ret
GetEditBoxValue	ENDP

EnableMenuItems	PROC	bFlag:DWORD
	call	EnableMenuItem, hHeader, FILE_HEADER, bFlag
	call	EnableMenuItem, hHeader, OPTIONAL_HEADER, bFlag
	call	EnableMenuItem, hHeader, DATA_DIRECTORY, bFlag
	call	EnableMenuItem, hHeader, IMPORTS, bFlag
	ret
EnableMenuItems	ENDP

DataDirectoryProc	PROC hDlg:DWORD, uMsg:DWORD, wPara:DWORD, lPara:DWORD

	.IF		uMsg==WM_DESTROY || uMsg==WM_CLOSE
		call	UnMapAndCloseHandles
		call	EndDialog, hDlg, NULL
	.ELSEIF	uMsg==WM_INITDIALOG
		call	SetEditBoxLimit, hDlg, IDC_COM_SIZE, IDC_EXPORT_RVA
		call	MapFileAndSetPointer
		lea		eax, (IMAGE_NT_HEADERS PTR [eax]).OptionalHeader
		call	GetDataDirectorys, hDlg, IDC_EXPORT_RVA, IDC_EXPORT_SIZE		
		call	GetDataDirectorys, hDlg, IDC_IMPORT_RVA, IDC_IMPORT_SIZE
		call	GetDataDirectorys, hDlg, IDC_RESOURCES_RVA, IDC_RESOURCES_SIZE
		call	GetDataDirectorys, hDlg, IDC_EXEPTION_RVA, IDC_EXEPTION_SIZE
		call	GetDataDirectorys, hDlg, IDC_SECURITY_RVA, IDC_SECURITY_SIZE
		call	GetDataDirectorys, hDlg, IDC_RELOC_RVA, IDC_RELOC_SIZE
		call	GetDataDirectorys, hDlg, IDC_DEBUG_RVA, IDC_DEBUG_SIZE
		call	GetDataDirectorys, hDlg, IDC_COPYRIGHT_RVA, IDC_COPYRIGHT_SIZE
		add		eax, size IMAGE_DATA_DIRECTORY ;UNKNOWN
		call	GetDataDirectorys, hDlg, IDC_TLS_RVA, IDC_TLS_SIZE
		call	GetDataDirectorys, hDlg, IDC_LOAD_RVA, IDC_LOAD_SIZE
		call	GetDataDirectorys, hDlg, IDC_BOUND_RVA, IDC_BOUND_SIZE
		call	GetDataDirectorys, hDlg, IDC_IAT_RVA, IDC_IAT_SIZE
		call	GetDataDirectorys, hDlg, IDC_DELAY_RVA, IDC_DELAY_SIZE
		call	GetDataDirectorys, hDlg, IDC_COM_RVA, IDC_COM_SIZE
	.ELSEIF uMsg==WM_COMMAND
		.IF		wPara==IDCANCEL
			call	SendMessage, hDlg, WM_CLOSE, NULL, NULL
		.ELSEIF	wPara==IDOK
			mov		ecx, ptrPeHeader
			lea		eax, (IMAGE_NT_HEADERS PTR [ecx]).OptionalHeader
			call	SetDataDirectorys, hDlg, IDC_EXPORT_RVA, IDC_EXPORT_SIZE
			call	SetDataDirectorys, hDlg, IDC_IMPORT_RVA, IDC_IMPORT_SIZE
			call	SetDataDirectorys, hDlg, IDC_RESOURCES_RVA, IDC_RESOURCES_SIZE
			call	SetDataDirectorys, hDlg, IDC_EXEPTION_RVA, IDC_EXEPTION_SIZE	
			call	SetDataDirectorys, hDlg, IDC_SECURITY_RVA, IDC_SECURITY_SIZE
			call	SetDataDirectorys, hDlg, IDC_RELOC_RVA, IDC_RELOC_SIZE
			call	SetDataDirectorys, hDlg, IDC_DEBUG_RVA, IDC_DEBUG_SIZE
			call	SetDataDirectorys, hDlg, IDC_COPYRIGHT_RVA, IDC_COPYRIGHT_SIZE
			add		eax, size IMAGE_DATA_DIRECTORY ;UNKNOWN
			call	SetDataDirectorys, hDlg, IDC_TLS_RVA, IDC_TLS_SIZE
			call	SetDataDirectorys, hDlg, IDC_LOAD_RVA, IDC_LOAD_SIZE
			call	SetDataDirectorys, hDlg, IDC_BOUND_RVA, IDC_BOUND_SIZE
			call	SetDataDirectorys, hDlg, IDC_IAT_RVA, IDC_IAT_SIZE
			call	SetDataDirectorys, hDlg, IDC_DELAY_RVA, IDC_DELAY_SIZE
			call	SetDataDirectorys, hDlg, IDC_COM_RVA, IDC_COM_SIZE
			call	SendMessage, hDlg, WM_CLOSE, NULL, NULL
		.ENDIF
	.ENDIF
	xor 	eax, eax
	ret

DataDirectoryProc	ENDP

.DATA

szCopy		db "Copy Selected",0
szCopyList	db "Copy All Items",0
szSortName	db "Sort by Name",0
szSortDll	db "Sort by DLL",0
szImportDll	db "%s - %s",0
szImportName	db "%s @ %s",0
szListItem	db 255 dup (?)


.DATA?	

pLibrary	dd ?
pImports	dd ?
hListMenu	dd ?
dwTextLen	dd ?
dwListCount	dd ?
dwSort		dd ?

.CODE

ImportsProc	PROC hDlg:DWORD, uMsg:DWORD, wPara:DWORD, lPara:DWORD

	.IF		uMsg==WM_DESTROY || uMsg==WM_CLOSE
		call	EndDialog, hDlg, NULL
	.ELSEIF	uMsg==WM_COMMAND
		.IF		wPara==IDOK
			call	SendMessage, hDlg, WM_CLOSE, NULL, NULL
		.ELSEIF	word ptr [wPara]==IDC_IMPORTS
			mov	eax, wPara
			shr	eax, 16
			.IF	ax==LBN_SELCHANGE
				call	GetCursorPos, offset stPoint
				call 	TrackPopupMenu, hListMenu, TPM_RIGHTBUTTON, stPoint.pt_x, stPoint.pt_y, NULL, hDlg, NULL
			.ENDIF
		.ELSEIF	wPara==123
			call	SendDlgItemMessage, hDlg, IDC_IMPORTS, LB_GETCURSEL, NULL, NULL
			call	SendDlgItemMessage, hDlg, IDC_IMPORTS, LB_GETTEXT, eax, offset szOutput
			call	MessageBox, hDlg, offset szOutput, NULL, MB_OK
		.ELSEIF	wPara==1234
			call	SendDlgItemMessage, hDlg, IDC_IMPORTS, LB_GETCOUNT, NULL, NULL
			dec		eax
			mov		dwCount, eax
			mov		dwListCount, eax
			.WHILE dwCount>0
				call	SendDlgItemMessage, hDlg, IDC_IMPORTS, LB_GETTEXTLEN, dwCount, NULL
				add		eax, 2
				add		dwTextLen, eax
				dec		dwCount
			.ENDW
			call	PrepareClipboard, dwTextLen
			push	eax
			int 3
			.WHILE	dwListCount>0
				call	SendDlgItemMessage, hDlg, IDC_IMPORTS, LB_GETTEXT, dwCount, pMem
				add		pMem, eax
				mov		eax, pMem
				mov		dword ptr [eax], 0a0dh
				add		pMem, 2					
				inc		dwCount
				dec		dwListCount
			.ENDW
			pop		pMem
			call	SetClipBoardData, CF_TEXT, pMem			
			call	EndClipboard
		.ELSEIF	wPara==12345
			call	SendDlgItemMessage, hDlg, IDC_IMPORTS, LB_RESETCONTENT, NULL, NULL
			.IF		dwSort==0
				mov		dwSort, 1
				call	LoadImports, hDlg, dwSort
				call	ModifyMenuA, hListMenu, 12345, MF_BYCOMMAND, 12345,	offset szSortDll
			.ELSE
				mov		dwSort, 0
				call	LoadImports, hDlg, dwSort
				call	ModifyMenuA, hListMenu, 12345, MF_BYCOMMAND, 12345,	offset szSortName
			.ENDIF
		.ENDIF	
	.ELSEIF	uMsg==WM_INITDIALOG
		call	CreatePopupMenu
		mov		hListMenu, eax
		call	AppendMenuA, hListMenu, MF_STRING, 123, offset szCopy
		call	AppendMenuA, hListMenu, MF_STRING, 1234, offset szCopyList
		call	AppendMenuA, hListMenu, MF_SEPARATOR, NULL, NULL	
		call	AppendMenuA, hListMenu, MF_STRING, 12345, offset szSortName
		mov 	stColumn.lx, 90
		mov 	stColumn.iSubItem, 0
		call	SetNewColumn, hDlg, offset szLibrary, 0
		mov 	stColumn.lx, 154
		call	SetNewColumn, hDlg, offset szImport, 1
		mov 	stColumn.lx, 62
		call	SetNewColumn, hDlg, offset szRVA, 2		
		mov 	stColumn.lx, 62
		call	SetNewColumn, hDlg, offset szHint, 3				
		mov 	stList.lv_iItem, -1
		mov 	stList.lv_imask, LVIF_TEXT				
		call	LoadImports, hDlg, dwSort		
	.ENDIF
	xor 	eax, eax
	ret

ImportsProc	ENDP

.DATA

szImport	db "Name",0
szLibrary	db "Library",0
szRva		db "RVA",0
szHint		db "Hint",0
szOrdinal	db "Ordinal",0

.CODE

PrepareClipboard	PROC	dwSize:DWORD
	call	OpenClipboard, NULL
	call	EmptyClipboard		
	call	GlobalAlloc, GMEM_MOVEABLE+GMEM_DDESHARE, dwSize
	mov		hMem, eax
	call	GlobalLock, eax
	mov		pMem, eax
	ret
PrepareClipboard	ENDP

EndClipboard	PROC
	call	CloseClipboard
	call	GlobalUnlock, pMem
	call	GlobalFree, hMem
	ret
EndClipBoard	ENDP

LoadImports	PROC	hDlg:DWORD
	LOCAL	dwHint:DWORD
	call	MapFileAndSetPointer
	push	(IMAGE_NT_HEADERS PTR [eax]).OptionalHeader.ImageBase
	pop		dwImageBase
	lea		eax, (IMAGE_NT_HEADERS PTR [eax]).OptionalHeader
	add		eax, size IMAGE_DATA_DIRECTORY
	call	RVA2Offset, (IMAGE_OPTIONAL_HEADER PTR [eax]).DataDirectory.VirtualAddress
	add		eax, pFileMap
	mov		pImports, eax
	.WHILE	!(IMAGE_IMPORT_DESCRIPTOR PTR [eax]).FirstThunk==0
		call	RVA2Offset, (IMAGE_IMPORT_DESCRIPTOR PTR [eax]).NameRva
		add		eax, pFileMap
		mov		pLibrary, eax
		mov		eax, pImports
		.IF	(IMAGE_IMPORT_DESCRIPTOR PTR [eax]).OriginalFirstThunk==0
			call	RVA2Offset, (IMAGE_IMPORT_DESCRIPTOR PTR [eax]).FirstThunk
		.ELSE
			call	RVA2Offset, (IMAGE_IMPORT_DESCRIPTOR PTR [eax]).OriginalFirstThunk
		.ENDIF
		add		eax, pFileMap
		mov		edx, [eax] 	;IMAGE_THUNK_DATA
		.WHILE	!edx==0
			push	eax
			mov		ecx, edx
			test ecx, IMAGE_ORDINAL_FLAG32
			.IF	!ZERO?
				xor		edx, IMAGE_ORDINAL_FLAG32
				mov		dwHint, edx
				push	pLibrary
				pop		stList.lv_pszText
				inc		stList.lv_iItem
				mov 	stList.lv_iSubItem, 0				
				call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_INSERTITEM, 0, offset stList
				push	offset szOrdinal
				pop		stList.lv_pszText
				inc 	stList.lv_iSubItem
				call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_SETITEM, 0, offset stList			
				pop		eax
				push	eax
				call	RVA2Offset, eax
				mov		stList.lv_pszText, offset szOutput
				call	ValueToListView, hDlg, eax
				call	ValueToListView, hDlg, dwHint				
			.ELSE
				call	RVA2Offset, edx
				push	eax
				add		eax, pFileMap
				mov		dx, (IMAGE_IMPORT_BY_NAME PTR [eax]).Hint
				and		edx, 0FFFFh
				mov		dwHint, edx
				lea		eax, (IMAGE_IMPORT_BY_NAME PTR [eax]).Name1
				inc		stList.lv_iItem
				mov 	stList.lv_iSubItem, 0
				push	pLibrary
				pop		stList.lv_pszText
				push	eax
				call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_INSERTITEM, 0, offset stList
				pop		stList.lv_pszText
				inc 	stList.lv_iSubItem
				call	SendDlgItemMessage, hDlg, IDC_LIST, LVM_SETITEM, 0, offset stList
				pop		eax
				mov		stList.lv_pszText, offset szOutput
				call	ValueToListView, hDlg, eax
				call	ValueToListView, hDlg, dwHint
			.ENDIF
			pop		eax
			add		eax, 4
			mov		edx, [eax]
		.ENDW
		add		pImports, size IMAGE_IMPORT_DESCRIPTOR
		mov		eax, pImports
	.ENDW	
	call	SendDlgItemMessage, hDlg, IDC_IMPORTS, LB_GETCOUNT, NULL, NULL
	call	SetDlgItemInt, hDlg, IDC_COUNT, eax, false
	ret

LoadImports	ENDP

SetEditBoxLimit	PROC	hDlg:DWORD, dwHighControl:DWORD, dwLowControl:DWORD
	mov		eax, dwLowControl
	.WHILE	dwHighControl>=eax
		call	SendDlgItemMessage, hDlg, dwHighControl, EM_LIMITTEXT, 8, NULL
		dec		dwHighControl
		mov		eax, dwLowControl
	.ENDW
	ret
SetEditBoxLimit	ENDP

GetDataDirectorys	PROC	hDlg:DWORD, dwControlOne:DWORD, dwControlTwo:DWORD
	call	ConvertToHexAndSetEdit, hDlg, dwControlOne, (IMAGE_OPTIONAL_HEADER PTR [eax]).DataDirectory.VirtualAddress
	call	ConvertToHexAndSetEdit, hDlg, dwControlTwo, (IMAGE_OPTIONAL_HEADER PTR [eax]).DataDirectory.ISize
	add		eax, size IMAGE_DATA_DIRECTORY
	ret
GetDataDirectorys	ENDP

GetValueAndConvert	PROC	hDlg:DWORD, dwControlD:DWORD
	pushad
	call	SendDlgItemMessageA, hDlg, dwControlID, WM_GETTEXT, 9, offset szOutput
	call	ConvertStringToHex, offset szOutput
	mov		dwReturn, edx
	popad
	ret
GetValueAndConvert	ENDP

SetDataDirectorys	PROC	hDlg:DWORD, dwControlOne:DWORD, dwControlTwo:DWORD
	call	GetValueAndConvert, hDlg, dwControlOne
	push	dwReturn
	pop		(IMAGE_OPTIONAL_HEADER PTR [eax]).DataDirectory.VirtualAddress
	call	GetValueAndConvert, hDlg, dwControlTwo
	push	dwReturn
	pop		(IMAGE_OPTIONAL_HEADER PTR [eax]).DataDirectory.ISize
	add		eax, size IMAGE_DATA_DIRECTORY
	ret
SetDataDirectorys	ENDP

End Start