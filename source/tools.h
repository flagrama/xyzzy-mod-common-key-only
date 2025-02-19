#ifndef __TOOLS_H__
#define __TOOLS_H__

#include <sys/unistd.h>
#include <wiiuse/wpad.h>
#include <malloc.h>
#include <stdio.h>
#include <sys/stat.h>
#include <ogc/machine/processor.h>

#define VERSION                     "1.3.3 Common Key Only"

#define ResetScreen()               printf("\x1b[2J")

#define TITLE_UPPER(x)              ((u32)((x) >> 32))
#define TITLE_LOWER(x)              ((u32)(x))
#define TITLE_ID(x, y)              (((u64)(x) << 32) | (y))

#define ALIGN_UP(x, y)              (((x) + ((y) - 1)) & ~((y) - 1))
#define ALIGN_DOWN(x, y)            ((x) & ~((y) - 1))

#define MAX_ELEMENTS(x)             (sizeof((x)) / sizeof((x)[0]))

#define MEMBER_SIZE(type, member)   sizeof(((type*)NULL)->member)

#define HW_SRNPROT                  0xD800060
#define HW_AHBPROT                  0xD800064
#define MEM_PROT                    0xD8B420A

// Top 12 MiB from MEM2
#define MEM2_IOS_LOOKUP_START       0x93400000
#define MEM2_IOS_LOOKUP_END         0x94000000

#define AHBPROT_DISABLED            (read32(HW_AHBPROT) == 0xFFFFFFFF)

extern bool g_isvWii;

bool IsWiiU(void);

void Reboot(void);

void InitPads(void);
void WaitForButtonPress(u32 *out, u32 *outGC);

void InitConsole();
void PrintHeadline();

void DisableMemoryProtection(void);
bool PatchNandFsPermissions(void);

void UnmountStorageDevice(void);
int SelectStorageDevice(void);
const char *StorageDeviceString(void);
const char *StorageDeviceMountName(void);

void HexKeyDump(FILE *fp, const void *d, size_t len, bool add_spaces);

signed_blob *GetSignedTMDFromTitle(u64 title_id, u32 *out_size);

static inline tmd *GetTMDFromSignedBlob(signed_blob *stmd)
{
    if (!stmd || !IS_VALID_SIGNATURE(stmd)) return NULL;
    return (tmd*)((u8*)stmd + SIGNATURE_SIZE(stmd));
}

void *ReadFileFromFlashFileSystem(const char *path, u32 *out_size);

bool CheckIfFlashFileSystemFileExists(const char *path);

#endif /* __TOOLS_H__ */
