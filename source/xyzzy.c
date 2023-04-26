/* OTP and SEEPROM access code taken from libOTP and libSEEPROM, respectively */
/* Both libraries were made by joedj (partially using code from MINI), so big thanks to him and Team fail0verflow */

/* Additional functions, like the hexdump feature and the device.cert dumping procedure, */
/* were taken from the original Xyzzy by bushing, which evidently served as a start point */

/* Kudos to WiiPower and Arikado for additional init code */
/* Kudos to InvoxiPlayGames for speeding up the key dumping algorithms */

/* DarkMatterCore - 2020-2022 */

#include <stdlib.h>
#include <string.h>
#include <gccore.h>
#include <network.h>

#include "tools.h"
#include "otp.h"
#include "mini_seeprom.h"
#include "vwii_sram_otp.h"
#include "sha1.h"
#include "aes.h"
#include "boot0.h"
#include "xxhash.h"

#define SYSTEM_MENU_TID     (u64)0x0000000100000002

#define DEVCERT_BUF_SIZE    0x200
#define DEVCERT_SIZE        0x180

#define ANCAST_HEADER_MAGIC (u32)0xEFA282D9

typedef struct {
    char human_info[0x100];
    otp_t otp_data;
    u8 otp_padding[0x80];
    seeprom_t seeprom_data;
    u8 seeprom_padding[0x100];
} bootmii_keys_bin_t;

typedef struct {
    char content_name[8];
    sha1 content_hash;
} __attribute__((packed)) content_map_entry_t;

typedef struct {
    u8 key[64];
    u32 key_size;
    u32 xxhash;
    u8 hash[SHA1HashSize];
    bool retrieved;
} additional_keyinfo_t;

typedef struct {
    u32 magic;
    u32 unk_1;
    u32 signature_offset;
    u32 unk_2;
    u8 unk_3[0x10];
    u32 signature_type;
    u8 signature[0x38];
    u8 padding_1[0x44];
    u16 unk_4;
    u8 unk_5;
    u8 unk_6;
    u32 unk_7;
    u32 hash_type;
    u32 body_size;
    u8 body_hash[0x14];
    u8 padding_2[0x3C];
} ppc_ancast_image_header_t;

static u8 otp_ptr[OTP_SIZE] = {0};

static const char *key_names_stdout[] = {
    "Common Key   ",
    NULL
};

static const char *key_names_txt[] = {
    "wii_common_key  ",
    NULL
};

static void OTP_ClearData(void)
{
    memset(otp_ptr, 0, OTP_SIZE);
}

static bool OTP_ReadData(void)
{
    OTP_ClearData();

    u8 ret = otp_read(otp_ptr, 0, OTP_SIZE);

    return (ret == OTP_SIZE);
}

static bool FillOTPStruct(otp_t **out)
{
    if (!out)
    {
        printf("Fatal error: invalid output OTP struct pointer.\n\n");
        return false;
    }

    otp_t *otp_data = memalign(32, sizeof(otp_t));
    if (!otp_data)
    {
        printf("Fatal error: unable to allocate memory for OTP struct.\n\n");
        return false;
    }

    /* Read OTP data into otp_ptr pointer */
    if (!OTP_ReadData())
    {
        printf("Fatal error: OTP_ReadData() failed.\n\n");
        OTP_ClearData();
        return false;
    }

    /* Copy OTP data into our allocated struct */
    memcpy(otp_data, otp_ptr, sizeof(otp_t));
    OTP_ClearData();

    /* Save OTP struct pointer */
    *out = otp_data;

    return true;
}

static void PrintAllKeys(const otp_t *otp_data, const seeprom_t *seeprom_data, const vwii_sram_otp_t *sram_otp_data, FILE *fp)
{
    if (!otp_data || !fp) return;

    u8 key_idx = 1;
    bool is_txt = (fp != stdout);
    const char **key_names = (is_txt ? key_names_txt : key_names_stdout);

    for(u8 i = 0; key_names[i]; i++)
    {
        fprintf(fp, "%s= ", key_names[i]);

        HexKeyDump(fp, otp_data->common_key, sizeof(otp_data->common_key), !is_txt);

        fprintf(fp, "\r\n");

        key_idx++;
    }
}

int XyzzyGetKeys(void)
{
    int ret = 0;
    FILE *fp = NULL;
    char ATTRIBUTE_ALIGN(32) path[128] = {0};
    char *pch = NULL;

    otp_t *otp_data = NULL;

    ret = SelectStorageDevice();
    if (ret == -2) return ret;
    ret = 0;

    PrintHeadline();
    printf("Getting keys, please wait...\n\n");

    if (!FillOTPStruct(&otp_data))
    {
        ret = -1;
        sleep(2);
        goto out;
    }

    /* Print common key to stdout */
    PrintAllKeys(otp_data, seeprom_data, sram_otp, stdout);

    /* Create output directory tree */
    sprintf(path, "%s:/", StorageDeviceMountName());
    pch = (path + strlen(path));

    /* Print common key to output txt */
    sprintf(pch, "keys.txt");
    fp = fopen(path, "w");
    if (fp)
    {
        PrintAllKeys(otp_data, seeprom_data, sram_otp, fp);
        fclose(fp);
        fp = NULL;
    } else {
        printf("\t- Unable to open keys.txt for writing.\n");
        printf("\t- Sorry, not writing keys to %s.\n\n", StorageDeviceString());
        sleep(2);
    }

    /* Save raw common key binary */
    sprintf(pch, "common-key.bin");
    fp = fopen(path, "wb");
    if (fp)
    {
        fwrite(otp_data->common_key, 1, sizeof(otp_data->common_key), fp);
        fclose(fp);
        fp = NULL;
    } else {
        printf("\n\t- Unable to open common-key.bin for writing.");
        printf("\n\t- Sorry, not writing raw Common Key data to %s.\n", StorageDeviceString());
        sleep(2);
    }

out:
    if (otp_data) free(otp_data);

    if (fp) fclose(fp);

    UnmountStorageDevice();

    return ret;
}
