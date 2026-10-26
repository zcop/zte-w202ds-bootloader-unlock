#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

/*
 * difftool.c
 *
 * Usage: difftool <patched_bin> <original_magic_processed_bin> [output_file]
 *
 *   patched_bin                 - The modified firmware (with desired patches).
 *   original_magic_processed_bin - The original firmware processed by magic32/magic64
 *                                 (original payload intact, patch_data area zeroed).
 *   output_file                 - Optional output filename.
 *                                 Default: original_magic_processed_bin with "_patched"
 *                                 suffix (e.g. "patched.bin" -> "patched_patched.bin").
 *
 * What it does:
 *   1. Uses footer->payload_offset to locate payload (not hardcoded).
 *   2. Compares payloads word-by-word, groups consecutive diffs into patch entries.
 *   3. Determines patch_data area position from the magic area layout.
 *   4. Injects patch_data directly into a copy of the original magic-processed file.
 *   5. Also writes a C array text file for reference.
 *
 * Patch entry format: [addr (4B LE)] [length_in_words (4B LE)] [data (length*4 B)]
 * Terminated by a zero address word.
 */

#define BTHD_MAGIC 0x42544844 /* "BTHD" */

/* ======================== struct definitions ======================== */

/* sys_img_header (BTHD) – at file offset 0 */
typedef struct
{
    uint32_t mMagicNum;
    uint32_t mVersion;
    uint8_t mPayloadHash[32];
    uint64_t mImgAddr;
    uint32_t mImgSize; /* modified by magic: original + add_lenth */
    uint32_t is_packed;
    uint32_t mFirmwareSize;
    uint8_t reserved[452];
} sys_img_header;

#define SIMG_MAGIC_SIZE 8
/* sprdsignedimageheader – at file offset 0x200 + hdr->mImgSize */
typedef struct
{
    uint8_t magic[SIMG_MAGIC_SIZE];
    uint32_t header_version_major;
    uint32_t header_version_minor;
    uint64_t payload_size;   /* original payload size (NOT modified by magic) */
    uint64_t payload_offset; /* set to 0x210 by magic */
    uint64_t cert_size;
    uint64_t cert_offset;
    uint64_t priv_size;
    uint64_t priv_offset;
    uint64_t cert_dbg_prim_size;
    uint64_t cert_dbg_prim_offset;
    uint64_t cert_dbg_developer_size;
    uint64_t cert_dbg_developer_offset;
} sprdsignedimageheader; /* 0x60 bytes */

/* ======================== helpers ======================== */

static uint8_t *loadfile(const char *fn, int32_t *num)
{
    size_t n, j = 0;
    uint8_t *buf = NULL;
    FILE *f = fopen(fn, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    if (n > 0)
    {
        fseek(f, 0, SEEK_SET);
        buf = (uint8_t *)malloc(n);
        if (buf)
            j = fread(buf, 1, n, f);
    }
    fclose(f);
    if (num)
        *num = (int32_t)j;
    return buf;
}

static int savefile(const char *fn, const uint8_t *data, int32_t len)
{
    FILE *f = fopen(fn, "wb");
    if (!f)
        return -1;
    int32_t written = (int32_t)fwrite(data, 1, len, f);
    fclose(f);
    return (written == len) ? 0 : -1;
}

/* ======================== main ======================== */

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        fprintf(stderr,
                "Usage: %s <patched_bin> <original_magic_processed_bin> <load_addr> [output_file]\n"
                "\n"
                "  <patched_bin>          - Modified firmware processed by IDA / HEX Editor\n"
                "  <original_magic_processed_bin> - Original firmware processed by magic32/magic64\n"
                "  <load_addr>            - Runtime load address of the payload (hex, e.g. 0x9F000000, don't use addr end with e00)\n"
                "  [output_file]          - Optional output filename.\n"
                "\n"
                "  Compares payload of two magic-processed firmware images,\n"
                "  generates patch_data, and writes a new copy of the original\n"
                "  with patch_data injected.\n"
                "\n"
                "  output_file defaults to the original filename with\n"
                "  '_patched' inserted before the extension.\n",
                argv[0]);
        return 1;
    }

    const char *patched_path = argv[1];
    const char *original_path = argv[2];
    const char *addr_str = argv[3];

    /* Parse load address (hex string) */
    char *endptr;
    uint64_t base_addr = strtoull(addr_str, &endptr, 16);
    if (*endptr != '\0' || base_addr == 0)
    {
        fprintf(stderr, "Error: invalid load address '%s' (use hex, e.g. 0x9F000000)\n", addr_str);
        return 1;
    }

    /* Derive default output name */
    char def_out[1024];
    {
        const char *dot = strrchr(original_path, '.');
        if (dot && dot > original_path)
        {
            ptrdiff_t base_len = dot - original_path;
            snprintf(def_out, sizeof(def_out), "%.*s_patched%s",
                     (int)base_len, original_path, dot);
        }
        else
        {
            snprintf(def_out, sizeof(def_out), "%s_patched", original_path);
        }
    }
    const char *output_path = (argc >= 5) ? argv[4] : def_out;

    /* ---- load files ---- */
    int32_t ps, os;
    uint8_t *patched = loadfile(patched_path, &ps);
    uint8_t *original = loadfile(original_path, &os);

    if (!patched || !original)
    {
        fprintf(stderr, "Error: failed to load input file(s)\n");
        free(patched);
        free(original);
        return 1;
    }

    printf("patched.bin  size: 0x%X (%u bytes)\n", ps, ps);
    printf("original.bin size: 0x%X (%u bytes)\n", os, os);

    /* ---- validate BTHD headers ---- */
    /* patched_bin allows raw format (no BTHD header) */
    sys_img_header *hdr_o = (sys_img_header *)original;
    if (hdr_o->mMagicNum != BTHD_MAGIC)
    {
        fprintf(stderr, "Error: no valid BTHD header in '%s' (original must have header)\n", original_path);
        free(patched);
        free(original);
        return 1;
    }

    int patched_is_raw = (*(uint32_t *)patched != BTHD_MAGIC);
    printf("Patched file format: %s\n", patched_is_raw ? "RAW" : "BTHD");

    uint32_t payload_off_p; /* offset of payload in patched file */
    uint32_t payload_off_o; /* offset of payload in original file */
    uint32_t payload_size;  /* original unmodified payload size */

    if (patched_is_raw)
    {
        /* raw patched file: the entire file is the payload */
        payload_off_p = 0;
    }
    else
    {
        /* patched file: locate its footer for payload offset */
        sys_img_header *hdr_p = (sys_img_header *)patched;
        uint32_t footer_off_p = 0x200 + hdr_p->mImgSize;
        if (footer_off_p + sizeof(sprdsignedimageheader) > (uint32_t)ps)
        {
            fprintf(stderr, "Error: footer offset 0x%X exceeds '%s'\n", footer_off_p, patched_path);
            free(patched);
            free(original);
            return 1;
        }
        sprdsignedimageheader *footer_p = (sprdsignedimageheader *)(patched + footer_off_p);
        payload_off_p = (uint32_t)(footer_p->payload_offset); /* 0x210 */
    }

    /* ---- locate footer in original file ---- */
    uint32_t footer_off_o = 0x200 + hdr_o->mImgSize;
    sprdsignedimageheader *footer_o;
    {
        if (footer_off_o + sizeof(sprdsignedimageheader) > (uint32_t)os)
        {
            fprintf(stderr, "Error: footer offset 0x%X exceeds '%s'\n", footer_off_o, original_path);
            free(patched);
            free(original);
            return 1;
        }
        footer_o = (sprdsignedimageheader *)(original + footer_off_o);
        payload_off_o = (uint32_t)(footer_o->payload_offset); /* 0x210 */
        payload_size = (uint32_t)(footer_o->payload_size);    /* original unmodified size */
    }

    printf("Patched  payload offset: 0x%X\n", payload_off_p);
    printf("Original payload offset: 0x%X\n", payload_off_o);
    printf("Payload size  (from original footer): 0x%X (%u bytes)\n", payload_size, payload_size);
    printf("Load address:                         0x%llX\n", (unsigned long long)base_addr);

    /* Sanity checks */
    if (payload_off_p + payload_size > (uint32_t)ps)
    {
        fprintf(stderr, "Error: patched payload (0x%X + 0x%X) exceeds file size 0x%X\n",
                payload_off_p, payload_size, ps);
        free(patched);
        free(original);
        return 1;
    }
    if (payload_off_o + payload_size > (uint32_t)os)
    {
        fprintf(stderr, "Error: original payload (0x%X + 0x%X) exceeds file size 0x%X\n",
                payload_off_o, payload_size, os);
        free(patched);
        free(original);
        return 1;
    }

    /* ---- compute contiguous extra data block (cert/priv/dbg, BTHD only) ---- */
    uint32_t extra_blk_off_o = 0, extra_blk_off_p = 0, extra_blk_sz = 0;

    if (!patched_is_raw)
    {
        sys_img_header *hdr_p2 = (sys_img_header *)patched;
        uint32_t footer_off_p2 = 0x200 + hdr_p2->mImgSize;
        sprdsignedimageheader *footer_p2 = (sprdsignedimageheader *)(patched + footer_off_p2);

        /* The 4 regions are contiguous; find the overall range */
        uint32_t min_off = 0xFFFFFFFF, max_end = 0;

#define ADD_REGION(field)                                          \
    do                                                             \
    {                                                              \
        uint32_t sz_o = (uint32_t)(footer_o->field##_size);        \
        if (sz_o > 0)                                              \
        {                                                          \
            uint32_t off_o = (uint32_t)(footer_o->field##_offset); \
            uint32_t end_o = off_o + sz_o;                         \
            if (off_o < min_off)                                   \
                min_off = off_o;                                   \
            if (end_o > max_end)                                   \
                max_end = end_o;                                   \
        }                                                          \
    } while (0)

        ADD_REGION(cert);
        ADD_REGION(priv);
        ADD_REGION(cert_dbg_prim);
        ADD_REGION(cert_dbg_developer);
#undef ADD_REGION

        if (max_end > min_off)
        {
            extra_blk_off_o = min_off;
            extra_blk_sz = max_end - min_off;
            /* patched file offset: use its own cert_offset as anchor */
            extra_blk_off_p = (uint32_t)(footer_p2->cert_offset);
            /* shift if original cert_offset differs */
            {
                uint32_t cert_off_o = (uint32_t)(footer_o->cert_offset);
                if (cert_off_o != extra_blk_off_o)
                    extra_blk_off_p += (extra_blk_off_o - cert_off_o);
            }

            printf("Extra data block: offset orig 0x%X / patch 0x%X, size 0x%X (%u bytes)\n",
                   extra_blk_off_o, extra_blk_off_p, extra_blk_sz, extra_blk_sz);
        }
    }

    uint8_t *orig_payload = original + payload_off_o;
    uint8_t *patch_payload = patched + payload_off_p;

    /* ---- determine architecture from jump opcode at offset 0x203 ---- */
    int shellcode_sz;
    int patch_data_max;
    if (original[0x203] == 0x14)
    {
        shellcode_sz = 0x70; /* magic64 */
        patch_data_max = 0x80;
        printf("Architecture: AArch64 (magic64)\n");
    }
    else if (original[0x203] == 0xEA)
    {
        shellcode_sz = 0x94; /* magic32 */
        patch_data_max = 0x15C;
        printf("Architecture: ARM32 (magic32)\n");
    }
    else
    {
        fprintf(stderr,
                "Error: unknown jump opcode 0x%02X at offset 0x203 (expected 0x14 or 0xEA)\n",
                original[0x203]);
        free(patched);
        free(original);
        return 1;
    }

    uint32_t patch_data_off = payload_off_o + payload_size + shellcode_sz;

    printf("Shellcode size: %d bytes\n", shellcode_sz);
    printf("Patch data at:  0x%X (max %d bytes)\n", patch_data_off, patch_data_max);

    /* ---- collect patch entries (dynamically, no hard limit) ---- */
    typedef struct
    {
        uint32_t addr;
        uint32_t length; /* in 4-byte words */
        uint32_t *data;
    } patch_entry;

    patch_entry *entries = NULL;
    int entry_cap = 0, entry_count = 0;

    int off = 0;
    while (off < (int)payload_size)
    {
        if (off + 4 <= (int)payload_size &&
            memcmp(&orig_payload[off], &patch_payload[off], 4) != 0)
        {

            int wc = 0;
            while (off + (wc + 1) * 4 <= (int)payload_size)
            {
                if (memcmp(&orig_payload[off + wc * 4],
                           &patch_payload[off + wc * 4], 4) == 0)
                    break;
                wc++;
            }

            if (entry_count >= entry_cap)
            {
                entry_cap = entry_cap ? entry_cap * 2 : 1024;
                entries = (patch_entry *)realloc(entries, entry_cap * sizeof(patch_entry));
                if (!entries)
                {
                    fprintf(stderr, "Error: out of memory\n");
                    free(patched);
                    free(original);
                    return 1;
                }
            }

            entries[entry_count].addr = (uint32_t)(base_addr + off);
            entries[entry_count].length = wc;
            entries[entry_count].data = (uint32_t *)&patch_payload[off];
            entry_count++;

            off += wc * 4;
        }
        else
        {
            off += 4;
        }
    }

    /* ---- compare contiguous extra data block (BTHD only) ---- */
    if (extra_blk_sz > 0)
    {
        if (extra_blk_off_o + extra_blk_sz > (uint32_t)os ||
            extra_blk_off_p + extra_blk_sz > (uint32_t)ps)
        {
            fprintf(stderr, "Warning: extra data block exceeds file bounds, skipping\n");
        }
        else
        {
            uint8_t *orig_blk = original + extra_blk_off_o;
            uint8_t *patch_blk = patched + extra_blk_off_p;

            int changed = 0;
            int roff = 0;
            while (roff < (int)extra_blk_sz)
            {
                if (memcmp(&orig_blk[roff], &patch_blk[roff], 4) != 0)
                {
                    int wc = 0;
                    while (roff + (wc + 1) * 4 <= (int)extra_blk_sz &&
                           memcmp(&orig_blk[roff + wc * 4],
                                  &patch_blk[roff + wc * 4], 4) != 0)
                        wc++;

                    if (entry_count >= entry_cap)
                    {
                        entry_cap = entry_cap ? entry_cap * 2 : 1024;
                        entries = (patch_entry *)realloc(entries, entry_cap * sizeof(patch_entry));
                        if (!entries)
                        {
                            fprintf(stderr, "Error: OOM\n");
                            free(patched);
                            free(original);
                            return 1;
                        }
                    }

                    entries[entry_count].addr = (uint32_t)(base_addr + extra_blk_off_o + roff - sizeof(sys_img_header));
                    entries[entry_count].length = wc;
                    entries[entry_count].data = (uint32_t *)&patch_blk[roff];
                    entry_count++;
                    changed = 1;

                    roff += wc * 4;
                }
                else
                {
                    roff += 4;
                }
            }

            if (changed)
                printf("Extra data block patches: included\n");
        }
    }

    /* ---- calculate total patch_data size ---- */
    int total_words = 1; /* terminator */
    for (int i = 0; i < entry_count; i++)
        total_words += 2 + entries[i].length;

    int total_bytes = total_words * 4;

    /* ---- compute whether we need to expand add_length ---- */
    uint32_t magic_start = payload_off_o + payload_size;
    int old_add_length = (int)(footer_off_o - magic_start) + 0x10;
    int add_delta = 0;

    if (total_bytes > patch_data_max)
    {
        int min_add = 0x10 + shellcode_sz + total_bytes;
        int new_add_length = (min_add + 0xFF) & ~0xFF;

        add_delta = new_add_length - old_add_length;
        patch_data_max = new_add_length - 0x10 - shellcode_sz;

        printf("\nPatch data (%d bytes) exceeds original space (%d bytes).\n",
               total_bytes, patch_data_max - add_delta);
        printf("  Old add_length: 0x%X\n", old_add_length);
        printf("  New add_length: 0x%X (delta +0x%X)\n", new_add_length, add_delta);
    }

    printf("\nPatch entries:    %d\n", entry_count);
    printf("Patch data size:  %d bytes\n", total_bytes);
    printf("Available space:  %d bytes\n", patch_data_max);

    /* ---- build the patch_data byte array ---- */
    uint8_t *patch_data = (uint8_t *)calloc(1, total_bytes);
    if (!patch_data)
    {
        fprintf(stderr, "Error: OOM\n");
        free(entries);
        free(patched);
        free(original);
        return 1;
    }

    {
        int pos = 0;
        for (int i = 0; i < entry_count; i++)
        {
            /* addr LE */
            patch_data[pos + 0] = (entries[i].addr >> 0) & 0xFF;
            patch_data[pos + 1] = (entries[i].addr >> 8) & 0xFF;
            patch_data[pos + 2] = (entries[i].addr >> 16) & 0xFF;
            patch_data[pos + 3] = (entries[i].addr >> 24) & 0xFF;
            pos += 4;
            /* length LE */
            uint32_t len = entries[i].length;
            patch_data[pos + 0] = (len >> 0) & 0xFF;
            patch_data[pos + 1] = (len >> 8) & 0xFF;
            patch_data[pos + 2] = (len >> 16) & 0xFF;
            patch_data[pos + 3] = (len >> 24) & 0xFF;
            pos += 4;
            /* data words LE */
            for (uint32_t w = 0; w < len; w++)
            {
                uint32_t word = entries[i].data[w];
                patch_data[pos + 0] = (word >> 0) & 0xFF;
                patch_data[pos + 1] = (word >> 8) & 0xFF;
                patch_data[pos + 2] = (word >> 16) & 0xFF;
                patch_data[pos + 3] = (word >> 24) & 0xFF;
                pos += 4;
            }
        }
        /* terminator (addr=0) already zeroed by calloc */
    }

    /* ---- inject patch_data into a copy of the original file ---- */
    {
        int new_size = os + add_delta;
        uint8_t *outbuf = (uint8_t *)malloc(new_size);
        if (!outbuf)
        {
            fprintf(stderr, "Error: OOM\n");
            free(patch_data);
            free(entries);
            free(patched);
            free(original);
            return 1;
        }

        if (add_delta > 0)
        {
            /* --- expanded layout: shift footer+cert backward --- */

            /* 1. header (0x200) – update mImgSize */
            memcpy(outbuf, original, 0x200);
            ((sys_img_header *)outbuf)->mImgSize += add_delta;

            /* 2. jump code (0x10) */
            memcpy(outbuf + 0x200, original + 0x200, 0x10);

            /* 3. payload */
            memcpy(outbuf + payload_off_o, original + payload_off_o, payload_size);

            /* 4. shellcode */
            memcpy(outbuf + magic_start, original + magic_start, shellcode_sz);

            /* 5. patch_data + padding */
            memcpy(outbuf + magic_start + shellcode_sz, patch_data, total_bytes);
            memset(outbuf + magic_start + shellcode_sz + total_bytes, 0,
                   patch_data_max - total_bytes);

            /* 6. footer – increment all offsets by add_delta */
            {
                sprdsignedimageheader *old_f = (sprdsignedimageheader *)(original + footer_off_o);
                sprdsignedimageheader *new_f = (sprdsignedimageheader *)(outbuf + footer_off_o + add_delta);
                memcpy(new_f, old_f, sizeof(sprdsignedimageheader));
                new_f->cert_offset += add_delta;
                if (new_f->priv_size)
                    new_f->priv_offset += add_delta;
                if (new_f->cert_dbg_prim_size)
                    new_f->cert_dbg_prim_offset += add_delta;
                if (new_f->cert_dbg_developer_size)
                    new_f->cert_dbg_developer_offset += add_delta;
            }

            /* 7. remaining cert data */
            {
                int after_footer = footer_off_o + (int)sizeof(sprdsignedimageheader);
                int remaining = os - after_footer;
                if (remaining > 0)
                    memcpy(outbuf + after_footer + add_delta, original + after_footer, remaining);
            }
        }
        else
        {
            /* --- in-place overwrite (no expansion needed) --- */
            memcpy(outbuf, original, os);
            memcpy(outbuf + patch_data_off, patch_data, total_bytes);
            memset(outbuf + patch_data_off + total_bytes, 0, patch_data_max - total_bytes);
        }

        if (savefile(output_path, outbuf, new_size) != 0)
        {
            fprintf(stderr, "Error: failed to write '%s'\n", output_path);
            free(outbuf);
            free(patch_data);
            free(entries);
            free(patched);
            free(original);
            return 1;
        }
        free(outbuf);
        printf("\nPatched file saved to: %s (%d bytes)\n", output_path, new_size);
    }

    /* ---- print summary ---- */
    printf("\n=== Patch Summary ===\n");
    for (int i = 0; i < entry_count && i < 50; i++)
    {
        printf("  [%d] addr=0x%08X  len=%d words",
               i, entries[i].addr, entries[i].length);
        if (entries[i].length <= 4)
        {
            printf("  data:");
            for (uint32_t w = 0; w < entries[i].length; w++)
                printf(" 0x%08X", entries[i].data[w]);
        }
        printf("\n");
    }
    if (entry_count > 50)
        printf("  ... and %d more entries\n", entry_count - 50);

    free(patch_data);
    free(entries);
    free(patched);
    free(original);
    return 0;
}
