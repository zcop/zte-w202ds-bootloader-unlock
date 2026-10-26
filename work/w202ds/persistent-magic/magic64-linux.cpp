#include <unistd.h>
#include <limits.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <filesystem>

typedef struct
{
    uint32_t mMagicNum;       // "BTHD"=="0x42544844"=="boothead"
    uint32_t mVersion;        // 1
    uint8_t mPayloadHash[32]; // sha256 hash value
    uint64_t mImgAddr;        // image loaded address
    uint32_t mImgSize;        // image size
    uint32_t is_packed;       // packed image flag 0:false 1:true
    uint32_t mFirmwareSize;   // runtime firmware size
    uint8_t reserved[452];    // 452 + 15*4 = 512
} sys_img_header;

#define MAGIC_SIZE 8
typedef struct sprdsignedimageheader
{

    /* Magic number */
    uint8_t magic[MAGIC_SIZE];
    /* Version of this header format */
    uint32_t header_version_major;
    /* Version of this header format */
    uint32_t header_version_minor;

    /*image body, plain or cipher text */
    uint64_t payload_size;
    uint64_t payload_offset;

    /*offset from itself start */
    /*content certification size,if 0,ignore */
    uint64_t cert_size;
    uint64_t cert_offset;

    /*(opt)private content size,if 0,ignore */
    uint64_t priv_size;
    uint64_t priv_offset;

    /*(opt)debug/rma certification primary size,if 0,ignore */
    uint64_t cert_dbg_prim_size;
    uint64_t cert_dbg_prim_offset;

    /*(opt)debug/rma certification second size,if 0,ignore */
    uint64_t cert_dbg_developer_size;
    uint64_t cert_dbg_developer_offset;

} sprdsignedimageheader;

static uint8_t *loadfile(const char *fn, int32_t *num, int32_t extra)
{
    size_t n, j = 0;
    uint8_t *buf = 0;
    FILE *filename = fopen(fn, "rb");
    if (filename)
    {
        fseek(filename, 0, SEEK_END);
        n = ftell(filename);
        if (n)
        {
            fseek(filename, 0, SEEK_SET);
            buf = (uint8_t *)malloc(n + extra);
            if (buf)
            {
                j = fread(buf, 1, n, filename);
                if (extra)
                    memset(&buf[n], 0, extra);
            }
        }
        fclose(filename);
    }
    if (num)
        *num = j;
    return buf;
}

uint8_t *compile_magic(const std::string &strArm64Asm, int32_t size, int32_t *magic_length_ptr)
{
    char szFileName[PATH_MAX] = {0};
    ssize_t exe_len = readlink("/proc/self/exe", szFileName, sizeof(szFileName) - 1);
    if (exe_len > 0) szFileName[exe_len] = '\0';
    std::string strMyPath = szFileName;
    strMyPath = strMyPath.substr(0, strMyPath.find_last_of('/') + 1);

    std::string asmFilePath = strMyPath + "aarch64-linux-android-as";
    if (!std::filesystem::exists(asmFilePath))
    {
        std::cerr << "Error: aarch64-linux-android-as not found. Please extract this file from the Android NDK." << std::endl;
        exit(EXIT_FAILURE);
    }

    std::ofstream inputFile;
    inputFile.open(strMyPath + "input.txt", std::ios_base::out | std::ios_base::trunc);
    inputFile << strArm64Asm;
    inputFile.close();

    std::filesystem::remove(std::string(strMyPath + "linker.lds"));
    std::filesystem::remove(std::string(strMyPath + "magic.o"));
    std::filesystem::remove(std::string(strMyPath + "magic.elf"));
    std::filesystem::remove(std::string(strMyPath + "magic.bin"));
    std::stringstream sstrLds;
    sstrLds
        << "OUTPUT_FORMAT(\"elf64-littleaarch64\")" << std::endl
        << "OUTPUT_ARCH(aarch64)" << std::endl
        << "ENTRY(_start)" << std::endl
        << "SECTIONS" << std::endl
        << "{" << std::endl
        << ". = 0x" << std::hex << size + 0x10 << ";" << std::endl
        << ".text : { *(.text*) }" << std::endl
        << "PROVIDE(label_init = 0);" << std::endl
        << "PROVIDE(label_patch = 0x" << std::hex << size + 0x80 << ");" << std::endl
        << "}" << std::endl;
    std::string strLds = sstrLds.str();
    std::cout << std::endl
              << strLds << std::endl;
    inputFile.open(strMyPath + "linker.lds", std::ios_base::out | std::ios_base::trunc);
    inputFile << strLds;
    inputFile.close();

    std::string cmd;
    cmd = strMyPath + "aarch64-linux-android-as -o " + strMyPath + "magic.o " + strMyPath + "input.txt";
    system(cmd.c_str());
    cmd = strMyPath + "aarch64-linux-android-ld -o " + strMyPath + "magic.elf " + "-T " + strMyPath + "linker.lds " + strMyPath + "magic.o";
    system(cmd.c_str());
    cmd = strMyPath + "aarch64-linux-android-objcopy -O binary " + strMyPath + "magic.elf " + strMyPath + "magic.bin";
    system(cmd.c_str());
    return loadfile((strMyPath + "magic.bin").c_str(), magic_length_ptr, 0);
}

#define ERR_EXIT(...)                 \
    do                                \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
        exit(1);                      \
    } while (0)

int main(int argc, char *argv[])
{
    if (argc < 2)
        ERR_EXIT("Usage: %s <file>\n", argv[0]);

    char *filename = argv[1];
    uint8_t *mem;
    int32_t size = 0;
    mem = loadfile(filename, &size, 0);
    uint8_t *mem0 = mem;
    int32_t size0 = size;
    if (!mem)
        ERR_EXIT("loadfile(\"%s\") failed\n", filename);
    // if (remove(filename)) ERR_EXIT("Failed to delete the file.\n");
    printf("file size: 0x%x\n", size);

    if (!(*(uint32_t *)&mem[0x30]))
        ERR_EXIT("The file is not sprd trusted firmware\n");
    if (*(int32_t *)&mem[0x30] + 0x200 >= size)
        ERR_EXIT("The file is not complete\n");
    if (*(uint32_t *)&mem[0x30] != *(uint32_t *)&mem[(*(uint32_t *)&mem[0x30]) + 0x200 + 0x10])
        ERR_EXIT("The file is already patched\n");
    size = *(uint32_t *)&mem[0x30];
    printf("payload size: 0x%x\n", size);

    // make magic
    std::stringstream sstrAsm;
    sstrAsm
        << ".section .text" << std::endl
        << ".globl _start" << std::endl
        << "_start :" << std::endl
        << "ADRP X9, label_init" << std::endl
        << "ADD X10, X9, #0x10" << std::endl
        << "MOV X11, #" << ((size / 8) & 0xFFFF0000) << std::endl
        << "MOVK X11, #" << ((size / 8) & 0xFFFF) << std::endl
        << "MOV X12, #0" << std::endl
        << "SUBS X13, X12, X11" << std::endl
        << "B.CS #0x1C" << std::endl
        << "LDR X13, [X10,X12,LSL#3]" << std::endl
        << "STR X13, [X9,X12,LSL#3]" << std::endl
        << "IC IALLUIS" << std::endl
        << "ISB" << std::endl
        << "ADD X12, X12, #1" << std::endl
        << "B #-0x1C" << std::endl
        << "ADRP X9, label_patch" << std::endl
        << "ADD X9, X9, #" << ((size + 0x80) & 0xFFF) << std::endl
        << "LDR W10, [X9],#4" << std::endl
        << "CBZ X10, #0x2C" << std::endl
        << "LDR W11, [X9],#4" << std::endl
        << "MOV X12, #0" << std::endl
        << "SUBS X13, X12, X11" << std::endl
        << "B.CS #-0x14" << std::endl
        << "LDR W13, [X9],#4" << std::endl
        << "STR W13, [X10],#4" << std::endl
        << "IC IALLUIS" << std::endl
        << "ISB" << std::endl
        << "ADD X12, X12, #1" << std::endl
        << "B #-0x1C" << std::endl
        << "B #" << -(size + 0x7C) << std::endl;

    std::string strAsmCode = sstrAsm.str();
    std::cout << std::endl
              << strAsmCode << std::endl;

    int32_t magic_length;
    uint8_t *magic_buf = compile_magic(strAsmCode, size, &magic_length);
    if (magic_length != 0x70)
        ERR_EXIT("length of magic error.\n");
    int add_lenth = (0x10 + magic_length + 0xFF) & 0xFFFFFF00;

    // FILE* file = fopen(filename, "wb");
    FILE *file = fopen("patched.bin", "wb");
    if (file == NULL)
        ERR_EXIT("Failed to create the file.\n");

    // HEADER
    sys_img_header *img_h = (sys_img_header *)mem;
    img_h->mImgSize += add_lenth;
    if (0x200 != fwrite(mem, sizeof(unsigned char), 0x200, file))
        ERR_EXIT("Failed to write payload.\n");
    mem += 0x200;

    // jump2magic
    unsigned char tmp[16] = {0};
    tmp[0] = (size + 0x10) / 4;
    tmp[1] = ((size + 0x10) / 4) >> 8;
    tmp[2] = ((size + 0x10) / 4) >> 16;
    tmp[3] = 0x14;
    if (0x10 != fwrite(tmp, sizeof(unsigned char), 0x10, file))
        ERR_EXIT("Failed to write jump_code.\n");

    // payload
    if (size != fwrite(mem, sizeof(unsigned char), size, file))
        ERR_EXIT("Failed to write payload.\n");
    mem += size;

    std::cout << std::hex << size << std::endl;

    // magic
    uint8_t *temp = (uint8_t *)realloc(magic_buf, add_lenth - 0x10);
    if (temp == NULL)
    {
        free(magic_buf);
        ERR_EXIT("Failed to reallocate memory");
    }
    magic_buf = temp;
    memset(magic_buf + magic_length, 0, add_lenth - 0x10 - magic_length);
    if (add_lenth - 0x10 != fwrite(magic_buf, sizeof(unsigned char), add_lenth - 0x10, file))
        ERR_EXIT("Failed to write magic.\n");
    free(magic_buf);

    std::cout << std::hex << add_lenth - 0x10 << std::endl;

    // FOOTER
    sprdsignedimageheader *img_f = (sprdsignedimageheader *)mem;
    img_f->payload_offset = 0x210;
    img_f->cert_offset += add_lenth;
    if (img_f->priv_size)
        img_f->priv_offset += add_lenth;
    if (img_f->cert_dbg_prim_size)
        img_f->cert_dbg_prim_offset += add_lenth;
    if (img_f->cert_dbg_developer_size)
        img_f->cert_dbg_developer_offset += add_lenth;
    if (0x60 != fwrite(img_f, sizeof(unsigned char), 0x60, file))
        ERR_EXIT("Failed to write the footer.\n");
    mem += 0x60;

    // remaining
    int remaining = size0 - 0x260 - size;
    if (remaining != fwrite(mem, sizeof(unsigned char), remaining, file))
        ERR_EXIT("Failed to write cert.\n");

    std::cout << std::hex << remaining << std::endl;

    fclose(file);
    free(mem0);
    return 0;
}