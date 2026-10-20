// kmcli - KeyMint TA raw cmd (ku mode only).
// Usage: kmcli <cmd_hex> <payload_hex> <out_path>
// Request: LE32 cmd || payload. Response: LE32 retcode || LE32 len || payload.
//
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned long long uint64_t;
typedef unsigned long size_t;
#define NULL ((void *)0)

int printf(const char *fmt, ...);
void *memset(void *s, int c, size_t n);
unsigned long strtoul(const char *nptr, char **endptr, int base);
extern void *dlopen(const char *filename, int flags);
extern void *dlsym(void *handle, const char *symbol);
extern char *dlerror(void);
extern void *malloc(size_t);
extern int setvbuf(void *stream, char *buf, int mode, size_t size);
extern void *stdout;
extern int open(const char *path, int flags, int mode);
extern long write(int fd, const void *buf, size_t n);
extern int close(int fd);

#define O_WRONLY_CREAT_TRUNC (0100 | 0001 | 01000)
#define _IONBF 2
#define RTLD_NOW 2
#define RTLD_GLOBAL 0x100

typedef void (*ku_ctor_fn)(void *self, int32_t security_level);
typedef void (*ku_dtor_fn)(void *self);
typedef int (*ku_send_cmd_fn)(void *self, void *cmd, uint32_t cmd_len, void *rsp, uint32_t rsp_len);

extern int __libc_init(void *raw_args, void (*onexit)(void),
                       int (*slingshot)(int, char **, char **), void *structors);
extern void exit(int status);
int main(int argc, char **argv, char **envp);

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t hex2bin(const char *hex, uint8_t *out, size_t outcap) {
    size_t n = 0;
    while (hex[0] && hex[1]) {
        if (hex[0] == ' ' || hex[0] == ':') { hex++; continue; }
        int hi = hexval(hex[0]), lo = hexval(hex[1]);
        if (hi < 0 || lo < 0 || n >= outcap) break;
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

static void put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int main(int argc, char **argv, char **envp) {
    (void)envp;
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 4) {
        printf("usage: kmcli <cmd_hex> <payload_hex> <out_path>\n");
        return 1;
    }

    uint32_t cmd = (uint32_t)strtoul(argv[1], NULL, 16);
    const char *payload_hex = argv[2];
    const char *outpath = argv[3];

    uint8_t *req = (uint8_t *)malloc(0xa000);
    uint8_t *rsp = (uint8_t *)malloc(0xa000);
    if (!req || !rsp) { printf("malloc failed\n"); return 2; }
    memset(req, 0, 0xa000);
    memset(rsp, 0, 0xa000);
    put_le32(req, cmd);
    size_t plen = hex2bin(payload_hex, req + 4, 0x9000);
    uint32_t req_len = 4 + (uint32_t)plen;
    printf("cmd=0x%x payload_len=%zu req_len=%u\n", cmd, plen, req_len);

    void *lib = dlopen("/vendor/lib64/libkeymasterdeviceutils.so", RTLD_NOW | RTLD_GLOBAL);
    if (!lib) { printf("dlopen deviceutils failed: %s\n", dlerror()); return 2; }

    ku_ctor_fn ctor = (ku_ctor_fn)dlsym(
        lib, "_ZN14keymasterutils14KeymasterUtilsC1E26keymaster_security_level_t");
    ku_dtor_fn dtor = (ku_dtor_fn)dlsym(
        lib, "_ZN14keymasterutils14KeymasterUtilsD1Ev");
    ku_send_cmd_fn ksend = (ku_send_cmd_fn)dlsym(
        lib, "_ZN14keymasterutils14KeymasterUtils8send_cmdEPvjS1_j");
    if (!ctor || !ksend) { printf("dlsym failed\n"); return 2; }

    void *ku = malloc(0x40);
    if (!ku) { printf("malloc failed\n"); return 2; }
    memset(ku, 0, 0x40);
    ctor(ku, 1); /* TRUSTED_ENVIRONMENT */

    int ret = ksend(ku, req, req_len, rsp, 0xa000);
    printf("KeymasterUtils::send_cmd -> %d\n", ret);
    if (ret != 0) {
        if (dtor) dtor(ku);
        return 5;
    }

    uint32_t rc = get_le32(rsp);
    uint32_t outlen = get_le32(rsp + 4);
    printf("TA retcode = 0x%08x (%d), payload_len = %u\n", rc, (int32_t)rc, outlen);
    if (outlen > 0xa000 - 8) outlen = 0xa000 - 8;

    if (outlen) {
        int fd = open(outpath, O_WRONLY_CREAT_TRUNC, 0644);
        if (fd >= 0) {
            write(fd, rsp + 8, outlen);
            close(fd);
            printf("payload -> %s (%u bytes)\n", outpath, outlen);
        }
    }

    if (dtor) dtor(ku);
    return 0;
}
