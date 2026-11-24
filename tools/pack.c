#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <arpa/inet.h>


#define KEYS 16
#define ITEMS 256


struct List
{
    char key[32];
    char items[ITEMS][128];
    int n;

};


struct Range
{
    uint32_t start;
    uint32_t end;

};


static struct List lists[KEYS];
static int nlists;
static struct Range* ranges;
static int nranges;
static int cap;
static uint64_t* hashes;
static int nhashes;
static int hcap;


static char* trim(char* s)
{
    char* e;

    while (isspace((unsigned char)*s))
    {
        s++;
    }

    e = s + strlen(s);

    while (e > s && isspace((unsigned char)e[-1]))
    {
        *--e = '\0';
    }

    if (e - s >= 2 && (*s == '"' || *s == '\'') && e[-1] == *s)
    {
        e[-1] = '\0';
        s++;
    }

    return s;
}


static void yaml(const char* path)
{
    FILE* f = fopen(path, "r");
    char line[512];
    struct List* now = NULL;

    if (f == NULL)
    {
        perror(path);
        exit(1);
    }

    while (fgets(line, sizeof line, f) != NULL)
    {
        char* hash = strchr(line, '#');
        char* s;

        if (hash != NULL)
        {
            *hash = '\0';
        }

        s = trim(line);

        if (*s == '\0')
        {
            continue;
        }

        if (s[0] == '-')
        {
            if (now != NULL && now->n < ITEMS)
            {
                snprintf(now->items[now->n++], 128, "%s", trim(s + 1));
            }

            continue;
        }

        if (s[strlen(s) - 1] == ':' && nlists < KEYS)
        {
            s[strlen(s) - 1] = '\0';
            now = &lists[nlists++];
            snprintf(now->key, sizeof now->key, "%s", trim(s));
        }
    }

    fclose(f);
}


static struct List* get(const char* key)
{
    static struct List none;

    for (int i = 0; i < nlists; i++)
    {
        if (strcmp(lists[i].key, key) == 0)
        {
            return &lists[i];
        }
    }

    return &none;
}


static void keep(uint32_t start, uint32_t end)
{
    if (nranges == cap)
    {
        cap = cap ? cap * 2 : 4096;
        ranges = realloc(ranges, cap * sizeof *ranges);
    }

    ranges[nranges].start = start;
    ranges[nranges].end = end;
    nranges++;
}


static int cidr(const char* s, uint32_t* start, uint32_t* end)
{
    char net[32];
    int bits = 32;
    struct in_addr a;
    uint32_t mask;

    if (sscanf(s, "%31[^/]/%d", net, &bits) < 1 || inet_pton(AF_INET, net, &a) != 1)
    {
        return 0;
    }

    if (bits < 0 || bits > 32)
    {
        return 0;
    }

    mask = bits == 0 ? 0 : 0xFFFFFFFFu << (32 - bits);
    *start = ntohl(a.s_addr) & mask;
    *end = *start | ~mask;

    return 1;
}


static int wanted(const char* cc)
{
    struct List* c = get("countries");

    for (int i = 0; i < c->n; i++)
    {
        if (strcasecmp(c->items[i], cc) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static void registry(const char* path)
{
    FILE* f = fopen(path, "r");
    char line[512];
    int found = 0;

    if (f == NULL)
    {
        printf("Can't open %s, run tools/fetch.sh first!!\n", path);
        exit(1);
    }

    while (fgets(line, sizeof line, f) != NULL)
    {
        char* field[8];
        int n = 0;
        char* p = line;
        struct in_addr a;
        unsigned long count;

        while (n < 8 && (field[n] = strsep(&p, "|")) != NULL)
        {
            n++;
        }

        if (n < 7 || strcmp(field[2], "ipv4") != 0 || !wanted(field[1]))
        {
            continue;
        }

        if (strncmp(field[6], "allocated", 9) != 0 && strncmp(field[6], "assigned", 8) != 0)
        {
            continue;
        }

        count = strtoul(field[4], NULL, 10);

        if (inet_pton(AF_INET, field[3], &a) != 1 || count == 0)
        {
            continue;
        }

        keep(ntohl(a.s_addr), ntohl(a.s_addr) + (uint32_t)(count - 1));
        found++;
    }

    fclose(f);
    printf("%s: %d ranges\n", path, found);
}


static void networks(long asn)
{
    char path[64];
    char line[64];
    FILE* f;
    int found = 0;

    snprintf(path, sizeof path, "data/as%ld", asn);
    f = fopen(path, "r");

    if (f == NULL)
    {
        printf("Can't open %s, run tools/fetch.sh first!!\n", path);
        exit(1);
    }

    while (fgets(line, sizeof line, f) != NULL)
    {
        uint32_t s;
        uint32_t e;

        line[strcspn(line, "\r\n")] = '\0';

        if (cidr(line, &s, &e))
        {
            keep(s, e);
            found++;
        }
    }

    fclose(f);
    printf("%s: %d ranges always allowed\n", path, found);
}


static int order(const void* a, const void* b)
{
    const struct Range* x = a;
    const struct Range* y = b;

    return x->start < y->start ? -1 : x->start > y->start;
}


static void merge(void)
{
    int out = 0;

    qsort(ranges, nranges, sizeof *ranges, order);

    for (int i = 0; i < nranges; i++)
    {
        if (out > 0 && (uint64_t)ranges[i].start <= (uint64_t)ranges[out - 1].end + 1)
        {
            if (ranges[i].end > ranges[out - 1].end)
            {
                ranges[out - 1].end = ranges[i].end;
            }
        }
        else
        {
            ranges[out++] = ranges[i];
        }
    }

    nranges = out;
}


static uint64_t fnv(const char* s)
{
    uint64_t h = 14695981039346656037ULL;

    while (*s)
    {
        h ^= (unsigned char)tolower((unsigned char)*s++);
        h *= 1099511628211ULL;
    }

    return h;
}


static int valid(const char* d)
{
    if (strchr(d, '.') == NULL || strlen(d) > 253)
    {
        return 0;
    }

    if (strcmp(d, "localhost.localdomain") == 0 || strcmp(d, "0.0.0.0") == 0)
    {
        return 0;
    }

    for (const char* p = d; *p; p++)
    {
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-' && *p != '_')
        {
            return 0;
        }
    }

    return 1;
}


static int spared(const char* d)
{
    struct List* a = get("allow_domains");

    for (int i = 0; i < a->n; i++)
    {
        if (strcasecmp(a->items[i], d) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static void hosts(const char* path)
{
    FILE* f = fopen(path, "r");
    char line[1024];
    int found = 0;

    if (f == NULL)
    {
        printf("Can't open %s, run tools/fetch.sh first!!\n", path);
        exit(1);
    }

    while (fgets(line, sizeof line, f) != NULL)
    {
        char one[300];
        char two[300];
        char* hash = strchr(line, '#');
        const char* d;
        int n;

        if (hash != NULL)
        {
            *hash = '\0';
        }

        n = sscanf(line, "%299s %299s", one, two);

        if (n == 2 && (strcmp(one, "0.0.0.0") == 0 || strcmp(one, "127.0.0.1") == 0))
        {
            d = two;
        }
        else if (n == 1)
        {
            d = one;
        }
        else
        {
            continue;
        }

        if (!valid(d) || spared(d))
        {
            continue;
        }

        if (nhashes == hcap)
        {
            hcap = hcap ? hcap * 2 : 65536;
            hashes = realloc(hashes, hcap * sizeof *hashes);
        }

        hashes[nhashes++] = fnv(d);
        found++;
    }

    fclose(f);
    printf("%s: %d domains\n", path, found);
}


static int compare(const void* a, const void* b)
{
    uint64_t x = *(const uint64_t*)a;
    uint64_t y = *(const uint64_t*)b;

    return x < y ? -1 : x > y;
}


static void put32(FILE* f, uint32_t v)
{
    unsigned char b[4] = {v & 255, (v >> 8) & 255, (v >> 16) & 255, v >> 24};

    fwrite(b, 1, 4, f);
}


static int covered(uint32_t a)
{
    for (int i = 0; i < nranges; i++)
    {
        if (a >= ranges[i].start && a <= ranges[i].end)
        {
            return 1;
        }
    }

    return 0;
}


int main()
{
    struct List* l;
    FILE* f;
    int out = 0;

    yaml("policy/policy.yaml");

    l = get("registries");

    for (int i = 0; i < l->n; i++)
    {
        registry(l->items[i]);
    }

    l = get("allow_ips");

    for (int i = 0; i < l->n; i++)
    {
        uint32_t s;
        uint32_t e;

        if (cidr(l->items[i], &s, &e))
        {
            keep(s, e);
        }
    }

    l = get("allow_asns");

    for (int i = 0; i < l->n; i++)
    {
        networks(atol(l->items[i]));
    }

    merge();

    l = get("blocklists");

    for (int i = 0; i < l->n; i++)
    {
        hosts(l->items[i]);
    }

    qsort(hashes, nhashes, sizeof *hashes, compare);

    for (int i = 0; i < nhashes; i++)
    {
        if (out == 0 || hashes[i] != hashes[out - 1])
        {
            hashes[out++] = hashes[i];
        }
    }

    nhashes = out;

    f = fopen("firmware/main/gen/ranges.bin", "wb");
    put32(f, nranges);

    for (int i = 0; i < nranges; i++)
    {
        put32(f, ranges[i].start);
        put32(f, ranges[i].end);
    }

    fclose(f);

    f = fopen("firmware/main/gen/domains.bin", "wb");
    put32(f, nhashes);

    for (int i = 0; i < nhashes; i++)
    {
        put32(f, (uint32_t)hashes[i]);
        put32(f, (uint32_t)(hashes[i] >> 32));
    }

    fclose(f);

    f = fopen("firmware/main/gen/policy.c", "w");
    fprintf(f, "#include <stdint.h>\n\n\n");
    fprintf(f, "struct Range\n{\n    uint32_t start;\n    uint32_t end;\n\n};\n\n\n");

    l = get("upstream_dns");
    fprintf(f, "const uint32_t upstream[] =\n{\n");

    for (int i = 0; i < l->n; i++)
    {
        struct in_addr a;

        if (inet_pton(AF_INET, l->items[i], &a) == 1)
        {
            fprintf(f, "    0x%08xu,\n", ntohl(a.s_addr));

            if (!covered(ntohl(a.s_addr)))
            {
                printf("Heads up!! upstream %s is outside the allowed countries\n", l->items[i]);
            }
        }
    }

    fprintf(f, "};\n\n\nconst int nupstream = %d;\n\n\n", l->n);

    l = get("block_ports");
    fprintf(f, "const int ports[] =\n{\n");

    for (int i = 0; i < l->n; i++)
    {
        fprintf(f, "    %d,\n", atoi(l->items[i]));
    }

    fprintf(f, "    -1,\n};\n\n\nconst int nports = %d;\n\n\n", l->n);

    l = get("deny_ips");
    fprintf(f, "const struct Range deny[] =\n{\n");
    out = 0;

    for (int i = 0; i < l->n; i++)
    {
        uint32_t s;
        uint32_t e;

        if (cidr(l->items[i], &s, &e))
        {
            fprintf(f, "    {0x%08xu, 0x%08xu},\n", s, e);
            out++;
        }
    }

    fprintf(f, "    {0, 0},\n};\n\n\nconst int ndeny = %d;", out);
    fclose(f);

    printf("Packed %d allowed ranges and %d blocked domains!!\n", nranges, nhashes);

    return 0;
}