#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/random.h>


#define PENDING 64
#define WAIT 5


struct Pending
{
    int used;
    uint16_t ours;
    uint16_t theirs;
    struct sockaddr_in from;
    time_t at;

};


extern const uint32_t upstream[];
extern const int nupstream;
extern const uint8_t domains[] asm("_binary_domains_bin_start");


int listed(const char* name);
int question(const uint8_t* q, int len, char* name, int* qtype, int* end);
int sinkhole(const uint8_t* q, int end, int qtype, uint8_t* out);
int calm(uint32_t ip);


static struct Pending pending[PENDING];
static uint32_t home;
static uint32_t mask;
static int turn;
static unsigned long asked;
static unsigned long blocked;


static uint32_t word(const uint8_t* p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
}


static void ask(int up, uint8_t* buf, int n, struct sockaddr_in* from)
{
    struct sockaddr_in to;
    int slot = -1;
    uint16_t id;

    for (int i = 0; i < PENDING && slot < 0; i++)
    {
        if (!pending[i].used)
        {
            slot = i;
        }
    }

    if (slot < 0)
    {
        return;
    }

    do
    {
        if (getrandom(&id, sizeof id, 0) != sizeof id)
        {
            id = 0;
        }

        for (int i = 0; i < PENDING; i++)
        {
            if (pending[i].used && pending[i].ours == id)
            {
                id = 0;
            }
        }
    }
    while (id == 0);

    pending[slot].used = 1;
    pending[slot].ours = id;
    pending[slot].theirs = (buf[0] << 8) | buf[1];
    pending[slot].from = *from;
    pending[slot].at = time(NULL);

    buf[0] = id >> 8;
    buf[1] = id & 255;

    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(53);
    to.sin_addr.s_addr = htonl(upstream[turn]);
    turn = (turn + 1) % nupstream;

    sendto(up, buf, n, 0, (struct sockaddr*)&to, sizeof to);
}


static void answer(int in, uint8_t* buf, int n, struct sockaddr_in* src)
{
    uint16_t id;
    int known = 0;

    if (n < 12 || src->sin_port != htons(53))
    {
        return;
    }

    for (int i = 0; i < nupstream; i++)
    {
        if (ntohl(src->sin_addr.s_addr) == upstream[i])
        {
            known = 1;
        }
    }

    if (!known)
    {
        return;
    }

    id = (buf[0] << 8) | buf[1];

    for (int i = 0; i < PENDING; i++)
    {
        if (pending[i].used && pending[i].ours == id)
        {
            buf[0] = pending[i].theirs >> 8;
            buf[1] = pending[i].theirs & 255;
            sendto(in, buf, n, 0, (struct sockaddr*)&pending[i].from, sizeof pending[i].from);
            pending[i].used = 0;
            return;
        }
    }
}


static void* serve(void* arg)
{
    struct sockaddr_in a;
    uint8_t buf[1500];
    uint8_t out[600];
    int in = socket(AF_INET, SOCK_DGRAM, 0);
    int up = socket(AF_INET, SOCK_DGRAM, 0);
    time_t last = time(NULL);

    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(53);
    a.sin_addr.s_addr = htonl(home);

    if (bind(in, (struct sockaddr*)&a, sizeof a) < 0)
    {
        printf("Couldn't start the DNS filter!!\n");
        return NULL;
    }

    printf("DNS filter is up with %lu blocked domains!!\n", (unsigned long)word(domains));

    while (1)
    {
        struct timeval tv = {1, 0};
        fd_set rd;

        FD_ZERO(&rd);
        FD_SET(in, &rd);
        FD_SET(up, &rd);

        if (select((in > up ? in : up) + 1, &rd, NULL, NULL, &tv) > 0)
        {
            struct sockaddr_in from;
            socklen_t flen = sizeof from;
            int n;

            if (FD_ISSET(in, &rd))
            {
                char name[256];
                int qtype;
                int end;

                n = recvfrom(in, buf, sizeof buf, 0, (struct sockaddr*)&from, &flen);

                if (n > 0 && n <= 512 && (ntohl(from.sin_addr.s_addr) & mask) == (home & mask)
                    && calm(from.sin_addr.s_addr) && question(buf, n, name, &qtype, &end))
                {
                    asked++;

#ifdef CONFIG_LOG_LOOKUPS
                    printf("Lookup %s\n", name);
#endif

                    if (listed(name))
                    {
                        blocked++;
                        printf("Blocked %s\n", name);
                        n = sinkhole(buf, end, qtype, out);
                        sendto(in, out, n, 0, (struct sockaddr*)&from, flen);
                    }
                    else
                    {
                        ask(up, buf, n, &from);
                    }
                }
            }

            if (FD_ISSET(up, &rd))
            {
                flen = sizeof from;
                n = recvfrom(up, buf, sizeof buf, 0, (struct sockaddr*)&from, &flen);

                if (n > 0)
                {
                    answer(in, buf, n, &from);
                }
            }
        }

        if (time(NULL) - last >= 60)
        {
            last = time(NULL);
            printf("DNS: %lu lookups, %lu blocked\n", asked, blocked);
        }

        for (int i = 0; i < PENDING; i++)
        {
            if (pending[i].used && time(NULL) - pending[i].at > WAIT)
            {
                pending[i].used = 0;
            }
        }
    }

    return NULL;
}


void dns(uint32_t ip, uint32_t m)
{
    pthread_t t;
    pthread_attr_t attr;

    home = ip;
    mask = m;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 6144);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &attr, serve, NULL);
}