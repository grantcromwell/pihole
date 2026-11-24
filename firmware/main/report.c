#include <stdio.h>
#include <unistd.h>
#include <pthread.h>


extern volatile unsigned long passed;
extern volatile unsigned long foreign;
extern volatile unsigned long ported;
extern volatile unsigned long stranger;


static void* report(void* arg)
{
    while (1)
    {
        sleep(60);
        printf("Packets passed %lu, stopped: %lu outside US, %lu sneaky DNS, %lu strangers\n",
            passed, foreign, ported, stranger);
    }

    return NULL;
}


void stats(void)
{
    pthread_t t;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 3072);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &attr, report, NULL);
}