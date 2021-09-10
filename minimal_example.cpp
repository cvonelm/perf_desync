#include <cmath>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

extern "C"
{
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
}

struct perf_record
{
    struct perf_event_header header;
    uint64_t time;
};

pid_t child_pid;
struct perf_event_attr common_attrs()
{
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(struct perf_event_attr));

    attr.size = sizeof(struct perf_event_attr);
    attr.use_clockid = 1;
    attr.clockid = CLOCK_MONOTONIC_RAW;
    attr.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_TIME;
    attr.watermark = 1;
    attr.wakeup_events = 1;
    return attr;
}

int perf_event_open(struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd,
                    unsigned long flags)
{
    int ret;

    ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
    return ret;
}
void tracing(int fd)
{
    struct perf_event_mmap_page* mmap_page = (struct perf_event_mmap_page*)mmap(
        NULL, (16 + 1) * getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (mmap_page == MAP_FAILED)
    {
        std::cerr << strerror(errno) << std::endl;
        return;
    }

    char* data = (char*)mmap_page + mmap_page->data_offset;

    struct pollfd fds;

    if (fd == -1)
    {
        std::cerr << strerror(errno) << std::endl;
        return;
    }
    memset(&fds, 0, sizeof(struct pollfd));
    fds.fd = fd;
    fds.events = POLLIN;

    while (1)
    {
        poll(&fds, 1, -1);
        auto cur_head = mmap_page->data_head;
        auto cur_tail = mmap_page->data_tail;

        while (cur_tail < cur_head)
        {
            auto event_header = (struct perf_event_header*)(data + cur_tail);
            if (event_header->type == PERF_RECORD_SWITCH ||
                event_header->type == PERF_RECORD_SAMPLE)
            {
                auto event = (struct perf_record*)event_header;
                std::cout << event->header.type << ", " << event->time << std::endl;
            }
            cur_tail += event_header->size;
        }

        mmap_page->data_tail = cur_tail;
    }
}
void read_switch_events()
{
    struct perf_event_attr attr = common_attrs();
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_DUMMY;
    attr.sample_id_all = 1;
    attr.context_switch = 1;

    int fd = perf_event_open(&attr, child_pid, -1, -1, 0);
    if (fd == -1)
    {
        std::cerr << strerror(errno) << std::endl;
        return;
    }

    tracing(fd);
}

void read_tracepoints_events()
{
    struct perf_event_attr attr = common_attrs();
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.config = 316; // sched switch;
    attr.sample_id_all = 1;

    int fd = perf_event_open(&attr, child_pid, -1, -1, 0);
    if (fd == -1)
    {
        std::cerr << strerror(errno) << std::endl;
        return;
    }

    tracing(fd);
}

void compute()
{
    while (1)
    {
        sleep(2);
        double number = rand() / RAND_MAX;
        for (int i = 0; i < 100; i++)
        {
            sqrt(number);
        }
    }
}

int main(void)
{
    std::cout << "type, tp" << std::endl;
    pid_t pid = fork();

    if (pid == 0)
    {
        compute();
    }
    else
    {
        child_pid = pid;
        std::thread t1(read_switch_events);
        std::thread t2(read_tracepoints_events);
        t1.join();
    }

    return 0;
}
