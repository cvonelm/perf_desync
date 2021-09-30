#include <atomic>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>

extern "C"
{
#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
}

struct perf_record
{
    struct perf_event_header header;
    uint64_t time;
};

std::atomic<bool> compute_running;

std::mutex mutex;

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

int perf_event_open(struct perf_event_attr* hw_event)
{
    //One of  those has to be -1;
    pid_t pid = child_pid;
    int cpuid = -1;

    return  syscall(__NR_perf_event_open, hw_event, pid, cpuid, -1, 0);
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

    while (compute_running)
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
                std::lock_guard<std::mutex> lock(mutex);
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
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_INSTRUCTIONS;
    attr.sample_period = 11010113;
    attr.sample_id_all = 1;
    attr.context_switch = 1;

    int fd = perf_event_open(&attr);
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

    // the tracepoint id isn't static so we have to look it up every time
    // sadly this means that this has to be run with root rights even with
    // kernel.perf_event_paranoid set to -1
    
    std::ifstream tp_id_file;
    tp_id_file.exceptions ( std::ifstream::failbit | std::ifstream::badbit  );

    tp_id_file.open("/sys/kernel/debug/tracing/events/syscalls/sys_enter_fchmod/id");
    tp_id_file >> attr.config;

    attr.sample_id_all = 1;

    int fd = perf_event_open(&attr);
    if (fd == -1)
    {
        std::cerr << strerror(errno) << std::endl;
        return;
    }

    tracing(fd);
}

int main(void)
{
    std::cout << "type, tp" << std::endl;
    compute_running = true;
    pid_t pid = fork();

    if (pid == 0)
    {
        execlp("./workload", "./workload", NULL);
    }
    else
    {
        child_pid = pid;
        std::thread t1(read_switch_events);
        std::thread t2(read_tracepoints_events);

        // wait for child exit
        int wait_status;
        int wait_ret = waitpid(child_pid, &wait_status, WUNTRACED | WCONTINUED);

        if (-1 == wait_ret)
        {
            std::cerr << "could not wait for children, leaving them behind\n";
            return 1;
        }

        compute_running = false;
        t1.join();
        t2.join();
    }

    return 0;
}
