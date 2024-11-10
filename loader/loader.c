#include "loader.h"
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
int fd;
int page_fault_count = 0;
int page_alloc_count = 0;
size_t total_allocated_memory = 0;

void *align_to_page(void *addr) {
    return (void *)((uintptr_t)addr & ~(getpagesize()-1));
}

void segfault_handler(int sig, siginfo_t *info, void *context){
    void *fault_addr = info->si_addr;
    for(int i=0; i<ehdr->e_phnum; i++){
        lseek(fd, (ehdr->e_phoff)+i*(ehdr->e_phentsize), SEEK_SET);
        read(fd, phdr, sizeof(Elf32_Phdr));
        if(phdr->p_type == PT_LOAD &&
            fault_addr >= (void *)phdr->p_vaddr &&
            fault_addr < (void *)(phdr->p_vaddr + phdr->p_memsz)){
            void *aligned_addr = align_to_page(fault_addr);
            size_t page_size = getpagesize();
            void *allocated_page = mmap(aligned_addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                                        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
            if(allocated_page == MAP_FAILED){
                printf("mmap failed");
                exit(1);
            }
            size_t offset = phdr->p_offset + ((uintptr_t)aligned_addr - phdr->p_vaddr);
            lseek(fd, offset, SEEK_SET);
            size_t read_size;
            if((uintptr_t)aligned_addr+page_size > phdr->p_vaddr+phdr->p_filesz){
                read_size = phdr->p_vaddr+phdr->p_filesz-(uintptr_t)aligned_addr;
            }else{
                read_size = page_size;
            }
            read(fd, allocated_page, read_size);
            page_fault_count++;
            page_alloc_count++;
            total_allocated_memory += page_size;
            return;
        }
    }
    printf("Segmentation fault at invalid address: %p\n", fault_addr);
    exit(1);
}

void setup_segfault_handler(){
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segfault_handler;
    sigemptyset(&sa.sa_mask);
    if(sigaction(SIGSEGV, &sa, NULL) == -1){
        printf("Failed to set up SIGSEGV handler");
        exit(1);
    }
}

void loader_cleanup(){
    if(ehdr){
        free(ehdr);
        ehdr = NULL;
    }
    if(phdr){
        free(phdr);
        phdr = NULL;
    }
    close(fd);
}

void load_and_run_elf(char **exe){
    fd = open(exe[1], O_RDONLY);
    if(fd < 0){
        printf("Error occurred while opening the ELF file");
        exit(1);
    }

    ehdr = malloc(sizeof(Elf32_Ehdr));
    if(read(fd, ehdr, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)){
        printf("Error occurred while reading the ELF header");
        exit(1);
    }

    phdr = malloc(sizeof(Elf32_Phdr));
    setup_segfault_handler();

    void *entry_point = (void *)ehdr->e_entry;
    int (*_start)() = (int (*)())entry_point;
    int result = _start();

    printf("User _start return value = %d\n", result);
    printf("Total page faults: %d\n", page_fault_count);
    printf("Total page allocations: %d\n", page_alloc_count);
    printf("Total internal fragmentation: %ld KB\n", (long)(total_allocated_memory - (size_t)(phdr->p_memsz)) / 1024);

    loader_cleanup();
}
