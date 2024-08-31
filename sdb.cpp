#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <sys/user.h>
#include <capstone/capstone.h>
#include <sys/personality.h>
#include <sys/types.h>
#include <map>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <algorithm>

using namespace std;

/*
///
to do:
1. launch the debugger
2. load the program
///
*/

#define	PEEKSIZE	8

class breakpoint {
public:
    size_t id;
    unsigned long long address;
    unsigned long original_data;
    bool enabled;
};

bool program_loaded = false;
pid_t child_pid=0;
stringstream ss;
int status;
static csh cshandle = 0;
unsigned long long entry_point=0;
long unsigned int text_start=0;
long unsigned int text_end=0;
map<unsigned long long, breakpoint> breakpoints;
vector<breakpoint> breakpoint_list;
unsigned long long breakpoint_id=0;
bool is_hit_breakpoint = false;
unsigned long long RIP; //store the last hit address of breakpoint
int syscall_enter = 0x01;

void load_elf(const char* program);
void disassemble(unsigned long long rip);
void load_program(const char* arg);
unsigned long long program_continue();
unsigned long long single_step();
void info_reg();
unsigned long string_to_long(string str);
unsigned long long string_to_llong(string str);
void patch(unsigned long long addr, unsigned long value, int size);
void info_break();
bool breakpoint_list_sort(breakpoint a, breakpoint b);
int add_breakpoint(unsigned long long addr);
int delete_breakpoint(unsigned long long addr);
void debugger();
void update_breakpoint_list(size_t id, unsigned long new_data);
unsigned long long syscall();

void load_elf(const char* program){
    int fd;
    fd = open(program,O_RDONLY);
    if(fd < 0){
        perror("open");
        return;
    }
    Elf64_Ehdr ehdr;
    if(read(fd,&ehdr,sizeof(ehdr)) != sizeof(ehdr)){
        perror("read");
        return;
    }
    if(memcmp(ehdr.e_ident,ELFMAG,SELFMAG) != 0){
        printf("** %s is not an ELF file.\n",program);
        return;
    }
    entry_point = ehdr.e_entry;

    Elf64_Shdr shdr;
    char* shstrtab;
    if(lseek(fd,ehdr.e_shoff + ehdr.e_shstrndx*sizeof(shdr),SEEK_SET) < 0){
        perror("lseek");
        return;
    }
    if(read(fd,&shdr,sizeof(shdr)) != sizeof(shdr)){
        perror("read");
        return;
    }
    shstrtab = (char*)malloc(shdr.sh_size);
    if(lseek(fd,shdr.sh_offset,SEEK_SET) < 0){
        perror("lseek");
        return;
    }
    if(read(fd,shstrtab,shdr.sh_size) != shdr.sh_size){
        perror("read");
        return;
    }

    for(size_t i=0; i < ehdr.e_shnum;i++){
        if(lseek(fd,ehdr.e_shoff + i*sizeof(shdr),SEEK_SET) < 0){
            perror("lseek");
            return;
        }
        if(read(fd,&shdr,sizeof(shdr)) != sizeof(shdr)){
            perror("read");
            return;
        }
        if(strcmp(&shstrtab[shdr.sh_name],".text") == 0){
            text_start = shdr.sh_addr;
            text_end = shdr.sh_addr + shdr.sh_size;
            //printf("** text section: 0x%lx-0x%lx\n",text_start,text_end);
            break;

        }
    
    }
    

}

void disassemble(unsigned long long rip){
    //printf("0x%llx:\n",rip);
    cs_insn *insn;
    size_t count;
    unsigned long word[5];
    unsigned char *ptr = (unsigned char *) &word;
    for(size_t i=0; i<5*PEEKSIZE; i+=PEEKSIZE){
        map<unsigned long long, breakpoint>::iterator it;
        it = breakpoints.find(rip+i*PEEKSIZE);
        if(it != breakpoints.end()){
            word[i/PEEKSIZE] = it->second.original_data;
            continue;
        }
        word[i/PEEKSIZE] = ptrace(PTRACE_PEEKTEXT,child_pid,rip+i,0);
    }
    for(unsigned char* p=ptr;p<ptr+5*PEEKSIZE;p++){
        if (*p == 0xcc){
            //printf("** breakpoint at 0x%llx\n", p - ptr + rip);
            map<unsigned long long, breakpoint>::iterator it;
            it = breakpoints.find(p - ptr + rip);
            if(it != breakpoints.end()){
                //printf("** breakpoint id: %lu\n", it->second.id);
                unsigned char *data = (unsigned char*)&it->second.original_data;
                for(int i=0; i<PEEKSIZE; i++){
                    *(p+i) = data[i];
                }
            }
            else{
                //printf("** unknown breakpoint\n");
            }
        }
    }
    count = cs_disasm(cshandle,(const uint8_t*)ptr,sizeof(unsigned long)*5,rip,0,&insn);
    size_t i=0;
    if(count > 0){
        size_t j;
        for (j = 0; j < count; j++) {
            if(insn[j].address < text_start || insn[j].address >= text_end) {
                printf("** the address is out of the range of the text section.\n");
                break;
            }
            printf("\t%lx: ",insn[j].address);
            for(int k=0 ; k<insn[j].size; k++){
                printf("%2.2x ",insn[j].bytes[k]);
            }
            switch(insn[j].size){
                case 1:
                case 2:
                    printf("\t");
                case 3:
                case 4:
                case 5:
                    printf("\t");
                default:
                    printf("\t");
            }
            printf("\t%s\t%s\n",insn[j].mnemonic,insn[j].op_str);
            i++;
            if(i>=5) break;
            // if out of elf's text section, break
        }
        cs_free(insn,count);
    }
    else{
        printf("0x%llx:\t<cannot disassemble>\n",rip);
    }

    return;
}

void load_program(const char* arg){
    pid_t pid = fork();
    if(pid < 0) perror("fork");
    if(pid == 0){
        // child process
        program_loaded = true;
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME,0,NULL,NULL);
        execl(arg,arg,NULL);
        perror("execl");
        program_loaded = false;
        child_pid = 0;
        return;
    }
    else{
        // parent process
        child_pid = pid;
        if(waitpid(pid,&status,0) < 0) perror("waitpid");
        if(WIFEXITED(status)){
            return;
        }
        program_loaded = true;
        assert(WIFSTOPPED(status));
        ptrace(PTRACE_SETOPTIONS,pid,NULL,PTRACE_O_EXITKILL|PTRACE_O_TRACESYSGOOD);
        //get entry point from elf header
        load_elf(arg);
        printf("** program '%s' loaded. entry point 0x%llx.\n",arg,entry_point);
        
        // disassemble the first 5 instructions
        disassemble(entry_point);

        //ptrace(PTRACE_SETREGS,pid,NULL,&regs);
        return;
    }
}

unsigned long long program_continue(){
    /*
    ///
    when cont hit breakpoints, rip-1 then disassemble
    cont at breakpoints addr -> poke the instruction back to original -> single step -> poke back 0xcc -> cont
    ///
    */
    // check if there is a breakpoint at the current address
    long long rip;
    struct user_regs_struct regs;
    map<unsigned long long, breakpoint>::iterator it;
    if(is_hit_breakpoint){
        is_hit_breakpoint = false;
        rip = RIP;
        it = breakpoints.find(rip);
        if(it != breakpoints.end()){
            unsigned long word = it->second.original_data;
            unsigned char* ptr = (unsigned char*)&word;
            ptrace(PTRACE_POKETEXT,child_pid,rip,word);
            ptrace(PTRACE_POKEUSER,child_pid,(unsigned char *)&regs.rip - (unsigned char *)&regs,rip);
            ptrace(PTRACE_SINGLESTEP,child_pid,NULL,NULL);
            waitpid(child_pid,&status,0);
            if(WIFEXITED(status)){
                if(status == 0){
                    printf("** the target program terminated.\n");
                }
                return 0;
            }
            ptr[0] = 0xcc;
            for(int i=1; i<PEEKSIZE; i++){
                it = breakpoints.find(rip+i);
                if(it != breakpoints.end()){
                    ptr[i]=0xcc;
                    break;
                }
            }
            ptrace(PTRACE_POKETEXT,child_pid,rip,word);
        }
    }
    ptrace(PTRACE_CONT,child_pid,NULL,NULL);
    waitpid(child_pid,&status,0);
    // check if the program is terminated
    if(WIFEXITED(status)){
        //if(status == 0){
            printf("** the target program terminated.\n");
        //}
        return 0;
    }
    // check if the program is stopped
    if(WIFSTOPPED(status)){
        rip = ptrace(PTRACE_PEEKUSER,child_pid,(unsigned char *)&regs.rip - (unsigned char *)&regs,0);
        if(WSTOPSIG(status) == SIGTRAP){
            it = breakpoints.find(rip-1);
            if(it != breakpoints.end()){
                rip--;
                is_hit_breakpoint = true;
                RIP = rip;
                ptrace(PTRACE_POKEUSER,child_pid,(unsigned char *)&regs.rip - (unsigned char *)&regs,rip);
                printf("** hit a breakpoint at 0x%llx.\n",rip);
            }
        }
    }
    return rip;
}

unsigned long long single_step(){
    long long rip;
    struct user_regs_struct regs;
    map<unsigned long long, breakpoint>::iterator it;
    if(is_hit_breakpoint){
        rip = RIP;
        it = breakpoints.find(rip);
        if(it != breakpoints.end()){
            unsigned long word = it->second.original_data;
            ptrace(PTRACE_POKETEXT,child_pid,rip,word);
            ptrace(PTRACE_POKEUSER,child_pid,(unsigned char *)&regs.rip - (unsigned char *)&regs,rip);
        }
    }
    ptrace(PTRACE_SINGLESTEP,child_pid,NULL,NULL);
    waitpid(child_pid,&status,0);
    if(WIFEXITED(status)){
        if(status == 0){
            printf("** the target program terminated.\n");
        }
        return 0;
    }
    if(is_hit_breakpoint){
        is_hit_breakpoint = false;
        it = breakpoints.find(rip);
        if(it != breakpoints.end()){
            unsigned long word = it->second.original_data;
            unsigned char* ptr = (unsigned char*)&word;
            ptr[0] = 0xcc;
            for(int i=1;i<PEEKSIZE;i++){
                it = breakpoints.find(rip+i);
                if(it != breakpoints.end()){
                    ptr[i] = 0xcc;
                }
            }
            ptrace(PTRACE_POKETEXT,child_pid,rip,word);
        }
    }
    rip = ptrace(PTRACE_PEEKUSER,child_pid,(unsigned char *)&regs.rip - (unsigned char *)&regs,0);
    it = breakpoints.find(rip);
    if(it != breakpoints.end()){
        is_hit_breakpoint = true;
        RIP = rip;
        printf("** hit a breakpoint at 0x%llx.\n",rip);
    }
    return rip;
}

void info_reg(){
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS,child_pid,NULL,&regs);
    printf("$rax 0x%016llx    $rbx 0x%16.16llx    $rcx 0x%16.16llx\n",regs.rax,regs.rbx,regs.rcx);
    printf("$rdx 0x%16.16llx    $rsi 0x%16.16llx    $rdi 0x%16.16llx\n",regs.rdx,regs.rsi,regs.rdi);
    printf("$rbp 0x%16.16llx    $rsp 0x%16.16llx    $r8  0x%16.16llx\n",regs.rbp,regs.rsp,regs.r8);
    printf("$r9  0x%16.16llx    $r10 0x%16.16llx    $r11 0x%16.16llx\n",regs.r9,regs.r10,regs.r11);
    printf("$r12 0x%16.16llx    $r13 0x%16.16llx    $r14 0x%16.16llx\n",regs.r12,regs.r13,regs.r14);
    printf("$r15 0x%16.16llx    $rip 0x%16.16llx    $eflags 0x%16.16llx\n",regs.r15,regs.rip,regs.eflags);
    return;
}

unsigned long string_to_long(string str){
    //string format 0x12345678
    unsigned long word = 0;
    size_t i=0;
    if(strncmp(str.c_str(),"0x",2)==0) i=2;
    for(; i<str.size(); i++){
        word = word*16;
        if(str[i] >= '0' && str[i] <= '9'){
            word += str[i] - '0';
        }
        else if(str[i] >= 'a' && str[i] <= 'f'){
            word += str[i] - 'a' + 10;
        }
        else if(str[i] >= 'A' && str[i] <= 'F'){
            word += str[i] - 'A' + 10;
        }
        else{
            printf("** invalid address.\n");
            return 0;
        }
    }
    return word;
}

unsigned long long string_to_llong(string str){
    //string format 0x12345678
    unsigned long long word = 0;
    size_t i=0;
    if(strncmp(str.c_str(),"0x",2)==0) i=2;
    for(; i<str.size(); i++){
        word = word*16;
        if(str[i] >= '0' && str[i] <= '9'){
            word += str[i] - '0';
        }
        else if(str[i] >= 'a' && str[i] <= 'f'){
            word += str[i] - 'a' + 10;
        }
        else if(str[i] >= 'A' && str[i] <= 'F'){
            word += str[i] - 'A' + 10;
        }
        else{
            printf("** invalid address.\n");
            return 0;
        }
    }
    return word;
}

void patch(unsigned long long addr, unsigned long value, int size){
    // *still need to handle breakpoint
    //size: 1, 2, 4, 8 bytes
    unsigned long original_data = ptrace(PTRACE_PEEKTEXT,child_pid,addr,0);
    unsigned long mask = 0xffffffffffffffff;
    if(size == 8) mask = 0x0;
    unsigned long data = original_data & (mask << size*8);
    data |= (value & ~(mask << size*8));
    for(int i=0; i<size; i++){
        unsigned char* ptr = (unsigned char*)&data;
        map<unsigned long long, breakpoint>::iterator it;
        it = breakpoints.find(addr+i);
        if(it != breakpoints.end()){
            it->second.original_data = ptr[i];
        }
    }
    ptrace(PTRACE_POKETEXT,child_pid,addr,data);
    printf("** patch memory at address 0x%llx.\n",addr);
    return;
}

void break_patch(unsigned long long addr, unsigned long value, int size){
    // *still need to handle breakpoint
    //size: 1, 2, 4, 8 bytes
    unsigned long original_data[3]; // 3 words, addr-8, addr, addr+8 
    map<unsigned long long, breakpoint>::iterator it;
    for(int i=0;i<3;i++){
        unsigned long long addr1 = addr + (i-1)*8;
        it = breakpoints.find(addr1);
        if(it != breakpoints.end()){
            original_data[i] = it->second.original_data;
        }
        else{
            original_data[i] = ptrace(PTRACE_PEEKTEXT,child_pid,addr1,0);
        }
    }
    unsigned char *ptr;
    ptr = (unsigned char*)original_data;
    for(int i=0;i<24;i++){
        if(ptr[i] == 0xcc){
            it = breakpoints.find(addr-8+i);
            if(it != breakpoints.end()){
                unsigned long temp = it->second.original_data;
                unsigned char* ptr1 = (unsigned char*)&temp;
                for(int j=0 ;j<PEEKSIZE && i+j<24; j++){
                    ptr[i+j] = ptr1[j];
                }
            }
        }
    }
    
    unsigned long mask = 0xffffffffffffffff;
    mask = (size==8) ? 0x0 : mask << size*8;
    unsigned long data = original_data[1] & mask;
    data |= (value & ~mask);
    original_data[1] = data;
    ptr = (unsigned char*)original_data;
    for(int i=0; i<16; i++){
        it = breakpoints.find(addr-8+i);
        if(it != breakpoints.end()){
            unsigned long temp = it->second.original_data;
            unsigned char* ptr1 = (unsigned char*)&temp;
            for(int j=0; j<PEEKSIZE; j++){
                ptr1[j] = ptr[i+j];
            }
            it->second.original_data = temp;
            update_breakpoint_list(it->second.id,temp);
        }
    }
    ptr = (unsigned char*)&data;
    for(int i=0;i<PEEKSIZE;i++){
        it = breakpoints.find(addr+i);
        if(it != breakpoints.end()){
            ptr[i] = 0xcc;
        }
    }

    ptrace(PTRACE_POKETEXT,child_pid,addr,data);


    printf("** patch memory at address 0x%llx.\n",addr);
    
    /*unsigned long mask = 0xffffffffffffffff;
    if(size == 8) mask = 0x0;
    unsigned long data = original_data & (mask << size*8);
    data |= (value & ~(mask << size*8));
    for(int i=0; i<size; i++){
        unsigned char* ptr = (unsigned char*)&data;
        map<unsigned long long, breakpoint>::iterator it;
        it = breakpoints.find(addr+i);
        if(it != breakpoints.end()){
            it->second.original_data = ptr[i];
        }
    }
    ptrace(PTRACE_POKETEXT,child_pid,addr,data);
    printf("** patch memory at address 0x%llx.\n",addr);*/
    return;
}

void info_break(){
    if(breakpoint_list.empty()){
        printf("** no breakpoints.\n");
        return;
    }
    else{
        printf("Num\tAddress\n");
        //printf("Num\tAddress\torig\n");
        for(size_t i=0; i<breakpoint_list.size(); i++){
            printf("%lu\t0x%llx\n",breakpoint_list[i].id,breakpoint_list[i].address);
            //printf("%lu\t0x%llx\t%lx\n",breakpoint_list[i].id,breakpoint_list[i].address,breakpoint_list[i].original_data);
        }
    }
    return;
}

bool breakpoint_list_sort(breakpoint a, breakpoint b){
    return a.id < b.id;
}

int add_breakpoint(unsigned long long addr){
    map<unsigned long long, breakpoint>::iterator it;
    it = breakpoints.find(addr);
    if(it != breakpoints.end()){
        printf("** breakpoint already exists.\n");
        return -1;
    }
    unsigned long word = ptrace(PTRACE_PEEKTEXT,child_pid,addr,0);
    unsigned char* ptr = (unsigned char*)&word;
    for(size_t i=0;i<PEEKSIZE;i++){
        map<unsigned long long, breakpoint>::iterator bp;
        bp = breakpoints.find(addr+i);
        if(bp != breakpoints.end()){
            unsigned long w = bp->second.original_data;
            unsigned char* p = (unsigned char*)&w;
            ptr[i] = p[0];
        }
    }


    breakpoint bp;
    bp.id = breakpoint_id++;
    bp.address = addr;
    bp.original_data = word;
    bp.enabled = true;
    breakpoints[addr] = bp;
    breakpoint_list.push_back(bp);
    sort(breakpoint_list.begin(),breakpoint_list.end(),breakpoint_list_sort);
    ptr[0] = 0xcc;
    ptrace(PTRACE_POKETEXT,child_pid,addr,word);
    printf("** set a breakpoint at 0x%llx.\n",addr);
    return 0;
}

int delete_breakpoint(size_t id){
    vector<breakpoint>::iterator it;
    bool flag = false;
    for(it = breakpoint_list.begin(); it != breakpoint_list.end(); it++){
        if(it->id == id){
            unsigned long word = it->original_data;
            unsigned char* ptr = (unsigned char*)&word;
            unsigned long long addr = it->address;
            for(size_t i=1; i<PEEKSIZE; i++){
                map<unsigned long long, breakpoint>::iterator bp;
                bp = breakpoints.find(addr+i);
                if(bp != breakpoints.end()){
                    ptr[i] = 0xcc;
                }
            }
            ptrace(PTRACE_POKETEXT,child_pid,addr,word);
            breakpoints.erase(it->address);
            breakpoint_list.erase(it);
            flag = true;
            printf("** delete breakpoint %lu.\n",id);
            break;
        }
    }
    if(!flag){
        printf("** breakpoint %lu does not exist.\n",id);
    }
    return 0;
}

void update_breakpoint_list(size_t id, unsigned long new_data){
    vector<breakpoint>::iterator it;
    for(it = breakpoint_list.begin(); it != breakpoint_list.end(); it++){
        if(it->id == id){
            it->original_data = new_data;
            break;
        }
    }
    return;
}

unsigned long long syscall(){
    long long rip;
    struct user_regs_struct regs;
    map<unsigned long long, breakpoint>::iterator it;
    if(is_hit_breakpoint){
        is_hit_breakpoint = false;
        rip = RIP;
        it = breakpoints.find(rip);
        if(it != breakpoints.end()){
            unsigned long word = it->second.original_data;
            unsigned char* ptr = (unsigned char*)&word;
            ptrace(PTRACE_POKETEXT,child_pid,rip,word);
            ptrace(PTRACE_POKEUSER,child_pid,(unsigned char *)&regs.rip - (unsigned char *)&regs,rip);
            ptrace(PTRACE_SINGLESTEP,child_pid,NULL,NULL);
            waitpid(child_pid,&status,0);
            if(WIFEXITED(status)){
                if(status == 0){
                    printf("** the target program terminated.\n");
                }
                return 0;
            }
            ptr[0] = 0xcc;
            for(int i=1; i<PEEKSIZE; i++){
                it = breakpoints.find(rip+i);
                if(it != breakpoints.end()){
                    ptr[i]=0xcc;
                    break;
                }
            }
            ptrace(PTRACE_POKETEXT,child_pid,rip,word);
        }
    }
    ptrace(PTRACE_SYSCALL,child_pid,NULL,NULL);
    waitpid(child_pid,&status,0);
    // check if the program is terminated
    if(WIFEXITED(status)){
        if(status == 0){
            printf("** the target program terminated.\n");
        }
        return 0;
    }
    // check if the program is stopped
    if(WIFSTOPPED(status)){
        int stop_signal = WSTOPSIG(status);
        if(stop_signal == (SIGTRAP | 0x80)){
            ptrace(PTRACE_GETREGS,child_pid,NULL,&regs);
            if(syscall_enter){
                printf("** enter a syscall(%lld) at 0x%llx.\n",regs.orig_rax,regs.rip-2);
            }else{
                printf("** leave a syscall(%lld) = %lld at 0x%llx.\n",regs.orig_rax,regs.rax,regs.rip-2);
            }
            syscall_enter ^= 0x01;
            rip = regs.rip-2;
        }
        else if(stop_signal == SIGTRAP){
            rip = ptrace(PTRACE_PEEKUSER,child_pid,(unsigned char *)&regs.rip - (unsigned char *)&regs,0);
            it = breakpoints.find(rip-1);
            if(it != breakpoints.end()){
                rip--;
                is_hit_breakpoint = true;
                RIP = rip;
                ptrace(PTRACE_POKEUSER,child_pid,(unsigned char *)&regs.rip - (unsigned char *)&regs,rip);
                printf("** hit a breakpoint at 0x%llx.\n",rip);
            }
        }
    }
    return rip;
}

void debugger(){
    // handling the commands
    // the program should be loaded before calling this function

    string input;
    vector<string> commands;
    ss.str("");
    ss.clear();
    while(WIFSTOPPED(status)){
        printf("(sdb) ");
        getline(cin,input);
        ss.str(input);
        string command;
        unsigned long long rip;
        // split the input into commands
        while(ss >> command){
            commands.push_back(command);
        }

        if(commands[0] == "q") break;
        
        if(commands[0] == "cont"){
            rip = program_continue();
            if(rip) disassemble(rip);
        }
        else if(commands[0] == "info"){
            if(commands.size() == 1){
                printf("** please provide a valid argument for the info command.\n");
            }
            else if(commands[1] == "reg"){
                info_reg();
            }
            else if(commands[1] == "break"){
                info_break();
            }
        }
        else if(commands[0] == "peek"){
            unsigned long long rip;
            struct user_regs_struct regs;
            rip = ptrace(PTRACE_PEEKUSER,child_pid,(unsigned char *)&regs.rip - (unsigned char *)&regs,0);
            disassemble(rip);
        }
        else if(commands[0] == "si"){
            rip = single_step();
            if(rip) disassemble(rip);
        }
        else if(commands[0] == "patch"){
            if(commands.size() < 4){
                printf("** format: patch [hex address] [hex value] [len]\n");
            }
            else{
                unsigned long long addr = string_to_llong(commands[1]);
                unsigned long value = string_to_long(commands[2]);
                int size = atoi(commands[3].c_str());
                //patch(addr,value,size);
                break_patch(addr,value,size);
            }
        }
        else if(commands[0] == "break"){
            if(commands.size() < 2){
                printf("** format: break [hex address]\n");
            }
            else{
                unsigned long long addr = string_to_llong(commands[1]);
                add_breakpoint(addr);
            }
        }
        else if(commands[0] == "delete"){
            if(commands.size() < 2){
                printf("** format: delete [breakpoint id]\n");
            }
            else{
                size_t id = atoi(commands[1].c_str());
                delete_breakpoint(id);
            }
        }
        else if(commands[0] == "syscall"){
            rip = syscall();
            if(rip) disassemble(rip);
        }
        else{
            printf("** unknown command.\n");
        }
        
        commands.clear();
        ss.str("");
        ss.clear();
    }
    return;
}

int main(int argc,char* argv[]){
    
    if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK){
        perror("cs_open");
        return -1;
    }
    //setvbuf(stdout, NULL, _IONBF, 0); 
    if (argc >= 2){
        load_program(argv[1]);
    }else{
        // load program
        string input;
        ss.str("");
        ss.clear();
        while(true){
            printf("(sdb) ");
            getline(cin, input);
            if(input == "q") goto end;
            ss.str(input);
            string command;
            ss >> command;
            if(command == "load"){
                if(ss.eof()){
                    printf("** please provide a program to load.\n");
                }
                else{
                    string program="";
                    string arg="";
                    ss >> arg;
                    if(arg[0]=='\"'){
                        // handling the case where the program name has spaces
                        if(arg[arg.size()-1] == '\"'){
                            program = arg.substr(1,arg.size()-2);
                        }
                        else{
                            program = arg.substr(1,arg.size()-1);
                            while(true){
                                ss >> arg;
                                if(arg[arg.size()-1] == '\"'){
                                    program += " " + arg.substr(0,arg.size()-1);
                                    break;
                                }
                                else{
                                    program += " " + arg;
                                }
                            }
                        }
                    }
                    else if(arg != ""){
                        program = arg;
                    }
                    else{
                        printf("** please provide a program to load.\n");
                        ss.str("");
                        ss.clear();
                        continue;
                    }
                    load_program(program.c_str());
                    if(program_loaded) break;
                    if(child_pid == 0) goto end;
                }
            }
            else{
                printf("** please load a program first.\n");
            }
            ss.str("");
            ss.clear();
        }
    }

    debugger();
    
    end:
    cs_close(&cshandle);
    return 0;
}