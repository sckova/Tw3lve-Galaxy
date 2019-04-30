#import <string.h>
#import <stdlib.h>
#import <stdio.h>
#import <unistd.h>
#import <spawn.h>
#import <sys/mman.h>
#import <sys/attr.h>
#import <mach/mach.h>
#import <sys/types.h>
#import <CommonCrypto/CommonDigest.h>
#include "Tw3lveView.h"

#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#define _assert(test, message, fatal) do \
if (!(test)) { \
int saved_errno = errno; \
LOGME("__assert(%d:%s)@%s:%u[%s]", saved_errno, #test, __FILENAME__, __LINE__, __FUNCTION__); \
} \
while (false)

#define NOTICE(msg, wait, destructive) showAlert(@"TW3LVE", msg, wait, destructive)






kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);
kern_return_t mach_vm_protect (vm_map_t target_task, mach_vm_address_t address,  mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
kern_return_t mach_vm_region(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name);


void setGID(gid_t gid, uint64_t proc);
void setUID (uid_t uid, uint64_t proc);
uint64_t selfproc(void);
void rootMe (int both, uint64_t proc);
void unsandbox (uint64_t proc);
NSString *get_path_file(NSString *resource);
void initPF64(void);
void getOffsets(void);
void remountFS(void);
void restoreRootFS(void);
void ux_tfp0(host_t orig_host, uint32_t type);
void is_unc0ver_installed(void);
void is_last_surprise_installed(void);
void is_electra12_installed(void);
uint64_t give_creds_to_addr(uint64_t proc, uint64_t cred_addr);
uint64_t get_kernel_cred_addr(void);
void set_platform_binary(uint64_t proc);
void saveOffs(void);
void installCydia(void);
bool restartSpringBoard(void);
void finishCydia(void);
void loadTweaks(void);
void dontLoadTweaks(void);
void installSileo(void);
