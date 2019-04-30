//
//  utils.m
//  tw3lve
//
//  Created by Tanay Findley on 4/9/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "utils.h"
#import "kernel_memory.h"
#import "kernel_slide.h"
#include "parameters.h"
#include "KernelUtils.h"
#include "patchfinder64.h"
#include "offsets.h"
#include "common.h"
#include "lzssdec.h"
#include <sys/utsname.h>
#include "PFOffs.h"
#include "remap_tfp_set_hsp.h"
#include "libsnappy.h"
#include "OffsetHolder.h"
#include "vnode_utils.h"
#include <sys/mount.h>
#include "KernelMemory.h"
#include <sys/snapshot.h>
#include <sys/stat.h>
#include "reboot.h"
#include "amfi_utils.h"
#include "ArchiveFile.h"
#import <copyfile.h>
#include "VarHolder.h"
#include "proc_info.h"
#include "libproc.h"

extern char **environ;
NSData *lastSystemOutput=nil;
int execCmdV(const char *cmd, int argc, const char * const* argv, void (^unrestrict)(pid_t)) {
    pid_t pid;
    posix_spawn_file_actions_t *actions = NULL;
    posix_spawn_file_actions_t actionsStruct;
    int out_pipe[2];
    bool valid_pipe = false;
    posix_spawnattr_t *attr = NULL;
    posix_spawnattr_t attrStruct;
    
    NSMutableString *cmdstr = [NSMutableString stringWithCString:cmd encoding:NSUTF8StringEncoding];
    for (int i=1; i<argc; i++) {
        [cmdstr appendFormat:@" \"%s\"", argv[i]];
    }
    
    valid_pipe = pipe(out_pipe) == ERR_SUCCESS;
    if (valid_pipe && posix_spawn_file_actions_init(&actionsStruct) == ERR_SUCCESS) {
        actions = &actionsStruct;
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 1);
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 2);
        posix_spawn_file_actions_addclose(actions, out_pipe[0]);
        posix_spawn_file_actions_addclose(actions, out_pipe[1]);
    }
    
    if (unrestrict && posix_spawnattr_init(&attrStruct) == ERR_SUCCESS) {
        attr = &attrStruct;
        posix_spawnattr_setflags(attr, POSIX_SPAWN_START_SUSPENDED);
    }
    
    int rv = posix_spawn(&pid, cmd, actions, attr, (char *const *)argv, environ);
    LOGME("%s(%d) command: %@", __FUNCTION__, pid, cmdstr);
    
    if (unrestrict) {
        unrestrict(pid);
        kill(pid, SIGCONT);
    }
    
    if (valid_pipe) {
        close(out_pipe[1]);
    }
    
    if (rv == ERR_SUCCESS) {
        if (valid_pipe) {
            NSMutableData *outData = [NSMutableData new];
            char c;
            char s[2] = {0, 0};
            NSMutableString *line = [NSMutableString new];
            while (read(out_pipe[0], &c, 1) == 1) {
                [outData appendBytes:&c length:1];
                if (c == '\n') {
                    LOGME("%s(%d): %@", __FUNCTION__, pid, line);
                    [line setString:@""];
                } else {
                    s[0] = c;
                    [line appendString:@(s)];
                }
            }
            if ([line length] > 0) {
                LOGME("%s(%d): %@", __FUNCTION__, pid, line);
            }
            lastSystemOutput = [outData copy];
        }
        if (waitpid(pid, &rv, 0) == -1) {
            LOGME("ERROR: Waitpid failed");
        } else {
            LOGME("%s(%d) completed with exit status %d", __FUNCTION__, pid, WEXITSTATUS(rv));
        }
        
    } else {
        LOGME("%s(%d): ERROR posix_spawn failed (%d): %s", __FUNCTION__, pid, rv, strerror(rv));
        rv <<= 8; // Put error into WEXITSTATUS
    }
    if (valid_pipe) {
        close(out_pipe[0]);
    }
    return rv;
}

int execCmd(const char *cmd, ...) {
    va_list ap, ap2;
    int argc = 1;
    
    va_start(ap, cmd);
    va_copy(ap2, ap);
    
    while (va_arg(ap, const char *) != NULL) {
        argc++;
    }
    va_end(ap);
    
    const char *argv[argc+1];
    argv[0] = cmd;
    for (int i=1; i<argc; i++) {
        argv[i] = va_arg(ap2, const char *);
    }
    va_end(ap2);
    argv[argc] = NULL;
    
    int rv = execCmdV(cmd, argc, argv, NULL);
    return WEXITSTATUS(rv);
}




void setGID(gid_t gid, uint64_t proc) {
    if (getgid() == gid) return;
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    kernel_write32(proc + off_p_gid, gid);
    kernel_write32(proc + off_p_rgid, gid);
    kernel_write32(ucred + off_ucred_cr_rgid, gid);
    kernel_write32(ucred + off_ucred_cr_svgid, gid);
    NSLog(@"Overwritten GID to %i for proc 0x%llx", gid, proc);
}

void setUID (uid_t uid, uint64_t proc) {
    if (getuid() == uid) return;
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    kernel_write32(proc + off_p_uid, uid);
    kernel_write32(proc + off_p_ruid, uid);
    kernel_write32(ucred + off_ucred_cr_uid, uid);
    kernel_write32(ucred + off_ucred_cr_ruid, uid);
    kernel_write32(ucred + off_ucred_cr_svuid, uid);
    NSLog(@"Overwritten UID to %i for proc 0x%llx", uid, proc);
}

uint64_t selfproc() {
    static uint64_t proc = 0;
    if (!proc) {
        proc = kernel_read64(current_task + OFFSET(task, bsd_info));
        NSLog(@"Found proc 0x%llx for PID %i", proc, getpid());
    }
    return proc;
}

void rootMe (int both, uint64_t proc) {
    setUID(both, proc);
    setGID(both, proc);
}

void unsandbox (uint64_t proc) {
    NSLog(@"Unsandboxed proc 0x%llx", proc);
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    uint64_t cr_label = kernel_read64(ucred + off_ucred_cr_label);
    kernel_write64(cr_label + off_sandbox_slot, 0);
}

bool canRead(const char *file) {
    NSString *path = @(file);
    NSFileManager *fileManager = [NSFileManager defaultManager];
    return ([fileManager attributesOfItemAtPath:path error:nil]);
}


static void *load_bytes2(FILE *obj_file, off_t offset, uint32_t size) {
    void *buf = calloc(1, size);
    fseek(obj_file, offset, SEEK_SET);
    fread(buf, size, 1, obj_file);
    return buf;
}

static inline bool clean_file(const char *file) {
    NSString *path = @(file);
    if ([[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil]) {
        return [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    }
    return YES;
}

uint32_t find_macho_header(FILE *file) {
    uint32_t off = 0;
    uint32_t *magic = load_bytes2(file, off, sizeof(uint32_t));
    while ((*magic & ~1) != 0xFEEDFACE) {
        off++;
        magic = load_bytes2(file, off, sizeof(uint32_t));
    }
    return off - 1;
}

void initPF64() {
    LOGME("Initializing patchfinder64...");
    const char *original_kernel_cache_path = "/System/Library/Caches/com.apple.kernelcaches/kernelcache";
    
    NSString *homeDirectory = NSHomeDirectory();
    
    const char *decompressed_kernel_cache_path = [homeDirectory stringByAppendingPathComponent:@"Documents/kernelcache.dec"].UTF8String;
    if (!canRead(decompressed_kernel_cache_path)) {
        FILE *original_kernel_cache = fopen(original_kernel_cache_path, "rb");
        _assert(original_kernel_cache != NULL, @"Failed to initialize patchfinder64.", true);
        uint32_t macho_header_offset = find_macho_header(original_kernel_cache);
        _assert(macho_header_offset != 0, @"Failed to initialize patchfinder64.", true);
        char *args[5] = { "lzssdec", "-o", (char *)[NSString stringWithFormat:@"0x%x", macho_header_offset].UTF8String, (char *)original_kernel_cache_path, (char *)decompressed_kernel_cache_path};
        _assert(lzssdec(5, args) == ERR_SUCCESS, @"Failed to initialize patchfinder64.", true);
        fclose(original_kernel_cache);
    }
    struct utsname u = { 0 };
    _assert(uname(&u) == ERR_SUCCESS, @"Failed to initialize patchfinder64.", true);
    if (init_kernel(NULL, 0, decompressed_kernel_cache_path) != ERR_SUCCESS || find_strref(u.version, 1, string_base_const, true, false) == 0) {
        _assert(clean_file(decompressed_kernel_cache_path), @"Failed to initialize patchfinder64.", true);
        _assert(false, @"Failed to initialize patchfinder64.", true);
    }
    if (auth_ptrs) {
        LOGME("Detected A12 Device.");
        setA12(1);
    }
    if (monolithic_kernel) {
        LOGME("Detected monolithic kernel.");
    }
    LOGME("Successfully initialized patchfinder64.");
}



bool is_mountpoint(const char *filename) {
    struct stat buf;
    if (lstat(filename, &buf) != ERR_SUCCESS) {
        return false;
    }
    
    if (!S_ISDIR(buf.st_mode))
        return false;
    
    char *cwd = getcwd(NULL, 0);
    int rv = chdir(filename);
    assert(rv == ERR_SUCCESS);
    struct stat p_buf;
    rv = lstat("..", &p_buf);
    assert(rv == ERR_SUCCESS);
    if (cwd) {
        chdir(cwd);
        free(cwd);
    }
    return buf.st_dev != p_buf.st_dev || buf.st_ino == p_buf.st_ino;
}

bool ensure_directory(const char *directory, int owner, mode_t mode) {
    NSString *path = @(directory);
    NSFileManager *fm = [NSFileManager defaultManager];
    id attributes = [fm attributesOfItemAtPath:path error:nil];
    if (attributes &&
        [attributes[NSFileType] isEqual:NSFileTypeDirectory] &&
        [attributes[NSFileOwnerAccountID] isEqual:@(owner)] &&
        [attributes[NSFileGroupOwnerAccountID] isEqual:@(owner)] &&
        [attributes[NSFilePosixPermissions] isEqual:@(mode)]
        ) {
        // Directory exists and matches arguments
        return true;
    }
    if (attributes) {
        if ([attributes[NSFileType] isEqual:NSFileTypeDirectory]) {
            // Item exists and is a directory
            return [fm setAttributes:@{
                                       NSFileOwnerAccountID: @(owner),
                                       NSFileGroupOwnerAccountID: @(owner),
                                       NSFilePosixPermissions: @(mode)
                                       } ofItemAtPath:path error:nil];
        } else if (![fm removeItemAtPath:path error:nil]) {
            // Item exists and is not a directory but could not be removed
            return false;
        }
    }
    // Item does not exist at this point
    return [fm createDirectoryAtPath:path withIntermediateDirectories:YES attributes:@{
                                                                                       NSFileOwnerAccountID: @(owner),
                                                                                       NSFileGroupOwnerAccountID: @(owner),
                                                                                       NSFilePosixPermissions: @(mode)
                                                                                       } error:nil];
}

uint64_t give_creds_to_process_at_addr(uint64_t proc, uint64_t cred_addr)
{
    uint64_t orig_creds = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    LOGME("orig_creds = " ADDR, orig_creds);
    if (!ISADDR(orig_creds)) {
        LOGME("failed to get orig_creds!");
        return 0;
    }
    WriteKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), cred_addr);
    return orig_creds;
}

static inline bool init_file(const char *file, int owner, mode_t mode) {
    NSString *path = @(file);
    return ([[NSFileManager defaultManager] fileExistsAtPath:path] &&
            [[NSFileManager defaultManager] setAttributes:@{
                                                            NSFileOwnerAccountID: @(owner),
                                                            NSFileGroupOwnerAccountID: @(owner),
                                                            NSFilePosixPermissions: @(mode)
                                                            } ofItemAtPath:path error:nil]);
}

bool ensure_file(const char *file, int owner, mode_t mode) {
    NSString *path = @(file);
    NSFileManager *fm = [NSFileManager defaultManager];
    id attributes = [fm attributesOfItemAtPath:path error:nil];
    if (attributes &&
        [attributes[NSFileType] isEqual:NSFileTypeRegular] &&
        [attributes[NSFileOwnerAccountID] isEqual:@(owner)] &&
        [attributes[NSFileGroupOwnerAccountID] isEqual:@(owner)] &&
        [attributes[NSFilePosixPermissions] isEqual:@(mode)]
        ) {
        // File exists and matches arguments
        return true;
    }
    if (attributes) {
        if ([attributes[NSFileType] isEqual:NSFileTypeRegular]) {
            // Item exists and is a file
            return [fm setAttributes:@{
                                       NSFileOwnerAccountID: @(owner),
                                       NSFileGroupOwnerAccountID: @(owner),
                                       NSFilePosixPermissions: @(mode)
                                       } ofItemAtPath:path error:nil];
        } else if (![fm removeItemAtPath:path error:nil]) {
            // Item exists and is not a file but could not be removed
            return false;
        }
    }
    // Item does not exist at this point
    return [fm createFileAtPath:path contents:nil attributes:@{
                                                               NSFileOwnerAccountID: @(owner),
                                                               NSFileGroupOwnerAccountID: @(owner),
                                                               NSFilePosixPermissions: @(mode)
                                                               }];
}

void saveOffs() {
    
    _assert(ensure_file("/var/tmp/is_jailbroken.tw3lve", 0, 0644), @"Failed to create is_jailbroken.tw3lve", true);
    
    _assert(ensure_directory("/jb", 0, 0755), @"Failed to create jailbreak directory.", true);
    _assert(chdir("/jb") == ERR_SUCCESS, @"Failed to create jailbreak directory.", true);
    LOGME("Successfully created jailbreak directory.");
    
    
    NSString *offsetsFile = @"/jb/offsets.plist";
    NSMutableDictionary *dictionary = [NSMutableDictionary new];
    #define ADDRSTRING(val)        [NSString stringWithFormat:@ADDR, val]
    #define CACHEADDR(value, name) do { \
    dictionary[@(name)] = ADDRSTRING(value); \
    } while (false)
    #define CACHEOFFSET(offset, name) CACHEADDR(GETOFFSET(offset), name)
        CACHEADDR(kbase, "KernelBase");
        CACHEADDR(kernel_slide, "KernelSlide");
        CACHEOFFSET(trustcache, "TrustChain");
        CACHEADDR(ReadKernel64(GETOFFSET(OSBoolean_True)), "OSBooleanTrue");
        CACHEADDR(ReadKernel64(GETOFFSET(OSBoolean_True)) + sizeof(void *), "OSBooleanFalse");
        CACHEOFFSET(osunserializexml, "OSUnserializeXML");
        CACHEOFFSET(smalloc, "Smalloc");
        CACHEOFFSET(add_x0_x0_0x40_ret, "AddRetGadget");
        CACHEOFFSET(zone_map_ref, "ZoneMapOffset");
        CACHEOFFSET(vfs_context_current, "VfsContextCurrent");
        CACHEOFFSET(vnode_lookup, "VnodeLookup");
        CACHEOFFSET(vnode_put, "VnodePut");
        CACHEOFFSET(kernel_task, "KernelTask");
        CACHEOFFSET(lck_mtx_lock, "LckMtxLock");
        CACHEOFFSET(lck_mtx_unlock, "LckMtxUnlock");
        CACHEOFFSET(vnode_get_snapshot, "VnodeGetSnapshot");
        CACHEOFFSET(fs_lookup_snapshot_metadata_by_name_and_return_name, "FsLookupSnapshotMetadataByNameAndReturnName");
        CACHEOFFSET(pmap_load_trust_cache, "PmapLoadTrustCache");
        CACHEOFFSET(apfs_jhash_getvnode, "APFSJhashGetVnode");
        CACHEOFFSET(paciza_pointer__l2tp_domain_module_start, "PacizaPointerL2TPDomainModuleStart");
        CACHEOFFSET(paciza_pointer__l2tp_domain_module_stop, "PacizaPointerL2TPDomainModuleStop");
        CACHEOFFSET(l2tp_domain_inited, "L2TPDomainInited");
        CACHEOFFSET(sysctl__net_ppp_l2tp, "SysctlNetPPPL2TP");
        CACHEOFFSET(sysctl_unregister_oid, "SysctlUnregisterOid");
        CACHEOFFSET(mov_x0_x4__br_x5, "MovX0X4BrX5");
        CACHEOFFSET(mov_x9_x0__br_x1, "MovX9X0BrX1");
        CACHEOFFSET(mov_x10_x3__br_x6, "MovX10X3BrX6");
        CACHEOFFSET(kernel_forge_pacia_gadget, "KernelForgePaciaGadget");
        CACHEOFFSET(kernel_forge_pacda_gadget, "KernelForgePacdaGadget");
        CACHEOFFSET(IOUserClient__vtable, "IOUserClientVtable");
        CACHEOFFSET(IORegistryEntry__getRegistryEntryID, "IORegistryEntryGetRegistryEntryID");
        CACHEOFFSET(allproc, "AllProc");
    #undef CACHEOFFSET
    #undef CACHEADDR
    if (![[NSMutableDictionary dictionaryWithContentsOfFile:offsetsFile] isEqual:dictionary]) {
        // Cache offsets.
        
        LOGME("Caching offsets...");
        _assert(([dictionary writeToFile:offsetsFile atomically:YES]), @"Failed to cache offsets.", true);
        _assert(init_file(offsetsFile.UTF8String, 0, 0644), @"Failed to cache offsets.", true);
        LOGME("Successfully cached offsets.");
    }
}


void getOffsets() {
    #define GO(x) do { \
    SETOFFSET(x, find_symbol("_" #x)); \
    if (!ISADDR(GETOFFSET(x))) SETOFFSET(x, find_ ##x()); \
    LOGME(#x " = " ADDR " + " ADDR, GETOFFSET(x), kernel_slide); \
    _assert(ISADDR(GETOFFSET(x)), @"Failed to find " #x " offset.", true); \
    SETOFFSET(x, GETOFFSET(x) + kernel_slide); \
    } while (false)
    //For jelbrekd
    SETOFFSET(allproc, find_allproc());
    LOGME("allproc = " ADDR " + " ADDR, GETOFFSET(allproc), kernel_slide);
    //Okay continue lmao
    GO(trustcache);
    GO(OSBoolean_True);
    GO(osunserializexml);
    GO(smalloc);
    if (!auth_ptrs) {
        GO(add_x0_x0_0x40_ret);
    }
    GO(zone_map_ref);
    GO(vfs_context_current);
    GO(vnode_lookup);
    GO(vnode_put);
    GO(kernel_task);
    GO(lck_mtx_lock);
    GO(lck_mtx_unlock);
    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        GO(vnode_get_snapshot);
        GO(fs_lookup_snapshot_metadata_by_name_and_return_name);
        GO(apfs_jhash_getvnode);
    }
    if (auth_ptrs) {
        GO(pmap_load_trust_cache);
        GO(paciza_pointer__l2tp_domain_module_start);
        GO(paciza_pointer__l2tp_domain_module_stop);
        GO(l2tp_domain_inited);
        GO(sysctl__net_ppp_l2tp);
        GO(sysctl_unregister_oid);
        GO(mov_x0_x4__br_x5);
        GO(mov_x9_x0__br_x1);
        GO(mov_x10_x3__br_x6);
        GO(kernel_forge_pacia_gadget);
        GO(kernel_forge_pacda_gadget);
        GO(IOUserClient__vtable);
        GO(IORegistryEntry__getRegistryEntryID);
    }
    
    #undef GO
    found_offs = true;
    term_kernel();
}



void list_all_snapshots(const char **snapshots, const char *origfs, bool has_origfs)
{
    for (const char **snapshot = snapshots; *snapshot; snapshot++) {
        if (strcmp(origfs, *snapshot) == 0) {
            has_origfs = true;
        }
        LOGME("%s", *snapshot);
    }
}

void clear_dev_flags(const char *thedisk)
{
    uint64_t devVnode = vnodeForPath(thedisk);
    _assert(ISADDR(devVnode), @"Failed to clear dev vnode's si_flags.", true);
    uint64_t v_specinfo = kernel_read64(devVnode + koffset(KSTRUCT_OFFSET_VNODE_VU_SPECINFO));
    _assert(ISADDR(v_specinfo), @"Failed to clear dev vnode's si_flags.", true);
    kernel_write32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS), 0);
    uint32_t si_flags = kernel_read32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS));
    _assert(si_flags == 0, @"Failed to clear dev vnode's si_flags.", true);
    _assert(_vnode_put(devVnode) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
}

uint64_t get_kernel_cred_addr()
{
    uint64_t kernel_proc_struct_addr = ReadKernel64(ReadKernel64(GETOFFSET(kernel_task)) + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
    return ReadKernel64(kernel_proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_UCRED));
}


int waitFF(const char *filename) {
    int rv = 0;
    rv = access(filename, F_OK);
    for (int i = 0; !(i >= 100 || rv == ERR_SUCCESS); i++) {
        usleep(100000);
        rv = access(filename, F_OK);
    }
    return rv;
}

void set_platform_binary(uint64_t proc)
{
    uint64_t task_struct_addr = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    uint32_t task_t_flags = ReadKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS));
    task_t_flags |= 0x00000400;
    WriteKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS), task_t_flags);
}




void renameSnapshot(int rootfd, const char* rootFsMountPoint, const char **snapshots, const char *origfs)
{
    LOGME("Renaming snapshot...");
    rootfd = open(rootFsMountPoint, O_RDONLY);
    _assert(rootfd > 0, @"Error renaming snapshot", true);
    snapshots = snapshot_list(rootfd);
    _assert(snapshots != NULL, @"Error renaming snapshot", true);
    LOGME("Snapshots on newly mounted RootFS:");
    for (const char **snapshot = snapshots; *snapshot; snapshot++) {
        LOGME("\t%s", *snapshot);
    }
    free(snapshots);
    snapshots = NULL;
    NSString *systemVersionPlist = @"/System/Library/CoreServices/SystemVersion.plist";
    NSString *rootSystemVersionPlist = [@(rootFsMountPoint) stringByAppendingPathComponent:systemVersionPlist];
    _assert(rootSystemVersionPlist != nil, @"Error renaming snapshot", true);
    NSDictionary *snapshotSystemVersion = [NSDictionary dictionaryWithContentsOfFile:systemVersionPlist];
    _assert(snapshotSystemVersion != nil, @"Error renaming snapshot", true);
    NSDictionary *rootfsSystemVersion = [NSDictionary dictionaryWithContentsOfFile:rootSystemVersionPlist];
    _assert(rootfsSystemVersion != nil, @"Error renaming snapshot", true);
    if (![rootfsSystemVersion[@"ProductBuildVersion"] isEqualToString:snapshotSystemVersion[@"ProductBuildVersion"]]) {
        LOGME("snapshot VersionPlist: %@", snapshotSystemVersion);
        LOGME("rootfs VersionPlist: %@", rootfsSystemVersion);
        _assert("BuildVersions match"==NULL, @"Error renaming snapshot/root_msg", true);
    }
    const char *test_snapshot = "test-snapshot";
    _assert(fs_snapshot_create(rootfd, test_snapshot, 0) == ERR_SUCCESS, @"Error renaming snapshot", true);
    _assert(fs_snapshot_delete(rootfd, test_snapshot, 0) == ERR_SUCCESS, @"Error renaming snapshot", true);
    char *systemSnapshot = copySystemSnapshot();
    _assert(systemSnapshot != NULL, @"Error renaming snapshot", true);
    uint64_t system_snapshot_vnode = 0;
    uint64_t system_snapshot_vnode_v_data = 0;
    uint32_t system_snapshot_vnode_v_data_flag = 0;
    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        system_snapshot_vnode = vnodeForSnapshot(rootfd, systemSnapshot);
        LOGME("system_snapshot_vnode = " ADDR, system_snapshot_vnode);
        _assert(ISADDR(system_snapshot_vnode),  @"Error renaming snapshot", true);
        system_snapshot_vnode_v_data = ReadKernel64(system_snapshot_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_DATA));
        LOGME("system_snapshot_vnode_v_data = " ADDR, system_snapshot_vnode_v_data);
        _assert(ISADDR(system_snapshot_vnode_v_data),  @"Error renaming snapshot", true);
        system_snapshot_vnode_v_data_flag = ReadKernel32(system_snapshot_vnode_v_data + 49);
        LOGME("system_snapshot_vnode_v_data_flag = 0x%x", system_snapshot_vnode_v_data_flag);
        WriteKernel32(system_snapshot_vnode_v_data + 49, system_snapshot_vnode_v_data_flag & ~0x40);
    }
    _assert(fs_snapshot_rename(rootfd, systemSnapshot, origfs, 0) == ERR_SUCCESS,  @"Error renaming snapshot", true);
    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        WriteKernel32(system_snapshot_vnode_v_data + 49, system_snapshot_vnode_v_data_flag);
        _assert(_vnode_put(system_snapshot_vnode) == ERR_SUCCESS,  @"Error renaming snapshot", true);
    }
    free(systemSnapshot);
    systemSnapshot = NULL;
    LOGME("Successfully renamed system snapshot.");
    
    
    NOTICE(NSLocalizedString(@"Snapshot Renamed! (Just in case something goes wrong and you need to restore your RootFS). We are going to reboot your device now.", nil), 1, 1);
    
    // Reboot.
    close(rootfd);
    
    LOGME("Rebooting...");
    reboot(RB_QUICK);
}

void preMountFS(const char *thedisk, int root_fs, const char **snapshots, const char *origfs)
{
    LOGME("Pre-Mounting RootFS...");
    _assert(!is_mountpoint("/var/MobileSoftwareUpdate/mnt1"), @"RootFS already mounted, delete OTA file from Settings - Storage if present and reboot.", true);
    const char *rootFsMountPoint = "/private/var/tmp/jb/mnt1";
    if (is_mountpoint(rootFsMountPoint)) {
        _assert(unmount(rootFsMountPoint, MNT_FORCE) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
    }
    _assert(clean_file(rootFsMountPoint), @"Failed to clear dev vnode's si_flags.", true);
    _assert(ensure_directory(rootFsMountPoint, 0, 0755), @"Failed to clear dev vnode's si_flags.", true);
    const char *argv[] = {"/sbin/mount_apfs", thedisk, rootFsMountPoint, NULL};
    _assert(execCmdV(argv[0], 3, argv, ^(pid_t pid) {
        uint64_t procStructAddr = get_proc_struct_for_pid(pid);
        LOGME("procStructAddr = " ADDR, procStructAddr);
        _assert(ISADDR(procStructAddr), @"Failed to clear dev vnode's si_flags.", true);
        give_creds_to_process_at_addr(procStructAddr, get_kernel_cred_addr());
    }) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
    _assert(execCmd("/sbin/mount", NULL) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
    const char *systemSnapshotLaunchdPath = [@(rootFsMountPoint) stringByAppendingPathComponent:@"sbin/launchd"].UTF8String;
    _assert(waitFF(systemSnapshotLaunchdPath) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
    LOGME("Successfully mounted RootFS.");
    
    renameSnapshot(root_fs, rootFsMountPoint, snapshots, origfs);
}



int trust_file(NSString *path) {
    
    NSMutableArray *paths = [NSMutableArray new];
    
    [paths addObject:path];
    
    injectTrustCache(paths, GETOFFSET(trustcache), pmap_load_trust_cache);
    
    return 0;
}

static inline bool create_file_data(const char *file, int owner, mode_t mode, NSData *data) {
    return [[NSFileManager defaultManager] createFileAtPath:@(file) contents:data attributes:@{
                                                                                               NSFileOwnerAccountID: @(owner),
                                                                                               NSFileGroupOwnerAccountID: @(owner),
                                                                                               NSFilePosixPermissions: @(mode)
                                                                                               }
            ];
}

static inline bool create_file(const char *file, int owner, mode_t mode) {
    return create_file_data(file, owner, mode, nil);
}


NSString *get_path_file(NSString *resource) {
    NSString *sourcePath = [[NSBundle mainBundle] bundlePath];
    NSString *path = [[sourcePath stringByAppendingPathComponent:resource] stringByStandardizingPath];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return nil;
    }
    return path;
}

int waitForFile(const char *filename) {
    int rv = 0;
    rv = access(filename, F_OK);
    for (int i = 0; !(i >= 100 || rv == ERR_SUCCESS); i++) {
        usleep(100000);
        rv = access(filename, F_OK);
    }
    return rv;
}


void remountFS() {
    
    //Vars
    int root_fs = open("/", O_RDONLY);
    
    _assert(root_fs > 0, @"Error Opening The Root Filesystem!", true);
    
    const char **snapshots = snapshot_list(root_fs);
    const char *origfs = "orig-fs";
    bool isOriginalFS = false;
    const char *root_disk = "/dev/disk0s1s1";

    if (snapshots == NULL) {
        
        LOGME("No System Snapshot Found! Don't worry, I'll Make One!");
        
        //Clear Dev Flags
        uint64_t devVnode = vnodeForPath(root_disk);
        _assert(ISADDR(devVnode), @"Failed to clear dev vnode's si_flags.", true);
        uint64_t v_specinfo = ReadKernel64(devVnode + koffset(KSTRUCT_OFFSET_VNODE_VU_SPECINFO));
        _assert(ISADDR(v_specinfo), @"Failed to clear dev vnode's si_flags.", true);
        WriteKernel32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS), 0);
        uint32_t si_flags = ReadKernel32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS));
        _assert(si_flags == 0, @"Failed to clear dev vnode's si_flags.", true);
        _assert(_vnode_put(devVnode) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
        
        //Pre-Mount
        preMountFS(root_disk, root_fs, snapshots, origfs);
        
        close(root_fs);
    }
    
    list_all_snapshots(snapshots, origfs, isOriginalFS);
    
    uint64_t rootfs_vnode = vnodeForPath("/");
    LOGME("rootfs_vnode = " ADDR, rootfs_vnode);
    _assert(ISADDR(rootfs_vnode), @"Failed to mount", true);
    uint64_t v_mount = ReadKernel64(rootfs_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_MOUNT));
    LOGME("v_mount = " ADDR, v_mount);
    _assert(ISADDR(v_mount), @"Failed to mount", true);
    uint32_t v_flag = ReadKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG));
    if ((v_flag & (MNT_RDONLY | MNT_NOSUID))) {
        v_flag = v_flag & ~(MNT_RDONLY | MNT_NOSUID);
        WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag & ~MNT_ROOTFS);
        _assert(execCmd("/sbin/mount", "-u", root_disk, NULL) == ERR_SUCCESS, @"Failed to mount", true);
        WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag);
    }
    _assert(_vnode_put(rootfs_vnode) == ERR_SUCCESS, @"Failed to mount", true);
    _assert(execCmd("/sbin/mount", NULL) == ERR_SUCCESS, @"Failed to mount", true);
    
}

bool is_symlink(const char *filename) {
    struct stat buf;
    if (lstat(filename, &buf) != ERR_SUCCESS) {
        return false;
    }
    return S_ISLNK(buf.st_mode);
}

bool mod_plist_file(NSString *filename, void (^function)(id)) {
    LOGME("%s: Will modify plist: %@", __FUNCTION__, filename);
    NSData *data = [NSData dataWithContentsOfFile:filename];
    if (data == nil) {
        LOGME("%s: Failed to read file: %@", __FUNCTION__, filename);
        return false;
    }
    NSPropertyListFormat format = 0;
    NSError *error = nil;
    id plist = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListMutableContainersAndLeaves format:&format error:&error];
    if (plist == nil) {
        LOGME("%s: Failed to generate plist data: %@", __FUNCTION__, error);
        return false;
    }
    if (function) {
        function(plist);
    }
    NSData *newData = [NSPropertyListSerialization dataWithPropertyList:plist format:format options:0 error:&error];
    if (newData == nil) {
        LOGME("%s: Failed to generate new plist data: %@", __FUNCTION__, error);
        return false;
    }
    if (![data isEqual:newData]) {
        LOGME("%s: Writing to file: %@", __FUNCTION__, filename);
        if (![newData writeToFile:filename atomically:YES]) {
            LOGME("%s: Failed to write to file: %@", __FUNCTION__, filename);
            return false;
        }
    }
    LOGME("%s: Success", __FUNCTION__);
    return true;
}



void restoreRootFS()
{
    LOGME("Restoring RootFS....");
    
    //NOTICE(NSLocalizedString(@"Restoring RootFS. Do not lock, or reboot the device!", nil), 1, 1);
    LOGME("Renaming system snapshot back...");
    int rootfd = open("/", O_RDONLY);
    _assert(rootfd > 0, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
    const char **snapshots = snapshot_list(rootfd);
    _assert(snapshots != NULL, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
    const char *snapshot = *snapshots;
    LOGME("%s", snapshot);
    _assert(snapshot != NULL, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
    
    char *systemSnapshot = copySystemSnapshot();
    _assert(systemSnapshot != NULL, @"Failed to mount", true);
    _assert(fs_snapshot_rename(rootfd, snapshot, systemSnapshot, 0) == ERR_SUCCESS, @"ERROR RENAMING SNAPSHOT!", true);
    
    
    free(systemSnapshot);
    systemSnapshot = NULL;
    close(rootfd);
    free(snapshots);
    snapshots = NULL;
    
    LOGME("Successfully renamed system snapshot back.");
    
    // Clean up.
    
    static const char *cleanUpFileList[] = {
        "/var/cache",
        "/var/lib",
        "/var/stash",
        "/var/db/stash",
        "/var/mobile/Library/Cydia",
        "/var/mobile/Library/Caches/com.saurik.Cydia",
        NULL
    };
    for (const char **file = cleanUpFileList; *file != NULL; file++) {
        clean_file(*file);
    }
    LOGME("Successfully cleaned up.");
    
    // Disallow SpringBoard to show non-default system apps.
    
    LOGME("Disallowing SpringBoard to show non-default system apps...");
    _assert(mod_plist_file(@"/var/mobile/Library/Preferences/com.apple.springboard.plist", ^(id plist) {
        plist[@"SBShowNonDefaultSystemApps"] = @NO;
    }), @"Failed to disallow SpringBoard to show non-default system apps.", true);
    LOGME("Successfully disallowed SpringBoard to show non-default system apps.");
    
    
    // Reboot.
    
    NOTICE(NSLocalizedString(@"RootFS Restored! We will reboot your device.", nil), 1, 1);
    
    LOGME("Rebooting...");
    reboot(RB_QUICK);
    
}


void ux_tfp0(host_t orig_host, uint32_t type)
{
    uint64_t hostport_addr = get_address_of_port(getpid(), orig_host);
    uint32_t old = ReadKernel32(hostport_addr);
    if ((old & type) != type) {
        WriteKernel32(hostport_addr, type);
    }
}

bool ensure_symlink(const char *to, const char *from) {
    ssize_t wantedLength = strlen(to);
    ssize_t maxLen = wantedLength + 1;
    char link[maxLen];
    ssize_t linkLength = readlink(from, link, sizeof(link));
    if (linkLength != wantedLength ||
        strncmp(link, to, maxLen) != ERR_SUCCESS
        ) {
        if (!clean_file(from)) {
            return false;
        }
        if (symlink(to, from) != ERR_SUCCESS) {
            return false;
        }
    }
    return true;
}

int systemCmd(const char *cmd) {
    const char *argv[] = {"sh", "-c", (char *)cmd, NULL};
    return execCmdV("/bin/sh", 3, argv, NULL);
}

bool runDpkg(NSArray <NSString*> *args, bool forceDeps) {
    if ([args count] < 2) {
        LOGME("%s: Nothing to do", __FUNCTION__);
        return false;
    }
    NSMutableArray <NSString*> *command = [NSMutableArray
                                           arrayWithArray:@[
                                                            @"/usr/bin/dpkg",
                                                            @"--force-bad-path",
                                                            @"--force-configure-any",
                                                            @"--no-triggers"
                                                            ]];
    
    if (forceDeps) {
        [command addObjectsFromArray:@[@"--force-depends", @"--force-remove-essential"]];
    }
    for (NSString *arg in args) {
        [command addObject:arg];
    }
    const char *argv[command.count];
    for (int i=0; i<[command count]; i++) {
        argv[i] = [command[i] UTF8String];
    }
    argv[command.count] = NULL;
    int rv = execCmdV("/usr/bin/dpkg", (int)[command count], argv, NULL);
    return !WEXITSTATUS(rv);
}

bool installDeb(const char *debName, bool forceDeps) {
    return runDpkg(@[@"-i", @(debName)], forceDeps);
}



pid_t pidOfProcess(const char *name) {
    int numberOfProcesses = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    pid_t pids[numberOfProcesses];
    bzero(pids, sizeof(pids));
    proc_listpids(PROC_ALL_PIDS, 0, pids, (int)sizeof(pids));
    for (int i = 0; i < numberOfProcesses; ++i) {
        if (pids[i] == 0) {
            continue;
        }
        char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
        bzero(pathBuffer, PROC_PIDPATHINFO_MAXSIZE);
        proc_pidpath(pids[i], pathBuffer, sizeof(pathBuffer));
        if (strlen(pathBuffer) > 0 && strcmp(pathBuffer, name) == 0) {
            return pids[i];
        }
    }
    return 0;
}

NSString *get_path_res(NSString *resource) {
    static NSString *sourcePath;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sourcePath = [[NSBundle mainBundle] bundlePath];
    });
    
    NSString *path = [[sourcePath stringByAppendingPathComponent:resource] stringByStandardizingPath];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return nil;
    }
    return path;
}

uint64_t give_creds_to_addr(uint64_t proc, uint64_t cred_addr)
{
    uint64_t orig_creds = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    WriteKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), cred_addr);
    return orig_creds;
}

bool runApt(NSArray <NSString*> *args) {
    if ([args count] < 1) {
        LOGME("%s: Nothing to do", __FUNCTION__);
        return false;
    }
    NSMutableArray <NSString*> *command = [NSMutableArray arrayWithArray:@[
                                                                           @"/usr/bin/apt-get",
                                                                           @"-o", @"Dir::Etc::sourcelist=tw3lve/tw3lve.list",
                                                                           @"-o", @"Dir::Etc::sourceparts=-",
                                                                           @"-o", @"APT::Get::List-Cleanup=0"
                                                                           ]];
    [command addObjectsFromArray:args];
    
    const char *argv[command.count];
    for (int i=0; i<[command count]; i++) {
        argv[i] = [command[i] UTF8String];
    }
    argv[command.count] = NULL;
    int rv = execCmdV(argv[0], (int)[command count], argv, NULL);
    return !WEXITSTATUS(rv);
}


void is_unc0ver_installed()
{
    int f = open("/.installed_unc0ver", O_RDONLY);
    
    if (!(f == -1))
    {
        NOTICE(NSLocalizedString(@"Unc0ver Has Been Detected! Please remove Unc0ver and restore rootfs before using Tw3lve. We are going to reboot your device.", nil), 1, 1);
        //restoreRootFS();
        reboot(RB_QUICK);
    }
    
}



void is_last_surprise_installed()
{
    int f = open("/.installed_last_surprise", O_RDONLY);
    
    if (!(f == -1))
    {
        NOTICE(NSLocalizedString(@"Last_Surprise Has Been Detected! Please remove Last_Surprise before using Tw3lve. We are going to reboot your device. We can restore your snapshot if you like.", nil), 1, 1);
        restoreRootFS();
        //reboot(RB_QUICK);
    }
    
}

void is_electra12_installed()
{
    int f = open("/Library/LaunchDaemons/jailbreakd.plist", O_RDONLY);
    
    if (!(f == -1))
    {
        NOTICE(NSLocalizedString(@"Another jailbreak Has Been Detected! Please remove the other jailbreak before using Tw3lve. We are going to reboot your device. We can restore your snapshot if you like.", nil), 1, 1);
        restoreRootFS();
        //reboot(RB_QUICK);
        
    }
    
}

void addToArray(NSString *package, NSMutableArray *array)
{
    NSString *dir = [[[NSBundle mainBundle] bundlePath] stringByAppendingString:@"/bootstrap/debs/"];
    NSString *strToAdd = [dir stringByAppendingString:package];
    
    [array addObject:strToAdd];
}


void extractSubstrate()
{
    NSString *substrateFile = get_path_res(@"bootstrap/Substrate.tar");
    ArchiveFile *subBSFile = [ArchiveFile archiveWithFile:substrateFile];
    [subBSFile extractToPath:@"/"];
    
    chdir("/");
    NSMutableArray *arrayToInject = [NSMutableArray new];
    NSDictionary *filesToInject = subBSFile.files;
    for (NSString *file in filesToInject.allKeys) {
        if (cdhashFor(file) != nil) {
            [arrayToInject addObject:file];
        }
    }
    LOGME("Injecting...");
    for (NSString *fileToInject in arrayToInject)
    {
        LOGME("CURRENTLY INJECTING: %@", fileToInject);
        trust_file(fileToInject);
    }
}

void extractRes()
{
    NSString *resFile = get_path_res(@"bootstrap/JBRes.tar");
    ArchiveFile *resBSFile = [ArchiveFile archiveWithFile:resFile];
    [resBSFile extractToPath:@"/"];
    
    chdir("/");
    NSMutableArray *arrayToInject = [NSMutableArray new];
    NSDictionary *filesToInject = resBSFile.files;
    for (NSString *file in filesToInject.allKeys) {
        if (cdhashFor(file) != nil) {
            [arrayToInject addObject:file];
        }
    }
    LOGME("Injecting...");
    for (NSString *fileToInject in arrayToInject)
    {
        LOGME("CURRENTLY INJECTING: %@", fileToInject);
        trust_file(fileToInject);
    }
    
    if (access("/usr/bin/ldid", F_OK) != ERR_SUCCESS) {
        _assert(access("/usr/libexec/ldid", F_OK) == ERR_SUCCESS, @"Failed to copy over our resources to RootFS.", true);
        _assert(ensure_symlink("../libexec/ldid", "/usr/bin/ldid"), @"Failed to copy over our resources to RootFS.", true);
    }
    
}

void extractLZMA()
{
    NSString *resFile = get_path_res(@"bootstrap/LZMA.tar");
    ArchiveFile *resBSFile = [ArchiveFile archiveWithFile:resFile];
    [resBSFile extractToPath:@"/"];
    
    chdir("/");
    NSMutableArray *arrayToInject = [NSMutableArray new];
    NSDictionary *filesToInject = resBSFile.files;
    for (NSString *file in filesToInject.allKeys) {
        if (cdhashFor(file) != nil) {
            [arrayToInject addObject:file];
        }
    }
    LOGME("Injecting...");
    for (NSString *fileToInject in arrayToInject)
    {
        LOGME("CURRENTLY INJECTING: %@", fileToInject);
        trust_file(fileToInject);
    }
}


void extractDPKG()
{
    NSString *resFile = get_path_res(@"bootstrap/DPKG.tar");
    ArchiveFile *resBSFile = [ArchiveFile archiveWithFile:resFile];
    [resBSFile extractToPath:@"/"];
    
    chdir("/");
    NSMutableArray *arrayToInject = [NSMutableArray new];
    NSDictionary *filesToInject = resBSFile.files;
    for (NSString *file in filesToInject.allKeys) {
        if (cdhashFor(file) != nil) {
            [arrayToInject addObject:file];
        }
    }
    LOGME("Injecting...");
    for (NSString *fileToInject in arrayToInject)
    {
        LOGME("CURRENTLY INJECTING: %@", fileToInject);
        trust_file(fileToInject);
    }
}


void fixFS()
{
    LOGME("[Tw3lveStrap] Fixing Fileystem");
    _assert(ensure_directory("/var/lib", 0, 0755), @"Failed to repair filesystem.", true);
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir;
    if ([fm fileExistsAtPath:@"/var/lib/dpkg" isDirectory:&isDir] && isDir) {
        if ([fm fileExistsAtPath:@"/Library/dpkg" isDirectory:&isDir] && isDir) {
            LOGME(@"Removing /var/lib/dpkg...");
            _assert([fm removeItemAtPath:@"/var/lib/dpkg" error:nil], @"Failed to repair filesystem.", true);
        } else {
            LOGME(@"Moving /var/lib/dpkg to /Library/dpkg...");
            _assert([fm moveItemAtPath:@"/var/lib/dpkg" toPath:@"/Library/dpkg" error:nil], @"Failed to repair filesystem.", true);
        }
    }
    
    _assert(ensure_symlink("/Library/dpkg", "/var/lib/dpkg"), @"Failed to repair filesystem.", true);
    _assert(ensure_directory("/Library/dpkg", 0, 0755), @"Failed to repair filesystem.", true);
    _assert(ensure_file("/var/lib/dpkg/status", 0, 0644), @"Failed to repair filesystem.", true);
    _assert(ensure_file("/var/lib/dpkg/available", 0, 0644), @"Failed to repair filesystem.", true);
    NSString *file = [NSString stringWithContentsOfFile:@"/var/lib/dpkg/info/firmware-sbin.list" encoding:NSUTF8StringEncoding error:nil];
    if ([file rangeOfString:@"/sbin/fstyp"].location != NSNotFound || [file rangeOfString:@"\n\n"].location != NSNotFound) {
        file = [file stringByReplacingOccurrencesOfString:@"/sbin/fstyp\n" withString:@""];
        file = [file stringByReplacingOccurrencesOfString:@"\n\n" withString:@"\n"];
        [file writeToFile:@"/var/lib/dpkg/info/firmware-sbin.list" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    _assert(ensure_symlink("/usr/lib", "/usr/lib/_ncurses"), message, true);
    _assert(ensure_directory("/Library/Caches", 0, S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO), message, true);
    LOGME("[Tw3lveStrap] Finished Fixing Filesystem!");
}


void createLocalRepo()
{
    _assert(ensure_directory("/etc/apt/tw3lve", 0, 0755), @"Failed to extract bootstrap.", true);
    clean_file("/etc/apt/sources.list.d/tw3lve");
    const char *listPath = "/etc/apt/tw3lve/tw3lve.list";
    NSString *listContents = @"deb file:///var/lib/tw3lve/apt ./\n";
    NSString *existingList = [NSString stringWithContentsOfFile:@(listPath) encoding:NSUTF8StringEncoding error:nil];
    if (![listContents isEqualToString:existingList]) {
        clean_file(listPath);
        [listContents writeToFile:@(listPath) atomically:NO encoding:NSUTF8StringEncoding error:nil];
    }
    init_file(listPath, 0, 0644);
    NSString *repoPath = [[[NSBundle mainBundle] bundlePath] stringByAppendingString:@"/bootstrap/debs"];
    _assert(repoPath != nil, @"Repo path is null!", true);
    ensure_directory("/var/lib/tw3lve", 0, 0755);
    ensure_symlink([repoPath UTF8String], "/var/lib/tw3lve/apt");
    
    runApt(@[@"update"]);
    
    // Workaround for what appears to be an apt bug
    ensure_symlink("/var/lib/tw3lve/apt/./Packages", "/var/lib/apt/lists/_var_lib_tw3lve_apt_._Packages");
}


void disableStashing()
{
    if (access("/.cydia_no_stash", F_OK) != ERR_SUCCESS) {
        // Disable stashing.
        
        LOGME("Disabling stashing...");
        _assert(create_file("/.cydia_no_stash", 0, 0644), @"Failed to disable stashing.", true);
        LOGME("Successfully disabled stashing.");
    }
}

bool restartSpringBoard() {
    pid_t backboardd_pid = pidOfProcess("/usr/libexec/backboardd");
    
    //pid_t backboardd_pid = pidOfProcess("/System/Library/CoreServices/SpringBoard.app/SpringBoard");
    
    if (!(backboardd_pid > 1)) {
        LOGME("Unable to find backboardd pid.");
        return false;
    }
    if (kill(backboardd_pid, SIGTERM) != ERR_SUCCESS) {
        LOGME("Unable to terminate backboardd.");
        return false;
    }
    return true;
}

void startSubstrate()
{
    LOGME("Starting Substrate...");
    if (!is_symlink("/usr/lib/substrate")) {
        _assert([[NSFileManager defaultManager] moveItemAtPath:@"/usr/lib/substrate" toPath:@"/Library/substrate" error:nil], @"Where is substrate? ERROR", true);
        _assert(ensure_symlink("/Library/substrate", "/usr/lib/substrate"), @"Failed to (re)start Substrate", true);
    }
    _assert(execCmd("/usr/libexec/substrate", NULL) == ERR_SUCCESS, @"Failed to restart Substrate", skipSubstrate?false:true);
    LOGME("Successfully started Substrate.");
}

void injectFinish()
{
    NSArray *resources = [NSArray arrayWithContentsOfFile:@"/usr/share/jailbreak/injectme.plist"];
    // If substrate is already running but was broken, skip injecting again
    resources = [@[@"/usr/libexec/substrate"] arrayByAddingObjectsFromArray:resources];
    for (NSString *toInject in resources)
    {
        trust_file(toInject);
    }
    trust_file(@"/usr/libexec/substrated");
}

void finishCydia()
{
    
    LOGME("[Tw3lveStrap] Disabling Stashing... (Cydia)");
    disableStashing();
    LOGME("[Tw3lveStrap] Disabled Stashing! (Cydia)");
    
    LOGME("Injecting Final Files...");
    injectFinish();
    LOGME("Fnished Injecting Final Files!");
    startSubstrate();
    
    installDeb([[[[NSBundle mainBundle] bundlePath] stringByAppendingString:@"/bootstrap/debs/openssh_7.9p1-3_iphoneos-arm.deb"] UTF8String], false);
    
    systemCmd("echo 'really jailbroken';"
           "shopt -s nullglob;"
           "for a in /Library/LaunchDaemons/*.plist;"
           "do echo loading $a;"
           "launchctl load \"$a\" ;"
           "done; ");
    systemCmd("for file in /etc/rc.d/*; do "
           "if [[ -x \"$file\" && \"$file\" != \"/etc/rc.d/substrate\" ]]; then "
           "\"$file\";"
           "fi;"
           "done");
    systemCmd("nohup bash -c \""
                "sleep 1 ;"
                "launchctl stop com.apple.mDNSResponder ;"
                "launchctl stop com.apple.backboardd"
                "\" >/dev/null 2>&1 &");
}

void installCydia()
{
    
    NSMutableArray *debArray = [NSMutableArray new];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bundleRoot = [[[NSBundle mainBundle] bundlePath] stringByAppendingString:@"/bootstrap/debs/"];
    NSArray *dirContents = [fm contentsOfDirectoryAtPath:bundleRoot error:nil];
    
    int f = open("/.installed_tw3lve", O_RDONLY);
    
    if (f == -1)
    {
        
        LOGME("We Need To Install Tw3lveStrap");
        
        LOGME("[Tw3lveStrap] Extracting Tw3lveStrap... (Substrate)");
        extractSubstrate();
        addToArray(@"mobilesubstrate_0.9.7032_iphoneos-arm.deb", debArray);
        LOGME("[Tw3lveStrap] Extracted! (Substrate)");
        
        LOGME("[Tw3lveStrap] Extracting Tw3lveStrap... (JBRes)");
        extractRes();
        
        
        //Why is it that ig doesn't work if we just install everything at once lol
        for (NSString *pkg in dirContents)
        {
            if (![pkg isEqual: @"mobilesubstrate_0.9.7032_iphoneos-arm.deb"] && ![pkg isEqual: @"lzma2_4.32.7-2_iphoneos-arm.deb"] && ![pkg isEqual: @"dpkg_1.18.25-9_iphoneos-arm.deb"] && ![pkg isEqual: @"cydia_tw3lve.deb"] && ![pkg isEqual: @"cydia-lproj_tw3lve.deb"] && ![pkg isEqual: @"darwintools_1-6_iphoneos-arm.deb"] && ![pkg isEqual: @"uikittools_1.1.13-5_iphoneos-arm.deb"] && ![pkg isEqual: @"system-cmds_790.30.1-2_iphoneos-arm.deb"])
            {
                addToArray(pkg, debArray);
            }
        }
        LOGME("[Tw3lveStrap] Extracted Tw3lveStrap! (JBRes)");
        LOGME("[Tw3lveStrap] Injecting...");
        NSArray *resources = [NSArray arrayWithContentsOfFile:@"/usr/share/jailbreak/injectme.plist"];
        for (NSString *toInject in resources)
        {
            trust_file(toInject);
        }
        trust_file(@"/usr/libexec/substrate");
        LOGME("[Tw3lveStrap] Injected!");
        
        fixFS();
        
        LOGME("[Tw3lveStrap] Starting Substrate...");
        startSubstrate();
        LOGME("[Tw3lveStrap] Started Substrate!");
        
        LOGME("[Tw3lveStrap] Extracting Tw3lveStrap... (LZMA)");
        extractLZMA();
        addToArray(@"lzma2_4.32.7-2_iphoneos-arm.deb", debArray);
        LOGME("[Tw3lveStrap] Extracted! (LZMA)");
        
        LOGME("[Tw3lveStrap] Extracting Tw3lveStrap... (DPKG)");
        extractDPKG();
        LOGME("[Tw3lveStrap] Extracted! (DPKG)");
        
        LOGME("[Tw3lveStrap] Installing Tw3lveStrap... (DPKG)");
        installDeb([[bundleRoot stringByAppendingString:@"dpkg_1.18.25-9_iphoneos-arm.deb"] UTF8String], true);
        LOGME("[Tw3lveStrap] Installed! (DPKG)");
        
        LOGME("[Tw3lveStrap] Installing Tw3lveStrap... (CYDIA)");
        installDeb([[bundleRoot stringByAppendingString:@"cydia_tw3lve.deb"] UTF8String], true);
        installDeb([[bundleRoot stringByAppendingString:@"cydia-lproj_tw3lve.deb"] UTF8String], true);
        installDeb([[bundleRoot stringByAppendingString:@"darwintools_1-6_iphoneos-arm.deb"] UTF8String], true);
        installDeb([[bundleRoot stringByAppendingString:@"uikittools_1.1.13-5_iphoneos-arm.deb"] UTF8String], true);
        installDeb([[bundleRoot stringByAppendingString:@"system-cmds_790.30.1-2_iphoneos-arm.deb"] UTF8String], true);
        LOGME("[Tw3lveStrap] Installed! (CYDIA)");
        
        LOGME("[Tw3lveStrap] Installing Tw3lveStrap... (CYDIA/FIRMWARE)");
        int rv = systemCmd("/usr/libexec/cydia/firmware.sh");
        _assert(WEXITSTATUS(rv) == 0, message, true);
        LOGME("[Tw3lveStrap] Installed! (CYDIA/FIRMWARE)");
        
        LOGME("[Tw3lveStrap] Installing Tw3lveStrap... (bootstrap/debs)");
        for (NSString *pkgToInstall in debArray)
        {
            installDeb([pkgToInstall UTF8String], true);
        }
        LOGME("[Tw3lveStrap] Installed Tw3lveStrap! (bootstrap/debs)");
        
        LOGME("[Tw3lveStrap] Creating Local Repo... (bootstrap/debs)");
        createLocalRepo();
        LOGME("[Tw3lveStrap] Created Local Repo! (bootstrap/debs)");
        
        LOGME("[Tw3lveStrap] Installing Substrate... (APT)");
        runApt([@[@"-y", @"--allow-unauthenticated", @"--allow-downgrades", @"install"]
                arrayByAddingObjectsFromArray:@[@"mobilesubstrate"]]);
        LOGME("[Tw3lveStrap] Installed Substrate! (APT)");
        
        
        _assert(clean_file("/var/mobile/Library/Cydia"), @"Failed Clearing Cydia Caches", true);
        _assert(clean_file("/var/mobile/Library/Caches/com.saurik.Cydia"), @"Failed Clearing Cydia Caches", true);
        
        LOGME("[Tw3lveStrap] Disabling Stashing... (Cydia)");
        disableStashing();
        LOGME("[Tw3lveStrap] Disabled Stashing! (Cydia)");
        
        _assert(mod_plist_file(@"/var/mobile/Library/Preferences/com.apple.springboard.plist", ^(id plist) {
            plist[@"SBShowNonDefaultSystemApps"] = @YES;
        }), @"Failed to edit plist", true);
        
        
        LOGME("[Tw3lveStrap] Installing Cydia... (APT)");
        runApt([@[@"-y", @"--allow-unauthenticated", @"--allow-downgrades", @"install"]
                arrayByAddingObjectsFromArray:@[@"--reinstall", @"cydia"]]);
        LOGME("[Tw3lveStrap] Installed Cydia! (APT)");
        
        
        _assert(clean_file("/var/mobile/Library/Cydia"), @"Failed Clearing Cydia Caches", true);
        _assert(clean_file("/var/mobile/Library/Caches/com.saurik.Cydia"), @"Failed Clearing Cydia Caches", true);
        
        
        LOGME("[Tw3lveStrap] Running UICache...");
        _assert(execCmd("/usr/bin/uicache", NULL) == ERR_SUCCESS, @"Failed To Run UICache", true);
        LOGME("[Tw3lveStrap] Finished Running UICache!");
        
        ensure_file("/.installed_tw3lve", 0, 0644);
        
        NOTICE(NSLocalizedString(@"Tw3lveStrap Has Been Extracted And Installed To This Device! We Are Going To Reboot. Please Jailbreak Upon Rebooting,", nil), 1, 1);
        
        
        reboot(RB_QUICK);
    }
}

void loadTweaks()
{
    clean_file("/var/tmp/.substrated_disable_loader");
}

void dontLoadTweaks()
{
    _assert(create_file("/var/tmp/.substrated_disable_loader", 0, 644), @"Unable To Disable Installation Of Tweaks!", true);
}


//////////SILEO/////////////
void extractSubZeroLol()
{
    NSString *substrateFile = get_path_res(@"bootstrap/sileo/sub_sileo.tar");
    ArchiveFile *subBSFile = [ArchiveFile archiveWithFile:substrateFile];
    [subBSFile extractToPath:@"/"];
    
    chdir("/");
    NSMutableArray *arrayToInject = [NSMutableArray new];
    NSDictionary *filesToInject = subBSFile.files;
    for (NSString *file in filesToInject.allKeys) {
        if (cdhashFor(file) != nil) {
            [arrayToInject addObject:file];
        }
    }
    LOGME("Injecting...");
    for (NSString *fileToInject in arrayToInject)
    {
        LOGME("CURRENTLY INJECTING: %@", fileToInject);
        trust_file(fileToInject);
    }
}


void extractTest()
{
    NSString *substrateFile = get_path_res(@"bootstrap/sileo/test.tar");
    ArchiveFile *subBSFile = [ArchiveFile archiveWithFile:substrateFile];
    [subBSFile extractToPath:@"/"];
    
    chdir("/");
}

void installSileo()
{
    
    NSMutableArray *debArray = [NSMutableArray new];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bundleRoot = [[[NSBundle mainBundle] bundlePath] stringByAppendingString:@"/bootstrap/sileo/debs/"];
    NSArray *dirContents = [fm contentsOfDirectoryAtPath:bundleRoot error:nil];
    
    int f = open("/.installed_tw3lve", O_RDONLY);
    int f2 = open("/.installed_sileo_t3", O_RDONLY);
    if (f == -1)
    {
        if (f2 == -1)
        {
            LOGME("We Need To Install Tw3lveStrap");
            LOGME("[Tw3lveStrap] Extracting Tw3lveStrap... (Substitute)");
            extractRes();
            extractSubZeroLol();
            extractTest();
            LOGME("[Tw3lveStrap] Extracted! (Substitute)");
            
            pid_t pd;
            posix_spawn(&pd, "/bin/launchctl", NULL, NULL, (char **)&(const char*[]){"launchctl", "load",  "/Library/LaunchDaemons/com.ex.substituted.plist", NULL}, NULL);
            waitpid(pd, NULL, 0);
            
            execCmd("/jb/jelbrekd_client", NULL);
            
        }
        
    } else {
        NOTICE(NSLocalizedString(@"Cydia Detected! Please Restore RootFS Before Using Sileo!", nil), 1, 1);
    }
}

