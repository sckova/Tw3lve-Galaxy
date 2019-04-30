//
//  ViewController.m
//  tw3lve
//
//  Created by Tanay Findley on 4/7/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#import "Tw3lveView.h"
#include "KernelMemory.h"
#include "OffsetHolder.h"
#include "KernelUtils.h"
#include "ms_offsets.h"
#include "machswap.h"
#include "VarHolder.h"
#include "patchfinder64.h"
#include "utils.h"
#include "voucher_swap.h"
#include "kernel_slide.h"
#include "kernel_memory.h"
#include "PFOffs.h"
#include "offsets.h"
#include "Tw3lveSettings.h"
#include "machswap2.h"
#include <sys/sysctl.h>

#include "remap_tfp_set_hsp.h"

#include "kernel_exec.h"

#define KERNEL_SEARCH_ADDRESS 0xfffffff007004000

@interface Tw3lveView ()
{
    
    IBOutlet UILabel *iosVers;
    IBOutlet UILabel *DeviceString;
    IBOutlet UIButton *leButton;
}

@property (strong, nonatomic) IBOutlet UITextView *uiLog;


@end

@implementation Tw3lveView



Tw3lveView *sharedController = nil;

- (void)viewDidLoad {
    [super viewDidLoad];
    sharedController = self;
    
    [iosVers setText:[[UIDevice currentDevice] systemVersion]];
    size_t len = 0;
    char *model = malloc(len * sizeof(char));
    sysctlbyname("hw.model", NULL, &len, NULL, 0);
    if (len) {
        sysctlbyname("hw.model", model, &len, NULL, 0);
        printf("[INFO]: model internal name: %s (%s)\n", model, [[[UIDevice currentDevice] systemVersion] UTF8String]);
    }
    
    
    NSString *modelStr = [[NSString stringWithFormat:@"%s", model] uppercaseString];
    [DeviceString setText:modelStr];
    
    if (access("/var/tmp/is_jailbroken.tw3lve", F_OK) == ERR_SUCCESS)
    {
        [leButton setTitle:@"Jailbroken" forState:UIControlStateNormal];
        //DEBUG: set to true idgaf
        [leButton setEnabled:true];
    } else {
        [leButton setTitle:@"Jailbreak" forState:UIControlStateNormal];
        [leButton setEnabled:true];
    }
    
}

+ (Tw3lveView *)sharedController {
    return sharedController;
}

/***
 Thanks Conor
 **/
void runOnMainQueueWithoutDeadlocking(void (^block)(void))
{
    if ([NSThread isMainThread])
    {
        block();
    }
    else
    {
        dispatch_sync(dispatch_get_main_queue(), block);
    }
}





/***********
 
    MAGIC
 
 ***********/

bool restoreFS = false;

bool cydia = true;

bool voucher_swap_exp = false;

bool should_load_tweaks = true;

int expType = 0;
//0 = ms
//1 = ms2
//2 = vs

void jelbrek()
{
    while (true)
    {
        //Init Offsets
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Getting Offsets...");
        });
        offs_init();

        NSLog(@"Jailbreak Thread Started!");
        
        host_t host = mach_host_self();
        
        
        //Init Exploit
        if (expType == 2)
        {
            runOnMainQueueWithoutDeadlocking(^{
                logToUI(@"\n[*] Running Voucher Swap...");
            });
            
            voucher_swap();
            set_tfp0_rw(kernel_task_port);
            
            
            if (MACH_PORT_VALID(tfp0)) {
                
                kbase = find_kernel_base();
                kernel_slide = (kbase - KERNEL_SEARCH_ADDRESS);
                
                runOnMainQueueWithoutDeadlocking(^{
                    logToUI(@"\n[*] Getting Root...");
                });
                rootMe(0, selfproc());
                runOnMainQueueWithoutDeadlocking(^{
                    logToUI(@"\n[*] Unsandboxing...");
                });
                unsandbox(selfproc());
                
            } else {
                LOGME("ERROR!");
                break;
            }
            
            
            
        }
        
        if (expType == 0) {
            runOnMainQueueWithoutDeadlocking(^{
                logToUI(@"\n[*] Running Machswap...");
            });
            ms_offsets_t *ms_offs = get_machswap_offsets();
            machswap_exploit(ms_offs, &tfp0, &kbase);
            
            if (MACH_PORT_VALID(tfp0))
            {
                kernel_slide = (kbase - KERNEL_SEARCH_ADDRESS);
                //Machswap and Machswap2 already gave us undandboxing and root. Thanks! <3
                runOnMainQueueWithoutDeadlocking(^{
                    logToUI(@"\n[*] We already have root and unsandbox.");
                });
            } else {
                LOGME("ERROR!");
                break;
            }
            
        }
        
        if (expType == 1) {
            runOnMainQueueWithoutDeadlocking(^{
                logToUI(@"\n[*] Running Machswap2...");
            });
            ms_offsets_t *ms_offs = get_machswap_offsets();
            machswap2_exploit(ms_offs, &tfp0, &kbase);
            
            if (MACH_PORT_VALID(tfp0))
            {
                kernel_slide = (kbase - KERNEL_SEARCH_ADDRESS);
                //Machswap and Machswap2 already gave us undandboxing and root. Thanks! <3
                runOnMainQueueWithoutDeadlocking(^{
                    logToUI(@"\n[*] We already have root and unsandbox.");
                });
            } else {
                LOGME("ERROR!");
                break;
            }
            
        }
        

        //Log
        NSLog(@"%@", [NSString stringWithFormat:@"TFP0: 0x%x", tfp0]);
        NSLog(@"%@", [NSString stringWithFormat:@"KERNEL BASE: %llx", kbase]);
        NSLog(@"%@", [NSString stringWithFormat:@"KERNEL SLIDE: %llx", kernel_slide]);
        
        NSLog(@"UID: %u", getuid());
        NSLog(@"GID: %u", getgid());
        
        
        //PF64 (STAGE 1)
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Init Patchfinder64... (1)");
        });
        initPF64();
        
        //GET (4...) OFFSETS (STAGE 2)
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Getting Offsets (2)...");
        });
        getOffsets();
        saveOffs();
        
        //REMAP AND UNEXPORT (STAGE 3)
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Remapping TFP0... (3)");
        });
        setHSP4();
        
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Unexporting TFP0... (4)");
        });
        ux_tfp0(host, 0x80000000 | 3);
        
        
        //INIT KEXECUTE (STAGE 4)
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Init kexecute... (5)");
        });
        init_kexecute();
        
        //REMOUNT (STAGE 5)
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Remounting RootFS... (6)");
        });
        remountFS();
        
        
        //CHECK JBS (STAGE 6)
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Detecting if any other jailbreak is installed... (7)");
        });
        
        is_unc0ver_installed();
        is_last_surprise_installed();
        is_electra12_installed();
        
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] No jailbreak is installed! Proceeding with the jailbreak.");
        });
        
        //CHECK FOR RESTORE FS (STAGE 7)
        if (restoreFS == true)
        {
            runOnMainQueueWithoutDeadlocking(^{
                logToUI(@"\n[DANGER] Restoring RootFS...");
            });
            restoreRootFS();
        }
        
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Saving Offsets (8)...");
        });
        saveOffs();
        
        //PACKAGER (STAGE 8)
        if (isA12 == 0)
        {
            if (cydia)
            {
                runOnMainQueueWithoutDeadlocking(^{
                    logToUI(@"\n[*] Extracting Bootstrap And Installing Cydia... (9)");
                });
                installCydia();
                
                if (should_load_tweaks)
                {
                    loadTweaks();
                } else {
                    dontLoadTweaks();
                }
                finishCydia();
            } else {
                NOTICE(NSLocalizedString(@"Sileo has not been finished. I should've disabled the button.", nil), 1, 1);
            }
        } else {
            NOTICE(NSLocalizedString(@"A12 Device Has Been Detected! Cydia Will Not Be Installed! You Do Have: TFP0, And R/W. Please Select Install Sileo Instead. (Reboot Needed)", nil), 1, 1);
        }
        
        
        term_kexecute();
        restartSpringBoard();
        
        break;
        
    }
}


void logToUI(NSString *text)
{
    runOnMainQueueWithoutDeadlocking(^{
        NSLog(@"%@", text);
        Tw3lveView.sharedController.uiLog.text = [Tw3lveView.sharedController.uiLog.text stringByAppendingString:text];
        NSRange range = NSMakeRange(Tw3lveView.sharedController.uiLog.text.length - 1, 1);
        [Tw3lveView.sharedController.uiLog scrollRangeToVisible:range];
    });
}






typedef struct {
    int exploit;
    bool restoreFS;
    bool loadTweaksPlz;
    bool installSileoPlz;
} prefs_t;

bool load_prefs(prefs_t *prefs, NSDictionary *defaults) {
    if (prefs == NULL) {
        return false;
    }
    prefs->exploit = [defaults[EXPLOITTYPE] intValue];
    prefs->restoreFS = [defaults[RESTORE_FS] boolValue];
    prefs->loadTweaksPlz = [defaults[LOAD_TWEAKS] boolValue];
    prefs->installSileoPlz = [defaults[INSTALL_SILEO] boolValue];
    return true;
}


typedef enum {
    mach_swap_exploit,
    mach_swap_2_exploit,
    voucher_swap_exploit
} exploit_t;



- (IBAction)jelbrekClik:(id)sender {
    
    [sender setTitle:@"Jailbreaking..." forState:UIControlStateNormal];
    [sender setEnabled:false];
    
    runOnMainQueueWithoutDeadlocking(^{
        logToUI(@"\n[*] Loading Preferences...");
    });
    
    prefs_t prefs;
    NSUserDefaults *userDefaults = nil;
    NSDictionary *userDefaultsDictionary = nil;
    NSString *user = @"mobile";
    userDefaults = [[NSUserDefaults alloc] initWithUser:user];
    userDefaultsDictionary = [userDefaults dictionaryRepresentation];
    load_prefs(&prefs, userDefaultsDictionary);
    
    //0 = ms
    //1 = ms2
    //2 = vs
    
    if (prefs.exploit == mach_swap_exploit)
    {
        expType = 0;
    }
    
    if (prefs.exploit == mach_swap_2_exploit)
    {
        expType = 1;
    }
    
    if (prefs.exploit == voucher_swap_exploit)
    {
        expType = 2;
    }
    
    if (prefs.restoreFS)
    {
        restoreFS = true;
    }
    
    if (!prefs.restoreFS)
    {
        restoreFS = false;
    }
    
    if (prefs.loadTweaksPlz)
    {
        should_load_tweaks = true;
    }
    
    if (!prefs.loadTweaksPlz)
    {
        should_load_tweaks = false;
    }
    
    if (prefs.installSileoPlz)
    {
        cydia = true;
    }
    
    if (!prefs.installSileoPlz)
    {
        cydia = true;
    }
   
    runOnMainQueueWithoutDeadlocking(^{
        logToUI(@"\n[*] Staring Jailbreak Thread...");
    });
    
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        jelbrek();
    });
}




@end
