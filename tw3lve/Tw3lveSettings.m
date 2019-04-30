//
//  Tw3lveSettings.m
//  tw3lve
//
//  Created by Tanay Findley on 4/19/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#import "Tw3lveSettings.h"
#include "common.h"

@interface Tw3lveSettings () {
    IBOutlet UISwitch *restoreFSSwitch;
    IBOutlet UISwitch *loadTweaksSwitch;
    IBOutlet UISwitch *sileoSwitch;
    IBOutlet UISegmentedControl *exploitTypeBar;
}

@end

@implementation Tw3lveSettings

- (void)viewDidLoad {
    [super viewDidLoad];
    [self fixData];
}

- (void)fixData {
    [exploitTypeBar setSelectedSegmentIndex:[[NSUserDefaults standardUserDefaults] integerForKey:EXPLOITTYPE]];
    [restoreFSSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:RESTORE_FS]];
    [loadTweaksSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:LOAD_TWEAKS]];
    //[sileoSwitch setOn:[[NSUserDefaults standardUserDefaults] boolForKey:INSTALL_SILEO]];
    [sileoSwitch setOn:false];
}

- (IBAction)rootFSChanges:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[restoreFSSwitch isOn] forKey:RESTORE_FS];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self fixData];
}


- (IBAction)loadTweaksChanges:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[loadTweaksSwitch isOn] forKey:LOAD_TWEAKS];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self fixData];
}

- (IBAction)installSileoChanges:(id)sender {
    [[NSUserDefaults standardUserDefaults] setBool:[sileoSwitch isOn] forKey:INSTALL_SILEO];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self fixData];
}

- (IBAction)exploitTypeChanges:(id)sender {
    [[NSUserDefaults standardUserDefaults] setInteger:exploitTypeBar.selectedSegmentIndex forKey:EXPLOITTYPE];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self fixData];
}

- (IBAction)creditsPressed:(id)sender {
    
    UIAlertView *credits = [[UIAlertView alloc] initWithTitle:@"Credits"
                                                 message:@"Developers - Chr0nic and BrandonPlank6.\nUI Developers - iiFir3z and Sukarodo.\nWeb Developer - Memor1eslib.\nMedia - BennyNottenson.\nDSN - Aydndk.\nTesters - Jedimike417, TotallyNotNero, and beastmode270.\n Exploit - Pwn20wnd, bazad, Alticha, xerub, s1guza, littlelailo, qwertyuiopz, S0rryMyBad\nCydia/Resources - Saurik, Pixelomer, Pwn20wnd, Sam Bingner"
                                                delegate:self
                                       cancelButtonTitle:@"Cancel"
                                       otherButtonTitles:@"Ok", nil];
    
    //Shows the alert
    [credits show];
    
}




@end
