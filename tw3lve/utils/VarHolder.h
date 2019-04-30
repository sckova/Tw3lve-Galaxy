//
//  VarHolder.h
//  tw3lve
//
//  Created by Tanay Findley on 4/7/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#ifndef VarHolder_h
#define VarHolder_h

#include <stdio.h>

extern mach_port_t tfp0;
extern uint64_t kbase;
extern uint64_t ourprocowo;
extern uint64_t current_task2;
extern uint isA12;

void set_tfp0(mach_port_t tfpOwO);
void setA12(uint a12);

#endif /* VarHolder_h */
