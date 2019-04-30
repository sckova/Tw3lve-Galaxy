//
//  VarHolder.c
//  tw3lve
//
//  Created by Tanay Findley on 4/7/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//
#include <mach/port.h>
#include "VarHolder.h"

mach_port_t tfp0 = MACH_PORT_NULL;
uint64_t kbase;
uint64_t current_task2;
uint64_t ourprocowo;
uint isA12 = 0;

void set_tfp0(mach_port_t tfpOwO)
{
    tfp0 = tfpOwO;
}

void setA12(uint a12)
{
    isA12 = a12;
}
