/*
 * so_caller.c
 * A simple program that links agains a traced shared-object and calls it.
 * The linkage to the shared object is specified at build-time and performed implicitly by ld.so
 *
 *  Created on: Nov 26, 2013
 *  Copyright by infinidat (http://infinidat.com)
 *  Author:     Yitzik Casapu, Infinidat
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
 */


#include <stdio.h>
#include <dlfcn.h>

#include "so_lib.h"


typedef int (*libfunc)(int);

static libfunc get_libfunc_ptr(void)
{
    void *const libhandle = dlopen("libso_demo_traced.so", RTLD_NOW);
    if (NULL == libhandle) {
        goto failed;
    }

    const libfunc f = dlsym(libhandle, "trace_write_simple_from_so");
    if (NULL == f) {
        goto failed;
    }

    return f;

failed:
    fprintf(stderr, "Library  load failed with: %s. libhandle=%p\n", dlerror(), libhandle);
    return NULL;
}

int main(void)
{
    const libfunc f = get_libfunc_ptr();
    int arg = f(41);
    printf("Got arg=%d\n", arg);
    return 0;
}
