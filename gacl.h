/*
 * gacl.h
 *
 * Copyright (c) 2025, Peter Eriksson <pen@lysator.liu.se>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef GACL_H
#define GACL_H 1

#include "config.h"

#ifdef HAVE_SYS_ACL_H
#  include <sys/acl.h>
#endif

#ifdef HAVE_ACL_LIBACL_H
#  include <acl/libacl.h>
#endif

#ifdef HAVE_SYS_XATTR_H /* Linux */
#  include <sys/xattr.h>
#  define ACL_NFS4_XATTR "system.nfs4_acl"
#endif



typedef struct {
    enum {
        GACL_TYPE_NONE  = 0,
	GACL_TYPE_POSIX = 1,
	GACL_TYPE_NFS4  = 2,
    } type;
    union {
#if defined(__linux__) || defined(__FreeBSD__)
	struct {
	    acl_t a;
	    acl_t d;
	} posix;
#endif
#if defined(__FreeBSD__) || defined(__APPLE__)
	acl_t nfs4;
#elif defined(__linux__)
	struct {
	    unsigned char *b;
	    ssize_t s;
	} nfs4;
#endif
    } impl;
} GACL;

extern GACL *
gacl_new(void);

extern void
gacl_free(GACL *ap);

extern GACL *
gacl_get(int fd,
	 const char *path);

extern int
gacl_set(int fd,
	 const char *path,
	 GACL *ap);

extern int
gacl_cmp(GACL *a,
	 GACL *b);

#endif
