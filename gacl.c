/*
 * gacl.c
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

#include "config.h"

#include "gacl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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


extern int f_debug;



/* - Internal Interfaces --------------------------------------------------------------------- */

static acl_perm_t perms[] = {
#if defined(ACL_WRITE) || defined(__DARWIN_ACL_WRITE)
    ACL_EXECUTE,
    ACL_WRITE,
    ACL_READ,
#endif
#if defined(ACL_READ_DATA) || defined(__DARWIN_ACL_READ_DATA)
    ACL_READ_DATA,
    ACL_WRITE_DATA,
    ACL_APPEND_DATA,
#if defined(ACL_READ_NAMED_ATTRS)
    ACL_READ_NAMED_ATTRS,
    ACL_WRITE_NAMED_ATTRS,
#endif
#if defined(__DARWIN_ACL_READ_EXTATTRIBUTES)
    ACL_READ_EXTATTRIBUTES,
    ACL_WRITE_EXTATTRIBUTES,
#endif
    ACL_DELETE_CHILD,
    ACL_READ_ATTRIBUTES,
    ACL_WRITE_ATTRIBUTES,
    ACL_DELETE,
#if defined(ACL_READ_ACL)
    ACL_READ_ACL,
    ACL_WRITE_ACL,
#endif
#if defined(__DARWIN_ACL_READ_SECURITY)
    ACL_READ_SECURITY,
    ACL_WRITE_SECURITY,
#endif
#ifdef ACL_WRITE_OWNER
    ACL_WRITE_OWNER,
#endif
#ifdef __DARWIN_ACL_CHANGE_OWNER
    ACL_CHANGE_OWNER,
#endif
    ACL_SYNCHRONIZE,
#endif
};

#ifdef HAVE_ACL_GET_FLAGSET_NP
static acl_flag_t flags[] = {
#if defined(ACL_ENTRY_FILE_INHERIT)
    ACL_ENTRY_FILE_INHERIT,
    ACL_ENTRY_DIRECTORY_INHERIT,
    ACL_ENTRY_NO_PROPAGATE_INHERIT,
    ACL_ENTRY_INHERIT_ONLY,
    ACL_ENTRY_SUCCESSFUL_ACCESS,
    ACL_ENTRY_FAILED_ACCESS,
    ACL_ENTRY_INHERITED,
#elif defined(__APPLE__)
    ACL_FLAG_DEFER_INHERIT,
    ACL_FLAG_NO_INHERIT,
    ACL_ENTRY_INHERITED,
    ACL_ENTRY_FILE_INHERIT,
    ACL_ENTRY_DIRECTORY_INHERIT,
    ACL_ENTRY_LIMIT_INHERIT,
    ACL_ENTRY_ONLY_INHERIT,
#endif
};
#endif


static int
_compare_permset(acl_permset_t a,
                acl_permset_t b) {
    int i;

    for (i = 0; i < sizeof(perms)/sizeof(perms[0]); i++) {
        int d, ap, bp;

#ifdef HAVE_ACL_GET_PERM_NP
        ap = acl_get_perm_np(a, perms[i]);
        bp = acl_get_perm_np(b, perms[i]);
#else
        ap = acl_get_perm(a, perms[i]);
        bp = acl_get_perm(b, perms[i]);
#endif
        d = ap-bp;
        if (d)
            return d;
    }

    return 0;
}

#ifdef HAVE_ACL_GET_FLAGSET_NP
static int
_compare_flagset(acl_flagset_t a,
		acl_flagset_t b) {
    int i;

    for (i = 0; i < sizeof(flags)/sizeof(flags[0]); i++) {
        int d, af, bf;

        af = acl_get_flag_np(a, flags[i]);
        bf = acl_get_flag_np(b, flags[i]);
	d = af-bf;
	if (d)
	    return d;
    }
    return 0;
}
#endif

static int
_compare_acl(acl_t sa,
             acl_t da) {

    int d = 0;
    acl_entry_t s_e, d_e;
    int i;
#if defined(ACL_USER) || defined(ACL_GROUP)
    void *vp;
#endif


    if (sa && !da)
        return 1;
    if (!sa && da)
        return -1;
    if (!sa && !da)
        return 0;

    i = 0;
    do {
        int s_rc, d_rc;
        acl_tag_t s_tt, d_tt;
#ifdef ACL_USER
        uid_t s_uid, d_uid;
#endif
#ifdef ACL_GROUP
        gid_t s_gid, d_gid;
#endif
        acl_permset_t s_ps, d_ps;
#ifdef HAVE_ACL_GET_ENTRY_TYPE_NP
        acl_entry_type_t s_et, d_et;
#endif
#ifdef HAVE_ACL_GET_FLAGSET_NP
        acl_flagset_t s_fs, d_fs;
#endif

        s_rc = acl_get_entry(sa, (i ? ACL_NEXT_ENTRY : ACL_FIRST_ENTRY), &s_e);
        d_rc = acl_get_entry(da, (i ? ACL_NEXT_ENTRY : ACL_FIRST_ENTRY), &d_e);
        if (!s_rc && !d_rc)
            return 0;

        d = s_rc - d_rc;
        if (d)
            return d;

        acl_get_tag_type(s_e, &s_tt);
        acl_get_tag_type(d_e, &d_tt);
        d = s_tt - d_tt;
        if (d)
            return d;

        switch (s_tt) {
#ifdef ACL_USER
        case ACL_USER:
            vp = acl_get_qualifier(s_e);
	    if (vp) {
		s_uid = *(uid_t *)vp;
		acl_free(vp);
	    } else
		s_uid = -1;
            vp = acl_get_qualifier(d_e);
	    if (vp) {
		d_uid = *(uid_t *)vp;
		acl_free(vp);
	    } else
		d_uid = -1;
            d = s_uid-d_uid;
            if (d)
                return d;
            break;
#endif
#ifdef ACL_GROUP
        case ACL_GROUP:
            vp = acl_get_qualifier(s_e);
            if (vp) {
                s_gid = *(gid_t *) vp;
                acl_free(vp);
            } else
                s_gid = -1;

            vp = acl_get_qualifier(d_e);
            if (vp) {
                d_gid = *(gid_t *) vp;
                acl_free(vp);
            } else
		d_gid = -1;

            d = s_gid-d_gid;
            if (d)
                return d;
            break;
#endif
#ifdef __DARWIN_ACL_EXTENDED_ALLOW
	case ACL_UNDEFINED_TAG:
	case ACL_EXTENDED_ALLOW:
	case ACL_EXTENDED_DENY:
	    break;
#endif
        }

        /* Allow vs Deny */
#ifdef HAVE_ACL_GET_ENTRY_TYPE_NP
        s_rc = acl_get_entry_type_np(s_e, &s_et);
        d_rc = acl_get_entry_type_np(d_e, &d_et);
        /* XXX: Handle errors */
        d = s_et - d_et;
        if (d)
            return d;
#endif

        s_rc = acl_get_permset(s_e, &s_ps);
        d_rc = acl_get_permset(d_e, &d_ps);

        d = _compare_permset(s_ps, d_ps);
        if (d)
            return d;

#ifdef HAVE_ACL_GET_FLAGSET_NP
        s_rc = acl_get_flagset_np(s_e, &s_fs);
        d_rc = acl_get_flagset_np(d_e, &d_fs);
        /* XXX: Handle errors */
        d = _compare_flagset(s_fs, d_fs);
        if (d)
            return d;
#endif

        ++i;
    } while (!d);

    return d;
}


/* - Public Interfaces --------------------------------------------------------------------- */


void
gacl_free(GACL *ap) {
#if defined(__FreeBSD__)
    if (ap->nfs4) {
        acl_free(ap->nfs4);
    }
#endif

#if defined(__APPLE__)
    if (ap->ext) {
        acl_free(ap->ext);
    }
#endif

#if defined(__linux__) || defined(__FreeBSD__)
    if (ap->posix.a) {
        acl_free(ap->posix.a);
    }
    if (ap->posix.d) {
        acl_free(ap->posix.d);
    }
#endif

#if defined(__linux__)
    if (ap->nfs4.b) {
        free(ap->nfs4.b);
    }
#endif

    memset(ap, 0, sizeof(*ap));
    free(ap);
}

GACL *
gacl_get(int fd,
	 const char *path) {
    int rc = -1;
    GACL *ap = malloc(sizeof(*ap));

    
    if (!ap)
        return NULL;

    memset(ap, 0, sizeof(*ap));
    
#if defined(__FreeBSD__)
    ap->nfs4 = acl_get_fd_np(fd, ACL_TYPE_NFS4);
    if (ap->nfs4) {
        rc = 0;
    }
#endif
    
#if defined(__APPLE__)
    ap->ext = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (ap->ext) {
        rc = 0;
    }
#endif

#if defined(__linux__) || defined(__FreeBSD__)
    ap->posix.a = acl_get_file(path, ACL_TYPE_ACCESS);
    if (ap->posix.a) {
        rc = 0;
    }
    ap->posix.d = acl_get_file(path, ACL_TYPE_DEFAULT);
#endif

#if defined(__linux__)
    ap->nfs4.s = fgetxattr(fd, ACL_NFS4_XATTR, NULL, 0);
    if (ap->nfs4.s >= 0) {
        ssize_t len;

        ap->nfs4.b = malloc(ap->nfs4.s+1);
	if (!ap->nfs4.b) {
	    return NULL;
	}
	
        while ((len = fgetxattr(xp->fd, ACL_NFS4_XATTR, ap->nfs4.b, ap->nfs4.s+1)) > 0 && len == ap->nfs4.s+1) {
	    ap->nfs4.s += 1024;
	    ap->nfs4.b = realloc(ap->nfs4.b, ap->nfs4.s+1);
	    if (!ap->nfs4.b) {
		return NULL;
	    }
	}
    }
    if (len > 0) {
	rc = 0;
    }
}
#endif

    if (rc == 0)
        return ap;

    gacl_free(ap);
    return NULL;
}


int
gacl_set(int fd,
	 const char *path,
	 GACL *ap) {
    int rc = 0;

    /* XXX: Handle ap == NULL */

#if defined(__linux__) || defined(__FreeBSD__)
    if (ap->posix.d) {
        if (f_debug)
	    fprintf(stderr, "** set_acl: Setting POSIX(default)\n");
        if (acl_set_file(path, ACL_TYPE_DEFAULT, ap->posix.d) < 0)
            rc = -1;
    }
    if (ap->posix.a) {
        if (f_debug)
	    fprintf(stderr, "** set_acl: Setting POSIX(access)\n");
        if (acl_set_fd(fd, ap->posix.a) < 0)
            rc = -1;
    }
#endif

#if defined(__FreeBSD__)
    if (ap->nfs4) {
        if (f_debug)
	    fprintf(stderr, "** set_acl: Setting NFS4\n");
        if (acl_set_fd_np(fd, ap->nfs4, ACL_TYPE_NFS4) < 0)
            rc = -1;
    }
#endif

#if defined(__APPLE__)
    if (ap->ext) {
        if (acl_set_fd(fd, ap->ext) < 0)
            rc = -1;
    }
#endif

#if defined(__linux__)
    if (ap->nfs4.b) {
        if (f_debug)
	    fprintf(stderr, "** set_acl: Setting NFS4(xattr)\n");
        if (fsetxattr(fd, ACL_NFS4_XATTR, ap->nfs4.b, ap->nfs4.s, 0) < 0)
            rc = -1;
    }
#endif

    return rc;
}



int
gacl_cmp(GACL *a,
	 GACL *b) {
    int rc;

#if defined(__FreeBSD__)
    rc = _compare_acl(a->nfs4, b->nfs4);
    if (rc)
        return rc;
#endif

#if defined(__APPLE__)
    rc = _compare_acl(a->ext, b->ext);
    if (rc)
        return rc;
#endif

#if defined(__linux__)
    /* NFS4 ACLs */

    rc = a->nfs4.s - b->nfs4.s;
    if (rc)
        return rc;
    if (a->nfs4.s > 0) {
        rc = memcmp(a->nfs4.b, b->nfs4.b, a->nfs4.s);
        if (rc)
            return rc;
    }
#endif

#if defined(__linux__) || defined(__FreeBSD__)
    rc = _compare_acl(a->posix.d, b->posix.d);
    if (rc)
        return rc;
    rc = _compare_acl(a->posix.a, b->posix.a);
    if (rc)
        return rc;
#endif

    return 0;
}

