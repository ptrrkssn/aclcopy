/*
 * aclcopy.c
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

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
    int fd;
    int flags;
    struct stat sb;
    char *path;
} XFD;


typedef struct {
#if defined(__FreeBSD__)
  acl_t nfs4;
#endif
#if defined(__APPLE__)
  acl_t ext;
#endif
#if defined(__linux__) || defined(__FreeBSD__)
  struct {
    acl_t a;
    acl_t d;
  } posix;
#endif
#if defined(__linux__)
  struct {
    unsigned char *b;
    ssize_t s;
  } nfs4;
#endif
} ACL;

char *argv0 = "aclcopy";

int f_verbose = 0;
int f_update = 1;
int f_test = 0;
int f_recurse = 0;
int f_onefsys = 0;
int f_force = 0;
int f_ignore = 0;
int f_debug = 0;

unsigned long n_scanned = 0;
unsigned long n_updated = 0;
unsigned long n_errors = 0;


acl_perm_t perms[] = {
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
acl_flag_t flags[] = {
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

void
spin(void) {
    static time_t last;
    time_t now;
    char dials[] = "|/-\\";
    static int p = 0;

    time(&now);
    if (now != last) {
	fputc(dials[p++%4], stderr);
	fputc('\b', stderr);
	last = now;
    }
}

int
compare_permset(acl_permset_t a,
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
int
compare_flagset(acl_flagset_t a,
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

        d = compare_permset(s_ps, d_ps);
        if (d)
            return d;

#ifdef HAVE_ACL_GET_FLAGSET_NP
        s_rc = acl_get_flagset_np(s_e, &s_fs);
        d_rc = acl_get_flagset_np(d_e, &d_fs);
        /* XXX: Handle errors */
        d = compare_flagset(s_fs, d_fs);
        if (d)
            return d;
#endif

        ++i;
    } while (!d);

    return d;
}


static inline int
is_valid_name(const char *s) {
    if (s[0] != '.')
        return 1;
    if (s[1] == '\0')
        return 0;
    if (s[1] == '.' && s[2] == '\0')
        return 0;

    return 1;
}



char *
strdupcat(const char *base,
	  ...) {
    va_list ap;
    char *result, *rp, *cp;
    size_t len;


    len = strlen(base);
    va_start(ap, base);
    while ((cp = va_arg(ap, char *)) != NULL) {
	len += strlen(cp);
    }
    va_end(ap);

    va_start(ap, base);

    rp = result = malloc(len+1);
    while (*base)
	*rp++ = *base++;

    while ((cp = va_arg(ap, char *)) != NULL) {
	while (*cp)
	    *rp++ = *cp++;
    }
    va_end(ap);
    *rp = '\0';
    return result;
}


int
xfd_reopen(XFD *xp,
	   int flags) {
    int fd;


    if (xp->flags == flags)
	return 0;

#ifdef O_EMPTY_PATH
    fd = openat(xp->fd, "", O_EMPTY_PATH|flags);
#else
    if (S_ISDIR(xp->sb.st_mode))
	fd = openat(xp->fd, ".", flags);
    else
	fd = open(xp->path, flags);
#endif

    if (fd < 0)
	return -1;

    xp->flags = flags;
    return dup2(fd, xp->fd);
}

DIR *
xfd_opendir(XFD *xp) {
    int fd;


#ifdef O_EMPTY_PATH
    fd = openat(xp->fd, "", O_EMPTY_PATH|O_RDONLY);
#else
    fd = openat(xp->fd, ".", O_RDONLY);
#endif

    if (fd < 0)
	return NULL;

    return fdopendir(fd);
}


XFD *
xfd_openat(XFD *dxp,
	   const char *name) {
    XFD *xp;
    int rc;


    xp = malloc(sizeof(*xp));
    if (!xp)
	return NULL;

#if defined(O_PATH) && defined(O_EMPTY_PATH)
    xp->fd = openat(dxp ? dxp->fd : AT_FDCWD, name, xp->flags = O_PATH|O_NOFOLLOW);
#else
    xp->fd = openat(dxp ? dxp->fd : AT_FDCWD, name, xp->flags = O_RDONLY|O_NOFOLLOW|O_NONBLOCK);
#endif
    if (xp->fd < 0) {
	free(xp);
	return NULL;
    }

#ifdef AT_EMPTY_PATH
    rc = fstatat(xp->fd, "", &xp->sb, AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH);
#else
    rc = fstatat(dxp ? dxp->fd : AT_FDCWD, name, &xp->sb, AT_SYMLINK_NOFOLLOW);
#endif
    if (rc < 0) {
	close(xp->fd);
	free(xp);
	return NULL;
    }

    if (name[0] == '/' || !dxp)
	xp->path = strdupcat(name, NULL);
    else {
	if (name[0] == '.' && name[1] == '/')
	    name += 2;
	if (dxp)
	    xp->path = strdupcat(dxp->path, "/", name, NULL);
    }

    if (!xp->path) {
	close(xp->fd);
	free(xp);
	return NULL;
    }

    return xp;
}


void
xfd_close(XFD *xp) {
    free(xp->path);
    close(xp->fd);
    free(xp);
}


int
print_xfd2path(FILE *fp,
	       XFD *dir,
	       const char *path) {
    if (path[0] == '/')
	return fputs(path, fp);

    while (path[0] == '.' && path[1] == '/')
	path += 2;

    if (dir)
	return fprintf(fp, "%s/%s", dir->path, path);;

    return fputs(path, fp);
}


void
perror_xfd_exit(XFD *dir,
		const char *path,
		const char *msg) {
    n_errors++;

    fprintf(stderr, "%s: Error: ", argv0);
    print_xfd2path(stderr, dir, path);
    fprintf(stderr, ": %s: %s",
	    msg, strerror(errno));
    if (f_ignore)
	fputs(" [ignored]", stderr);
    putc('\n', stderr);

    if (!f_ignore)
	exit(1);
}

#ifndef HAVE_ACL_STRIP_NP
acl_t
acl_strip_np(acl_t a,
             int recalculate_mask) {
    return acl_init(0);
}
#endif


void
free_acl(ACL *ap) {
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

ACL *
get_acl(XFD *xp) {
    int rc = -1;
    ACL *ap = malloc(sizeof(*ap));

    if (!ap)
        return NULL;

    memset(ap, 0, sizeof(*ap));

#if defined(__FreeBSD__)
    ap->nfs4 = acl_get_fd_np(xp->fd, ACL_TYPE_NFS4);
    if (ap->nfs4)
        rc = 0;
#endif

#if defined(__APPLE__)
    ap->ext = acl_get_fd_np(xp->fd, ACL_TYPE_EXTENDED);
    if (ap->ext)
        rc = 0;
#endif

#if defined(__linux__) || defined(__FreeBSD__)
    ap->posix.a = acl_get_fd(xp->fd);
    if (ap->posix.a)
        rc = 0;
    if (S_ISDIR(xp->sb.st_mode))
        ap->posix.d = acl_get_file(xp->path, ACL_TYPE_DEFAULT);
    else
        ap->posix.d = NULL;
#endif

#if defined(__linux__)
    ap->nfs4.s = fgetxattr(xp->fd, ACL_NFS4_XATTR, NULL, 0);
    if (ap->nfs4.s >= 0) {
        ssize_t len;

        ap->nfs4.b = malloc(ap->nfs4.s+1);
	if (!ap->nfs4.b) {
	  fprintf(stderr, "%s: Error: %lu: malloc: %s\n",
		  argv0, ap->nfs4.s+1, strerror(errno));
	  exit(1);
	}
	
        while ((len = fgetxattr(xp->fd, ACL_NFS4_XATTR, ap->nfs4.b, ap->nfs4.s+1)) > 0 && len == ap->nfs4.s+1) {
	  ap->nfs4.s += 1024;
	  ap->nfs4.b = realloc(ap->nfs4.b, ap->nfs4.s+1);
	  if (!ap->nfs4.b) {
	    fprintf(stderr, "%s: Error: %lu: realloc: %s\n",
		    argv0, ap->nfs4.s+1, strerror(errno));
	    exit(1);
	  }
	}
        if (len > 0)
            rc = 0;
    }
#endif

    if (rc == 0)
        return ap;

    free_acl(ap);
    return NULL;
}


int
set_acl(XFD *xp,
        ACL *ap) {
    int rc = 0;

    /* XXX: Handle ap == NULL */

#if defined(__FreeBSD__)
    if (ap->nfs4) {
        if (f_debug)
	    fprintf(stderr, "** set_acl: Setting NFS4\n");
        if (acl_set_fd_np(xp->fd, ap->nfs4, ACL_TYPE_NFS4) < 0)
            rc = -1;
    }
#endif

#if defined(__APPLE__)
    if (ap->ext) {
        if (acl_set_fd(xp->fd, ap->ext) < 0)
            rc = -1;
    }
#endif

#if defined(__linux__) || defined(__FreeBSD__)
    if (ap->posix.d && S_ISDIR(xp->sb.st_mode)) {
        if (f_debug)
	    fprintf(stderr, "** set_acl: Setting POSIX(default)\n");
        if (acl_set_file(xp->path, ACL_TYPE_DEFAULT, ap->posix.d) < 0)
            rc = -1;
    }
    if (ap->posix.a) {
        if (f_debug)
	    fprintf(stderr, "** set_acl: Setting POSIX(access)\n");
        if (acl_set_fd(xp->fd, ap->posix.a) < 0)
            rc = -1;
    }
#endif

#if defined(__linux__)
    if (ap->nfs4.b) {
        if (f_debug)
	    fprintf(stderr, "** set_acl: Setting NFS4(xattr)\n");
        if (fsetxattr(xp->fd, ACL_NFS4_XATTR, ap->nfs4.b, ap->nfs4.s, 0) < 0)
            rc = -1;
    }
#endif

    return rc;
}


int
cmp_acl(ACL *a,
        ACL *b) {
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


int
copy_acl(XFD *s_dir,
	 const char *s_name,
         XFD *d_dir,
         const char *d_name,
         int level) {
    ACL *s_acl, *d_acl;
    XFD *s_fd, *d_fd;
    int rc;

    n_scanned++;

    if (f_debug) {
	fprintf(stderr, "%*s", level, "");
	print_xfd2path(stderr, s_dir, s_name);
	fputs(" -> ", stderr);
	print_xfd2path(stderr, d_dir, d_name);
	putc('\n', stderr);
    }

    s_fd = xfd_openat(s_dir, s_name);
    if (!s_fd) {
	if (errno == ELOOP || errno == EMLINK)
	    return 0;

	perror_xfd_exit(s_dir, s_name, "open(src)");
	return 0; /* Skip if source unreadable */
    }

    /* Stop at filesystem boundary */
    if (f_onefsys && s_dir && (s_dir->sb.st_dev != s_fd->sb.st_dev)) {
	xfd_close(s_fd);
	return 0;
    }

    d_fd = xfd_openat(d_dir, d_name);
    if (!d_fd) {
	if (f_verbose > 1 || !(errno == ENOENT && f_ignore)) {
	    perror_xfd_exit(d_dir, d_name, "open(dst)");
	}
	xfd_close(s_fd);
	return 0; /* Skip if target not exist */
    }

    if ((s_fd->sb.st_mode & S_IFMT) != (d_fd->sb.st_mode & S_IFMT)) {
        fprintf(stderr, "%s: Error: ", argv0);
	print_xfd2path(stderr, s_dir, s_name);
	fputs(" -> ", stderr);
	print_xfd2path(stderr, d_dir, d_name);
	fprintf(stderr, ": Different object types");
        if (f_ignore)
            fputs(" [ignored]", stderr);
        putc('\n', stderr);
        if (f_ignore) {
            xfd_close(d_fd);
            xfd_close(s_fd);
            return 0;
        }
        else
            exit(1);
    }

    if (S_ISDIR(s_fd->sb.st_mode) && f_recurse) {
        struct dirent *dp;
	DIR *dirp;


	dirp = xfd_opendir(s_fd);
	if (!dirp) {
	    perror_xfd_exit(d_dir, d_name, "opendir");
	    exit(1);
	}
	while ((dp = readdir(dirp)) != NULL) {
	    if (is_valid_name(dp->d_name)) {
		copy_acl(s_fd, dp->d_name, d_fd, dp->d_name, level+1);
	    }
	}
	closedir(dirp);
    }


    /* Update the ACL */
    s_acl = get_acl(s_fd);
    d_acl = get_acl(d_fd);

    if (s_acl != NULL && d_acl != NULL) {
        /* Both have ACLs */
        if (f_force || cmp_acl(s_acl, d_acl) != 0) {
            if (f_update) {
		if (xfd_reopen(d_fd, O_RDONLY|O_NONBLOCK) < 0) {
		    perror_xfd_exit(d_dir, d_name, "Reopening as Normal Descriptor");
		    exit(1);
		}

                rc = set_acl(d_fd, s_acl);

                if (rc < 0) {
		    perror_xfd_exit(d_dir, d_name, "acl_set_fd_np");
                } else {
		    n_updated++;
		    if (f_verbose) {
			print_xfd2path(stdout, d_dir, d_name);
			printf(": Updated\n");
		    }
		}
            } else {
		n_updated++;
                if (f_verbose) {
		    print_xfd2path(stdout, d_dir, d_name);
		    printf(": (NOT) Updated\n");
		}
            }
        }
    } else if (s_acl != NULL && d_acl == NULL) {
        /* Source have ACL, Dest not */

        if (f_update) {
	    if (xfd_reopen(d_fd, O_RDONLY|O_NONBLOCK) < 0) {
		perror_xfd_exit(d_dir, d_name, "Reopening as Normal Descriptor");
		exit(1);
	    }

            rc = set_acl(d_fd, s_acl);
            if (rc < 0) {
		perror_xfd_exit(d_dir, d_name, "acl_set_fd_np");
            } else {
		n_updated++;
		if (f_verbose) {
		    print_xfd2path(stdout, d_dir, d_name);
		    printf(": Created\n");
		}
	    }
        } else {
	    n_updated++;
            if (f_verbose) {
		print_xfd2path(stdout, d_dir, d_name);
                printf(": (NOT) Created\n");
	    }
        }

    } else if (s_acl == NULL && d_acl != NULL) {
        if (f_update) {
	    if (xfd_reopen(d_fd, O_RDONLY|O_NONBLOCK) < 0) {
		perror_xfd_exit(d_dir, d_name, "Reopening as Normal Descriptor");
		exit(1);
	    }

            rc = set_acl(d_fd, NULL);
            if (rc < 0) {
		perror_xfd_exit(d_dir, d_name, "acl_set_fd_np");
            } else {
		n_updated++;
		if (f_verbose) {
		    print_xfd2path(stdout, d_dir, d_name);
		    printf(": Cleared\n");
		}
	    }
        } else {
	    n_updated++;
            if (f_verbose) {
		print_xfd2path(stdout, d_dir, d_name);
		printf(": (NOT) Cleared\n");
	    }
        }
    } else {
        /* Neither have ACLs */
    }

    if (s_acl)
        acl_free(s_acl);
    if (d_acl)
        acl_free(d_acl);

    xfd_close(d_fd);
    xfd_close(s_fd);

    if (isatty(2)) {
	if (f_verbose) {
	    static time_t ts;
	    time_t tn;

	    time(&tn);
	    if (tn != ts) {
		fprintf(stderr, "[%lu]\r", n_scanned);
		ts = tn;
	    }
	} else
	    spin();
    }

    return 0;
}


void
usage(FILE *fp) {
    fprintf(fp, "Usage:\n  %s [<options>] <src> <dst>\n",
            argv0);
    fprintf(fp, "\nOptions\n");
    fprintf(fp, "  -V          Display version and exit\n");
    fprintf(fp, "  -v          Increase verbosity\n");
    fprintf(fp, "  -n          No update mode (dryrun)\n");
    fprintf(fp, "  -d          Enable debugging output\n");
    fprintf(fp, "  -i          Ignore non-fatal errors\n");
    fprintf(fp, "  -f          Force update of ACLs\n");
    fprintf(fp, "  -r          Recurse into directories\n");
    fprintf(fp, "  -x          Stay inside filesystem\n");
    fprintf(fp, "  -t          Test mode - exit status 1 if ACLs needs update\n");
    fprintf(fp, "  -h          Display this info and exit\n");
    fprintf(fp, "\nVersion:\n  %s\n", PACKAGE_VERSION);
    fprintf(fp, "\nWebsite:\n  %s\n", PACKAGE_URL);
    fprintf(fp, "\nAuthor:\n  Peter Eriksson <%s>\n", PACKAGE_BUGREPORT);

}

void
print_version(FILE *fp) {
    fprintf(fp, "[aclcopy, version %s - Copyright (c) 2025 Peter Eriksson %s]\n",
            PACKAGE_VERSION, PACKAGE_BUGREPORT);
}


int
main(int argc,
     char *argv[]) {
    int i, j;
    time_t t0, t1;
    unsigned long dt;


    for (i = 1; i < argc && argv[i][0] == '-'; i++) {
        for (j = 1; argv[i][j]; j++) {
            switch (argv[i][j]) {
            case 'V':
                print_version(stdout);
                exit(0);
            case 'v':
                f_verbose++;
                break;
            case 'n':
                f_update = 0;
                break;
            case 't':
                f_test++;
                break;
            case 'd':
                f_debug++;
                break;
            case 'i':
                f_ignore++;
                break;
            case 'f':
                f_force++;
                break;
            case 'r':
                f_recurse++;
                break;
	    case 'x':
		f_onefsys++;
		break;
            case 'h':
                usage(stdout);
                exit(0);
            case '-':
                ++i;
                goto EndArg;
            }
        }
    }
 EndArg:;

    if (i+2 != argc) {
        fprintf(stderr, "%s: Error: Missing required <src> <dst> arguments\n",
                argv[0]);
        exit(1);
    }

    if (f_verbose)
        print_version(stdout);

    time(&t0);
    copy_acl(NULL, argv[i], NULL, argv[i+1], 0);
    time(&t1);

    dt = t1-t0;

    if (f_verbose)
	printf("[%lu scanned, %lu updated & %lu errors in %lu s]\n", n_scanned, n_updated, n_errors, dt);

    return f_test ? (n_updated > 0 ? 1 : 0) : (n_errors > 0 ? 1 : 0);
}
