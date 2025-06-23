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


char *argv0 = "aclcopy";

int f_verbose = 0;
int f_update = 1;
int f_recurse = 0;
int f_force = 0;
int f_ignore = 0;
int f_debug = 0;

uint64_t n_scanned = 0;
uint64_t n_updated = 0;
uint64_t n_errors = 0;


acl_perm_t perms[] = {
    ACL_EXECUTE,
    ACL_WRITE,
    ACL_READ,
#ifdef ACL_READ_DATA
    ACL_READ_DATA,
    ACL_WRITE_DATA,
    ACL_APPEND_DATA,
    ACL_READ_NAMED_ATTRS,
    ACL_WRITE_NAMED_ATTRS,
    ACL_DELETE_CHILD,
    ACL_READ_ATTRIBUTES,
    ACL_WRITE_ATTRIBUTES,
    ACL_DELETE,
    ACL_READ_ACL,
    ACL_WRITE_ACL,
    ACL_WRITE_OWNER,
    ACL_SYNCHRONIZE,
#endif
};

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

int
compare_acl(acl_t sa,
            acl_t da) {

    int d = 0;
#if 1
    acl_entry_t s_e, d_e;
    int i;
    void *vp;


    i = 0;
    do {
        int s_rc, d_rc;
        acl_tag_t s_tt, d_tt;
        uid_t s_uid, d_uid;
        gid_t s_gid, d_gid;
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
        d = memcmp(s_fs, d_fs, sizeof(*s_fs));
        if (d)
            return d;
#endif

        ++i;
    } while (!d);

#else
    char *ss, *ds;


    ss = acl_to_text(sa, NULL);
    ds = acl_to_text(da, NULL);

    printf("%svs\n%s\n", ss, ds);
    d = strcmp(ss, ds);

    acl_free(ds);
    acl_free(ss);
#endif

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

typedef struct {
    int fd;
    int flags;
    struct stat sb;
    char *path;
} XFD;


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
    
    fd = openat(xp->fd, "", O_EMPTY_PATH|flags);

    if (fd < 0)
	return -1;

    xp->flags = flags;
    return dup2(fd, xp->fd);
}


XFD *
xfd_openat(XFD *dxp,
	   const char *name) {
    XFD *xp;

    xp = malloc(sizeof(*xp));
    if (!xp)
	return NULL;

#ifdef O_PATH
    xp->fd = openat(dxp ? dxp->fd : AT_FDCWD, name, xp->flags = O_PATH);
#else
    xp->fd = openat(dxp ? dxp->fd : AT_FDCWD, name, xp->flags = O_RDONLY|O_NOFOLLOW|O_NONBLOCK);
#endif
    if (xp->fd < 0) {
	free(xp);
	return NULL;
    }

    if (fstatat(xp->fd, "", &xp->sb, AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH) < 0) {
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

int
copy_acl(XFD *s_dir,
	 const char *s_name,
         XFD *d_dir,
         const char *d_name,
         int level) {
    acl_t s_acl, d_acl;
    XFD *s_fd, *d_fd;
	


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
	if (errno == EMLINK)
	    return 0;
	
	perror_xfd_exit(s_dir, s_name, "open");
	return 0; /* Skip if source unreadable */
    }

    d_fd = xfd_openat(d_dir, d_name);
    if (!d_fd) {
	perror_xfd_exit(d_dir, d_name, "open");
	xfd_close(s_fd);
	return 0; /* Skip if target not exist */
    }

    if ((s_fd->sb.st_mode & S_IFMT) != (d_fd->sb.st_mode & S_IFMT)) {
        fprintf(stderr, "%s: Error: ", argv0);
	print_xfd2path(stderr, s_dir, s_name);
	fputs(" -> ", stderr);
	print_xfd2path(stderr, d_dir, d_name);
	fprintf(stderr, ": Different object types\n");
        exit(1);
    }

    if (S_ISDIR(s_fd->sb.st_mode) && f_recurse) {
        struct dirent *dp;
        char buf[8192];
        ssize_t nr;
        off_t basep = 0;


	if (xfd_reopen(s_fd, O_RDONLY|O_DIRECTORY) < 0) {
	    perror_xfd_exit(d_dir, d_name, "Reopening as Directory");
	    exit(1);
	}
	
        while ((nr = getdirentries(s_fd->fd, buf, sizeof(buf), &basep)) > 0) {
            char *ptr = buf;

            while (ptr < buf+nr) {
                dp = (struct dirent *) ptr;
                if (is_valid_name(dp->d_name)) {
                    copy_acl(s_fd, dp->d_name, d_fd, dp->d_name, level+1);
                }
                ptr += dp->d_reclen;
            }
        }
    }


    /* Update the ACL */

    s_acl = acl_get_fd_np(s_fd->fd, ACL_TYPE_NFS4);
    d_acl = acl_get_fd_np(d_fd->fd, ACL_TYPE_NFS4);

    if (s_acl != NULL && d_acl != NULL) {
        /* Both have ACLs */
        if (f_force || compare_acl(s_acl, d_acl) != 0) {
            if (f_update) {
		if (xfd_reopen(d_fd, O_RDONLY|O_NONBLOCK) < 0) {
		    perror_xfd_exit(d_dir, d_name, "Reopening as Normal Descriptor");
		    exit(1);
		}
		
                if (acl_set_fd_np(d_fd->fd, s_acl, ACL_TYPE_NFS4) < 0) {
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
	    
            if (acl_set_fd_np(d_fd->fd, d_acl, ACL_TYPE_NFS4) < 0) {
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
        acl_t t_acl;

        /* Source does not have ACL, Dest have */
        t_acl = acl_strip_np(d_acl, 0);

        if (f_update) {
	    if (xfd_reopen(d_fd, O_RDONLY|O_NONBLOCK) < 0) {
		perror_xfd_exit(d_dir, d_name, "Reopening as Normal Descriptor");
		exit(1);
	    }
	    
            if (acl_set_fd_np(d_fd->fd, t_acl, ACL_TYPE_NFS4) < 0) {
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

        acl_free(t_acl);
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
    fprintf(fp, "Options\n");
    fprintf(fp, "  -v          Increase verbosity\n");
    fprintf(fp, "  -n          No update mode (dryrun)\n");
    fprintf(fp, "  -d          Enable debugging output\n");
    fprintf(fp, "  -i          Ignore errors\n");
    fprintf(fp, "  -f          Force updates\n");
    fprintf(fp, "  -r          Recurse\n");
    fprintf(fp, "  -h          Display this info\n");
}


int
main(int argc,
     char *argv[]) {
    int i, j;
    time_t t0, t1;
    uint64_t dt;
    
    
    for (i = 1; i < argc && argv[i][0] == '-'; i++) {
        for (j = 1; argv[i][j]; j++) {
            switch (argv[i][j]) {
            case 'v':
                f_verbose++;
                break;
            case 'n':
                f_update = 0;
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

    time(&t0);
    copy_acl(NULL, argv[i], NULL, argv[i+1], 0);
    time(&t1);

    dt = t1-t0;
    
    printf("[%lu scanned, %lu updated & %lu errors in %lu s]\n", n_scanned, n_updated, n_errors, dt);

    return n_errors > 0 ? 1 : 0;
}
