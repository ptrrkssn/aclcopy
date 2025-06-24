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

#include "gacl.h"



typedef struct {
    int fd;
    int flags;
    struct stat sb;
    char *path;
    GACL *acl;
} XFD;


char *argv0 = "aclcopy";

int f_verbose = 0;
int f_update = 1;
int f_test = 0;
int f_recurse = 0;
int f_onefsys = 0;
int f_force = 0;
int f_ignore = 0;
int f_debug = 0;
int f_posix = 0;
int f_extended = 0;

unsigned long n_scanned = 0;
unsigned long n_updated = 0;
unsigned long n_errors = 0;


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

    xp->acl = gacl_get(xp->fd, xp->path);
    return xp;
}


void
xfd_close(XFD *xp) {
    if (xp->path) {
	free(xp->path);
	xp->path = NULL;
    }
    if (xp->acl) {
	gacl_free(xp->acl);
	xp->acl = NULL;
    }
    if (xp->fd >= 0) {
	close(xp->fd);
	xp->fd = -1;
    }
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



int
copy_acl(XFD *s_dir,
	 const char *s_name,
         XFD *d_dir,
         const char *d_name,
         int level) {
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


    if (f_force || gacl_cmp(s_fd->acl, d_fd->acl) != 0) {
	if (f_update) {
	    if (xfd_reopen(d_fd, O_RDONLY|O_NONBLOCK) < 0) {
		perror_xfd_exit(d_dir, d_name, "Reopening as Normal Descriptor");
		exit(1);
	    }
	    
	    rc = gacl_set(d_fd->fd, d_fd->path, s_fd->acl);
	    if (rc < 0) {
		perror_xfd_exit(d_dir, d_name, "Updating ACL");
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
            case 'p':
                f_posix++;
                break;
            case 'e':
                f_extended++;
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
