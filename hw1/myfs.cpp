#include "config.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <cassert>
#include <cstring>
#include <iostream>

extern "C" {
    #include "log.h"
}

struct my_stat {
    ino_t ino;
    mode_t mode;
    nlink_t nlink;
    uid_t uid;
    gid_t gid;
    off_t st_size;
    blkcnt_t st_blocks;
    size_t open_counter;

    // TODO (extra task)
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
};

using catalog_type = std::unordered_map<std::string, ino_t>;
using file_content_type = std::vector<char>;

struct inode {
    struct my_stat stats;
    ino_t parent_inode;
    void *data;

    ~inode() {
        if ((stats.mode & S_IFMT) == S_IFDIR) {
            delete reinterpret_cast<catalog_type*>(data);
        } else {
            delete reinterpret_cast<file_content_type*>(data);
        }
    }
};

struct my_context {
    FILE *logfile;
    std::unordered_map <ino_t, inode*> inodes;
    ino_t root_ino = 0;
    ino_t next_ino = 0;

    ~my_context() {
        for (const auto [_, node] : inodes) {
            delete node;
        }
        fclose(logfile);
    }
};

my_context* my_get_context() {
    return reinterpret_cast<my_context*>(fuse_get_context()->private_data);
}

void update_atime(inode *node) {
    timespec_get(&node->stats.st_atim, TIME_UTC);
}

void update_ctime(inode *node) {
    timespec_get(&node->stats.st_ctim, TIME_UTC);
}

void update_mtime(inode *node) {
    timespec_get(&node->stats.st_mtim, TIME_UTC);
    update_ctime(node);
}

bool check_permissions(inode *node, int mode) {
    uid_t uid = fuse_get_context()->uid;
    gid_t gid = fuse_get_context()->gid;
    log_msg("Checking permissions uid = %d, gid = %d, mode = 0%o, real mode = 0%o\n", uid, gid, mode, node->stats.mode & 0777);

    if (uid == 0) {
        if (mode & X_OK) {
            if (!(node->stats.mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
                log_msg("Permissioon denied for root\n");
            }
            return node->stats.mode & (S_IXUSR | S_IXGRP | S_IXOTH);
        }
        return true;
    }

    int real_mode = 0;
    if (uid == node->stats.uid) {
        real_mode = (node->stats.mode >> 6) & 7;
    } else if (gid == node->stats.gid) {
        real_mode = (node->stats.mode >> 3) & 7;
    } else {
        real_mode = node->stats.mode & 7;
    }
    if ((real_mode & mode) != mode) {
        log_msg("Permission denied: asked 0%o, real = 0%o\n", mode, real_mode);
    }
    return (real_mode & mode) == mode;
}

int get_inode_by_path(const char *path) {
    my_context *context = my_get_context();

    ino_t current = context->root_ino;
    const char *cur_symbol = path;
    while (*cur_symbol != '\0') {
        assert((*cur_symbol) == '/');
        while ((*cur_symbol) == '/') {
            cur_symbol++;
        }

        if ((*cur_symbol) == '\0') {
            return current;
        }

        inode* current_node = context->inodes[current];
        if ((current_node->stats.mode & S_IFMT) != S_IFDIR) {
            // Not a directory
            return -ENOTDIR;
        }
        if (!check_permissions(current_node, X_OK)) {
            return -EACCES;
        }

        const char *prev_symbol = cur_symbol;
        while (*cur_symbol != '\0' && *cur_symbol != '/') {
            cur_symbol++;
        }

        std::string name = std::string(prev_symbol, cur_symbol);
        auto catalog = reinterpret_cast<catalog_type*>(current_node->data);
        if (catalog->find(name) == catalog->end()) {
            // No such file in directory
            return -ENOENT;
        }
        current = catalog->at(name);
    }

    return current;
}

int split_to_inode_and_last_entry(const char *path, std::string &last, int root_dir_error) {
    size_t len = strlen(path);
    char buf[len + 1];
    strcpy(buf, path);
    for (char *ptr = buf + len - 1; ; ptr--) {
        if ((*ptr) == '/') {
            if (ptr == buf + len - 1) {
                if (len == 1) {
                    return -root_dir_error;
                }
                continue;
            }

            last = std::string(ptr + 1, buf + len);
            *(ptr + 1) = '\0';

            int ino = get_inode_by_path(buf);
            if (ino < 0) {
                return ino;
            }

            inode *dir_node = my_get_context()->inodes[ino];
            if ((dir_node->stats.mode & S_IFMT) != S_IFDIR) {
                return -ENOTDIR;
            }
            if (!check_permissions(dir_node, X_OK)) {
                return -EACCES;
            }

            return ino;
        }
    }
    return -ENOTDIR;
}

int get_or_find_inode(const char *path, fuse_file_info *fi) {
    if (fi != nullptr) {
        return fi->fh;
    }
    return get_inode_by_path(path);
}

int my_getattr(const char *path, struct stat *statbuf) {
    log_msg("\nmy_getattr(path=\"%s\")\n", path);
    int ino = get_inode_by_path(path);

    if (ino < 0) {
        return ino;
    }

    const my_stat *cur_stat = &my_get_context()->inodes[ino]->stats;
    statbuf->st_atim = cur_stat->st_atim;
    statbuf->st_blocks = cur_stat->st_blocks;
    statbuf->st_ctim = cur_stat->st_ctim;
    statbuf->st_uid = cur_stat->uid;
    statbuf->st_gid = cur_stat->gid;
    statbuf->st_ino = cur_stat->ino;
    statbuf->st_mode = cur_stat->mode;
    statbuf->st_mtim = cur_stat->st_mtim;
    statbuf->st_nlink = cur_stat->nlink;
    statbuf->st_size = cur_stat->st_size;
    return 0;
}

int my_readlink(const char *path, char *link, size_t size) {
    log_msg("\nmy_readlink(path=\"%s\", link=\"%s\" size=%d)\n", path, link, size);

    // TODO: symlinks are not supported (additional task)
    return 0;
}

inode* gen_new_inode(ino_t parent_ino, mode_t mode, void *data) {
    ino_t new_ino = my_get_context()->next_ino++;
    my_stat new_stat = my_stat { 
        .ino = new_ino,
        .mode = mode,
        .nlink = 1,
        .uid = fuse_get_context()->uid,
        .gid = fuse_get_context()->gid,
        .st_size = 0,
        .st_blocks = 0,
        .open_counter = 0,
    };

    inode* ans = new inode { new_stat, parent_ino, data };
    update_atime(ans);
    update_mtime(ans);
    return ans;
}

inode *gen_new_dir_inode(ino_t parent_ino, int mode) {
    catalog_type* new_catalog = new catalog_type { {".", my_get_context()->next_ino}, {"..", parent_ino} };
    inode *node = gen_new_inode(parent_ino, mode | S_IFDIR, new_catalog);
    node->stats.nlink++;
    return node;
}

inode *gen_new_file_inode(ino_t parent_ino, int mode) {
    inode *node = gen_new_inode(parent_ino, mode | S_IFREG, new file_content_type());
    return node;
}

int my_mkdir_or_node(const char *path, mode_t mode) {
    std::string name;
    int dir_ino = split_to_inode_and_last_entry(path, name, EEXIST);
    if (dir_ino < 0) {
        return dir_ino;
    }

    inode *dir_node = my_get_context()->inodes[dir_ino];
    if (!check_permissions(dir_node, W_OK)) {
        return -EACCES;
    }
    catalog_type *dir_catalog = reinterpret_cast<catalog_type*>(dir_node->data);

    if (dir_catalog->find(name) != dir_catalog->end()) {
        return -EEXIST;
    }

    inode *new_inode;
    try {
        if ((mode & S_IFMT) == S_IFDIR) {
            new_inode = gen_new_dir_inode((ino_t) dir_ino, mode);
        } else {
            new_inode = gen_new_file_inode((ino_t) dir_ino, mode);
        }
        ino_t new_ino = new_inode->stats.ino;
        my_get_context()->inodes[new_ino] = new_inode;
        dir_catalog->insert({name, new_ino});
    } catch (const std::bad_alloc &_) {
        return -ENOMEM;
    }

    if ((mode & S_IFMT) == S_IFDIR) {
        dir_node->stats.nlink++;
    }

    log_msg("Successfully created\n");
    update_mtime(dir_node);
    return 0;
}

int my_mknod(const char *path, mode_t mode, dev_t dev) {
    log_msg("\nmy_mknod(path=\"%s\", mode=0%3o, dev=%lld)\n",
	  path, mode, dev);

    return my_mkdir_or_node(path, mode | S_IFREG);
}

int my_mkdir(const char *path, mode_t mode) {    
    log_msg("\nmy_mkdir(path=\"%s\", mode=0%3o)\n",
	    path, mode);
    return my_mkdir_or_node(path, mode | S_IFDIR);
}

int my_unlink(const char *path) {    
    log_msg("my_unlink(path=\"%s\")\n", path);

    std::string name;
    int parent_ino = split_to_inode_and_last_entry(path, name, EISDIR);
    if (parent_ino < 0) {
        return parent_ino;
    }

    inode *parent = my_get_context()->inodes[parent_ino];
    catalog_type *parent_catalog = reinterpret_cast<catalog_type*>(parent->data);
    if (!check_permissions(parent, W_OK)) {
        return -EACCES;
    }
    if (parent_catalog->find(name) == parent_catalog->end()) {
        return -ENOENT;
    }

    int ino = parent_catalog->at(name);
    inode *node = my_get_context()->inodes[(ino_t) ino];
    if ((node->stats.mode & S_IFMT) == S_IFDIR) {
        return -EISDIR;
    }

    parent_catalog->erase(name);
    update_ctime(node);
    if (--node->stats.nlink == 0 && node->stats.open_counter == 0) {
        log_msg("deleting inode %d\n", ino);
        my_get_context()->inodes.erase((ino_t) ino);
        delete node;
    }
    update_mtime(parent);
    return 0;
}

int my_rmdir(const char *path) {    
    log_msg("my_rmdir(path=\"%s\")\n", path);

    std::string name;
    int parent_ino = split_to_inode_and_last_entry(path, name, EBUSY);
    if (parent_ino < 0) {
        return parent_ino;
    }
    inode *parent_node = my_get_context()->inodes[parent_ino];
    catalog_type *parent_catalog = reinterpret_cast<catalog_type*>(parent_node->data);

    if (parent_catalog->find(name) == parent_catalog->end()) {
        return -ENOENT;
    }
    if (!check_permissions(parent_node, X_OK)) {
        return -EACCES;
    }
    ino_t ino = parent_catalog->at(name);
    inode *node = my_get_context()->inodes[ino];

    if ((node->stats.mode & S_IFMT) != S_IFDIR) {
        return -ENOTDIR;
    }

    catalog_type *catalog = reinterpret_cast<catalog_type*>(node->data);
    if (catalog->size() > 2) {
        return -ENOTEMPTY;
    }

    // TODO: do we need to check for node->stats.open_counter here?
    parent_catalog->erase(name);
    my_get_context()->inodes.erase((ino_t) ino);
    parent_node->stats.nlink--;
    delete node;
    update_mtime(parent_node);
    return 0;
}

int my_symlink(const char *path, const char *link) {    
    log_msg("\nmy_symlink(path=\"%s\", link=\"%s\")\n", path, link);

    // TODO: symlinks are not supported (additional task)
    return 0;
}

int my_rename(const char *path, const char *newpath) {
    log_msg("\nmy_rename(fpath=\"%s\", newpath=\"%s\")\n", path, newpath);

    if (!strcmp(path, newpath)) {
        return 0;
    }

    std::string src_name;
    int src_dir_ino = split_to_inode_and_last_entry(path, src_name, EBUSY);
    if (src_dir_ino < 0) {
        return src_dir_ino;
    }

    inode *src_dir_node = my_get_context()->inodes[src_dir_ino];
    catalog_type *src_catalog = reinterpret_cast<catalog_type*>(src_dir_node->data);
    if (src_catalog->find(src_name) == src_catalog->end()) {
        return -ENOENT;
    }
    ino_t src_ino = src_catalog->at(src_name);
    inode *src_node = my_get_context()->inodes[src_ino];

    std::string dst_name;
    int dst_dir_ino = split_to_inode_and_last_entry(newpath, dst_name, EBUSY);
    if (dst_dir_ino < 0) {
        return dst_dir_ino;
    }

    if (!strncmp(path, newpath, strlen(path)) && newpath[strlen(path)] == '/') {
        // path is prefix of newpath
        return -EINVAL;
    }

    inode *dst_dir_node = my_get_context()->inodes[dst_dir_ino];
    catalog_type *dst_catalog = reinterpret_cast<catalog_type*>(dst_dir_node->data);
    if (!check_permissions(src_dir_node, W_OK) || !check_permissions(dst_dir_node, W_OK)) {
        return -EACCES;
    }

    if (dst_catalog->find(dst_name) == dst_catalog->end()) {
        try {
            dst_catalog->insert({dst_name, src_ino});
        } catch (const std::bad_alloc &_) {
            return -ENOMEM;
        }
        src_catalog->erase(src_name);

        if ((src_node->stats.mode & S_IFMT) == S_IFDIR) {
            src_dir_node->stats.nlink--;
            dst_dir_node->stats.nlink++;
        }
    } else {
        ino_t dst_ino = dst_catalog->at(dst_name);
        inode *prev_dst = my_get_context()->inodes[dst_ino];
        if (dst_ino == src_ino) {
            // According to docs, 
            // If oldpath and newpath are existing hard links referring to the same file,
            // then rename() does nothing, and returns a success status.
            return 0;
        }

        if ((src_node->stats.mode & S_IFMT) == S_IFDIR) {
            if ((prev_dst->stats.mode & S_IFMT) != S_IFDIR) {
                return -ENOTDIR;
            }
            if (reinterpret_cast<catalog_type*>(prev_dst->data)->size() > 2) {
                return -ENOTEMPTY;
            }

            dst_catalog->at(dst_name) = src_ino;
            my_get_context()->inodes.erase(dst_ino);
            delete prev_dst;

            src_catalog->erase(src_name);
            src_dir_node->stats.nlink--;
        } else {
            if ((prev_dst->stats.mode & S_IFMT) == S_IFDIR) {
                return -EISDIR;
            }

            dst_catalog->at(dst_name) = src_ino;
            update_ctime(prev_dst);
            if (--prev_dst->stats.nlink == 0 && prev_dst->stats.open_counter == 0) {
                my_get_context()->inodes.erase(dst_ino);
                delete prev_dst;
            }

            src_catalog->erase(src_name);
        }
    }
    update_mtime(src_dir_node);
    update_mtime(dst_dir_node);
    update_ctime(src_node);
    return 0;
}

int my_link(const char *path, const char *newpath) {    
    log_msg("\nmy_link(path=\"%s\", newpath=\"%s\")\n",
	    path, newpath);

    int src_ino = get_inode_by_path(path);
    if (src_ino < 0) {
        return src_ino;
    }

    auto context = my_get_context();
    inode *src_node = context->inodes[src_ino];
    if ((src_node->stats.mode & S_IFMT) == S_IFDIR) {
        return -EPERM;
    }

    std::string name;
    int dir_ino = split_to_inode_and_last_entry(newpath, name, EEXIST);
    if (dir_ino < 0) {
        return dir_ino;
    }

    inode *dir_node = my_get_context()->inodes[dir_ino];
    catalog_type *dir_catalog = reinterpret_cast<catalog_type*>(dir_node->data);
    if (dir_catalog->find(name) != dir_catalog->end()) {
        return -EEXIST;
    }

    if (!check_permissions(dir_node, W_OK)) {
        return -EACCES;
    }

    try {
        dir_catalog->insert({name, src_ino});
    } catch (const std::bad_alloc &_) {
        return -ENOMEM;
    }
    src_node->stats.nlink++;
    update_mtime(dir_node);
    update_ctime(src_node);

    log_msg("Successfully created link\n");
    return 0;
}

/** Change the permission bits of a file */
int my_chmod(const char *path, mode_t mode) {    
    log_msg("\nmy_chmod(fpath=\"%s\", mode=0%03o)\n",
	    path, mode);

    int ino = get_inode_by_path(path);
    if (ino < 0) {
        return ino;
    }
    inode *node = my_get_context()->inodes[ino];
    uid_t uid = fuse_get_context()->uid;
    if (uid != 0 && uid != node->stats.uid) {
        return -EPERM;
    }
    node->stats.mode = (node->stats.mode & (~0777)) | (mode & 0777);
    update_ctime(node);
    return 0;
}

int my_chown(const char *path, uid_t uid, gid_t gid) {
    log_msg("\nmy_chown(path=\"%s\", uid=%d, gid=%d)\n",
	    path, uid, gid);
    int ino = get_inode_by_path(path);
    if (ino < 0) {
        return ino;
    }
    inode *node = my_get_context()->inodes[ino];
    uid_t caller_uid = fuse_get_context()->uid;
    gid_t caller_gid = fuse_get_context()->gid;
    if (caller_uid != 0 && (caller_uid != node->stats.uid || ((int) gid != -1 && gid != caller_gid))) {
        return -EACCES;
    }
    if ((int) gid != -1) {
        node->stats.gid = gid;
    }
    node->stats.uid = uid;
    update_ctime(node);
    return 0;
}

int my_truncate(const char *path, off_t newsize) {
    log_msg("\nmy_truncate(path=\"%s\", newsize=%lld)\n", path, newsize);

    int ino = get_inode_by_path(path);  
    if (ino < 0) {
        return ino;
    }

    inode *node = my_get_context()->inodes[(ino_t) ino];
    if ((node->stats.mode & S_IFMT) == S_IFDIR) {
        return -EISDIR;
    }
    if (!check_permissions(node, W_OK)) {
        return -EACCES;
    }

    file_content_type *data = reinterpret_cast<file_content_type*>(node->data);
    try {
        data->resize(newsize);
    } catch (const std::bad_alloc &_) {
        return -ENOMEM;
    }
    node->stats.st_size = data->size();
    update_mtime(node);
    return 0;
}

int my_utime(const char *path, struct utimbuf *ubuf) {
    log_msg("\nmy_utime(path=\"%s\", ubuf=0x%08x)\n",
	    path, ubuf);
    int ino = get_inode_by_path(path);
    if (ino < 0) {
        return ino;
    }
    uid_t uid = fuse_get_context()->uid;
    inode *node = my_get_context()->inodes[ino];

    if (uid != 0 && uid != node->stats.uid) {
        return -EPERM;
    }

    node->stats.st_mtim.tv_sec = ubuf->modtime;
    node->stats.st_mtim.tv_nsec = 0;
    node->stats.st_atim.tv_sec = ubuf->actime;
    node->stats.st_atim.tv_nsec = 0;
    update_ctime(node);
    return 0;
}

int my_open(const char *path, struct fuse_file_info *fi) {
    log_msg("\nmy_open(path\"%s\", fi=0x%08x)\n", path, fi);
    
    int ino = get_inode_by_path(path);

    if (ino < 0) {
        return ino;
    }
    inode *node = my_get_context()->inodes[(ino_t) ino];
    mode_t mode = 0;
    if ((fi->flags & O_ACCMODE) == O_RDONLY) {
        mode = R_OK;
    } else if ((fi->flags & O_ACCMODE) == O_WRONLY) {
        mode = W_OK;
    } else if ((fi->flags & O_ACCMODE) == O_RDWR) {
        mode = R_OK | W_OK;
    }
    if (!check_permissions(node, mode)) {
        return -EACCES;
    }
    // TODO: do we need to check for S_IFREG here?
    node->stats.open_counter++;
    fi->fh = ino;
    return 0;
}

int my_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {    
    log_msg("\nmy_read(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n",
	    path, buf, size, offset, fi);

    int ino = get_or_find_inode(path, fi);
    if (ino < 0) {
        return ino;
    }

    inode *node = my_get_context()->inodes[(ino_t) ino];
    file_content_type *data = reinterpret_cast<file_content_type*>(node->data);
    if ((fi->flags & O_ACCMODE) == O_WRONLY) {
        return -EACCES;
    }
    if (offset > (int) data->size()) {
        return -EINVAL;
    }

    int result = std::min(size, data->size() - offset);
    memcpy(buf, data->data() + offset, result);
    update_atime(node);
    return result;
}

int my_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {    
    log_msg("\nmy_write(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n",
	    path, buf, size, offset, fi
	);

    int ino = get_or_find_inode(path, fi);
    if (ino < 0) {
        return ino;
    }
    if ((fi->flags & O_ACCMODE) == O_RDONLY) {
        return -EACCES;
    }
    inode *node = my_get_context()->inodes[(ino_t) ino];
    file_content_type *data = reinterpret_cast<file_content_type*>(node->data);
    if (fi->flags & O_APPEND) {
        offset = data->size();
    }
    if (offset > (int) data->size()) {
        return -EINVAL;
    }

    try {
        data->resize(std::max(data->size(), offset + size));
    } catch (const std::bad_alloc &_) {
        return -ENOMEM;
    }
    memcpy(data->data() + offset, buf, size);
    node->stats.st_size = data->size();
    update_mtime(node);
    return size;
}

int my_statfs(const char *path, struct statvfs *statv) {    
    log_msg("\nmy_statfs(path=\"%s\", statv=0x%08x)\n", path, statv);
    
    // TODO: what should be returned here?
    statv->f_bavail = INT_MAX;
    statv->f_bfree = INT_MAX;
    statv->f_blocks = INT_MAX;
    statv->f_bsize = 1024;
    statv->f_ffree = INT_MAX;
    statv->f_files = INT_MAX;
    statv->f_namemax = 1024;
    return 0;
}

int my_flush(const char *path, struct fuse_file_info *fi) {
    log_msg("\nmy_flush(path=\"%s\", fi=0x%08x)\n", path, fi);
    return 0;
}

int my_release(const char *path, struct fuse_file_info *fi) {
    log_msg("\nmy_release(path=\"%s\", fi=0x%08x)\n", path, fi);

    ino_t ino = fi->fh;
    inode *node = my_get_context()->inodes[ino];
    if (--node->stats.open_counter == 0 && node->stats.nlink == 0) {
        log_msg("Deleting inode %d", ino);
        my_get_context()->inodes.erase(ino);
        delete node;
    }
    return 0;
}

int my_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
    log_msg("\nmy_fsync(path=\"%s\", datasync=%d, fi=0x%08x)\n",
	    path, datasync, fi);
    
    // TODO: really nothing here?  
    return 0;
}

int my_opendir(const char *path, struct fuse_file_info *fi) {   
    log_msg("\nmy_opendir(path=\"%s\", fi=0x%08x)\n",
	  path, fi);

    int ino = get_inode_by_path(path);

    if (ino < 0) {
        return ino;
    }
    inode *node = my_get_context()->inodes[(ino_t) ino];

    if ((node->stats.mode & S_IFMT) != S_IFDIR) {
        return -ENOTDIR;
    }
    fi->fh = ino;    
    return 0;
}

int my_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    log_msg("\nmy_readdir(path=\"%s\", buf=0x%08x, filler=0x%08x, offset=%lld, fi=0x%08x)\n",
	    path, buf, filler, offset, fi);

    ino_t ino = fi->fh;
    inode* node = my_get_context()->inodes[ino];
    if (!check_permissions(node, R_OK)) {
        return -EACCES;
    }
    catalog_type *catalog = reinterpret_cast<catalog_type*>(node->data);
    update_atime(node);
    for (const auto &[name, childnode] : *catalog) {
        if (filler(buf, name.c_str(), NULL, 0)) {
            return -ENOMEM;
        }
    }
    
    return 0;
}

int my_releasedir(const char *path, struct fuse_file_info *fi) {    
    log_msg("\nmy_releasedir(path=\"%s\", fi=0x%08x)\n",
	    path, fi);
    
    // TODO: really nothing here?
    return 0;
}

int my_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi) {    
    log_msg("\nmy_fsyncdir(path=\"%s\", datasync=%d, fi=0x%08x)\n",
	    path, datasync, fi);
    
    // TODO: really nothing here?
    return 0;
}

void *my_init(struct fuse_conn_info *conn) {
    (void) conn;

    log_msg("\nmy_init()\n");
    my_context* context = my_get_context();
    
    inode *root_inode;
    try {
        root_inode = gen_new_dir_inode(0, 0777);
    } catch (const std::bad_alloc &_) {
        log_msg("Failed to allocate root node, terminating");
        exit(1);
    }

    context->root_ino = 0;
    context->inodes[0] = root_inode;
    return context;
}

void my_destroy(void *userdata) {
    log_msg("\nmy_destroy(userdata=0x%08x)\n", userdata);
    delete my_get_context();
}

int my_access(const char *path, int mask) {
    log_msg("\nmy_access(path=\"%s\", mask=0%o)\n", path, mask);
    int ino = get_inode_by_path(path);
    if (ino < 0) {
        return ino;
    }

    inode *node = my_get_context()->inodes[ino];
    if (!check_permissions(node, mask)) {
        log_msg("Access denied");
        return -EACCES;
    }
    log_msg("Accesss allowed");
    return 0;
}

int my_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi) {
    log_msg("\nmy_ftruncate(path=\"%s\", offset=%lld, fi=0x%08x)\n", path, offset, fi);
    return my_truncate(path, offset);
}

int my_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi) {    
    log_msg("\nmy_fgetattr(path=\"%s\", statbuf=0x%08x, fi=0x%08x)\n",
	    path, statbuf, fi);
    return my_getattr(path, statbuf);
}

struct fuse_operations my_oper = {
  .getattr = my_getattr,
  .readlink = my_readlink,
  // no .getdir -- that's deprecated
  .getdir = NULL,
  .mknod = my_mknod,
  .mkdir = my_mkdir,
  .unlink = my_unlink,
  .rmdir = my_rmdir,
  .symlink = my_symlink,
  .rename = my_rename,
  .link = my_link,
  .chmod = my_chmod,
  .chown = my_chown,
  .truncate = my_truncate,
  .utime = my_utime,
  .open = my_open,
  .read = my_read,
  .write = my_write,
  .statfs = my_statfs,
  .flush = my_flush,
  .release = my_release,
  .fsync = my_fsync,
  
  .opendir = my_opendir,
  .readdir = my_readdir,
  .releasedir = my_releasedir,
  .fsyncdir = my_fsyncdir,
  .init = my_init,
  .destroy = my_destroy,
  .access = my_access,
  .ftruncate = my_ftruncate,
  .fgetattr = my_fgetattr
};

int main(int argc, char *argv[]) {
    int fuse_stat;

    if ((getuid() == 0) || (geteuid() == 0)) {
    	fprintf(stderr, "Running fuse as root opens unnacceptable security holes\n");
    	return 1;
    }

    // See which version of fuse we're running
    fprintf(stderr, "Fuse library version %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);

    if ((argc < 2) || (argv[argc-1][0] == '-')) {
        fprintf(stderr, "Expected last argument to be the mount directory");
        abort();
    }

    my_context *context;
    try {
        context = new my_context;
    } catch (const std::bad_alloc &_) {
        log_msg("Failed to allocate context in main, terminating");
        exit(1);
    }
    
    context->logfile = log_open();
    
    // turn over control to fuse
    fprintf(stderr, "about to call fuse_main\n");
    fuse_stat = fuse_main(argc, argv, &my_oper, context);
    fprintf(stderr, "fuse_main returned %d\n", fuse_stat);
    
    return fuse_stat;
}
