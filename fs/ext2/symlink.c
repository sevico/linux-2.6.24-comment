/*
 *  linux/fs/ext2/symlink.c
 *
 * Only fast symlinks left here - the rest is done by generic code. AV, 1999
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/symlink.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 symlink handling code
 */

#include "ext2.h"
#include "xattr.h"
#include <linux/namei.h>

static void *ext2_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	/*首先得到ext2_inode_info结构体，获得i_data字段，这个字段在ext2文件系统就是软链接的指向文件*/
	struct ext2_inode_info *ei = EXT2_I(dentry->d_inode);
	/*然后就在nd结构体内部记录下来*/
	nd_set_link(nd, (char *)ei->i_data);
	return NULL;
}

const struct inode_operations ext2_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
#ifdef CONFIG_EXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
};
 
const struct inode_operations ext2_fast_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= ext2_follow_link,
#ifdef CONFIG_EXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
};
