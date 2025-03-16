import { PrismaClient } from '@prisma/client';
import { GraphQLScalarType } from 'graphql';
import { GraphQLUpload } from 'graphql-upload';
import { v4 as uuidv4 } from 'uuid';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import * as path from 'path';

const prisma = new PrismaClient();

// Custom scalars
const DateTimeScalar = new GraphQLScalarType({
  name: 'DateTime',
  description: 'DateTime custom scalar type',
  serialize(value) {
    return value.toISOString();
  },
  parseValue(value) {
    return new Date(value);
  },
  parseLiteral(ast) {
    if (ast.kind === Kind.STRING) {
      return new Date(ast.value);
    }
    return null;
  },
});

const JSONScalar = new GraphQLScalarType({
  name: 'JSON',
  description: 'JSON custom scalar type',
  serialize(value) {
    return value;
  },
  parseValue(value) {
    return value;
  },
  parseLiteral(ast) {
    switch (ast.kind) {
      case Kind.STRING:
        return JSON.parse(ast.value);
      case Kind.OBJECT:
        return ast.value;
      default:
        return null;
    }
  },
});

// Helper functions
const getUserId = (context) => {
  const Authorization = context.req.headers.authorization;
  if (Authorization) {
    const token = Authorization.replace('Bearer ', '');
    const { userId } = jwt.verify(token, process.env.JWT_SECRET);
    return userId;
  }
  throw new Error('Not authenticated');
};

const checkPermission = async (userId, resourceType, resourceId, requiredLevel) => {
  const permission = await prisma.permission.findFirst({
    where: {
      resourceType,
      resourceId,
      userId,
    },
  });

  if (!permission) {
    const userGroups = await prisma.groupMember.findMany({
      where: { userId },
      select: { groupId: true },
    });
    
    const groupIds = userGroups.map(g => g.groupId);
    
    const groupPermission = await prisma.permission.findFirst({
      where: {
        resourceType,
        resourceId,
        groupId: { in: groupIds },
      },
    });
    
    if (!groupPermission) {
      throw new Error('Insufficient permissions');
    }
    
    const accessLevels = ['viewer', 'editor', 'manager', 'owner'];
    if (accessLevels.indexOf(groupPermission.accessLevel) < accessLevels.indexOf(requiredLevel)) {
      throw new Error('Insufficient permissions');
    }
    
    return groupPermission;
  }
  
  const accessLevels = ['viewer', 'editor', 'manager', 'owner'];
  if (accessLevels.indexOf(permission.accessLevel) < accessLevels.indexOf(requiredLevel)) {
    throw new Error('Insufficient permissions');
  }
  
  return permission;
};

const logAuditEvent = async (userId, action, resourceType, resourceId, details = null, context) => {
  return prisma.auditLog.create({
    data: {
      userId,
      action,
      resourceType,
      resourceId,
      details,
      ipAddress: context.req.ip || null,
      userAgent: context.req.headers['user-agent'] || null,
    },
  });
};

// Setup upload directory
const UPLOAD_DIR = path.join(__dirname, '../uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Resolvers
export const resolvers = {
  DateTime: DateTimeScalar,
  JSON: JSONScalar,
  Upload: GraphQLUpload,
  
  User: {
    ownedFolders: (parent) => prisma.folder.findMany({ where: { ownerId: parent.id } }),
    ownedFiles: (parent) => prisma.file.findMany({ where: { ownerId: parent.id } }),
    fileVersions: (parent) => prisma.fileVersion.findMany({ where: { modifiedById: parent.id } }),
    permissions: (parent) => prisma.permission.findMany({ where: { userId: parent.id } }),
    managedClients: (parent) => prisma.client.findMany({ where: { accountManagerId: parent.id } }),
    sharedByUser: (parent) => prisma.share.findMany({ where: { sharedById: parent.id } }),
    sharedWithUser: (parent) => prisma.share.findMany({ where: { sharedWithUserId: parent.id } }),
    groupMemberships: (parent) => prisma.groupMember.findMany({ where: { userId: parent.id } }),
    auditLogs: (parent) => prisma.auditLog.findMany({ where: { userId: parent.id } })
  },
  
  Folder: {
    owner: (parent) => prisma.user.findUnique({ where: { id: parent.ownerId } }),
    parentFolder: (parent) => parent.parentFolderId ? prisma.folder.findUnique({ where: { id: parent.parentFolderId } }) : null,
    childFolders: (parent) => prisma.folder.findMany({ where: { parentFolderId: parent.id } }),
    files: (parent) => prisma.file.findMany({ where: { folderId: parent.id } }),
    folderPermissions: (parent) => prisma.permission.findMany({ 
      where: { resourceType: 'folder', resourceId: parent.id } 
    }),
    folderShares: (parent) => prisma.share.findMany({ 
      where: { resourceType: 'folder', resourceId: parent.id } 
    }),
    client: (parent) => parent.clientId ? prisma.client.findUnique({ where: { id: parent.clientId } }) : null
  },
  
  File: {
    folder: (parent) => prisma.folder.findUnique({ where: { id: parent.folderId } }),
    owner: (parent) => prisma.user.findUnique({ where: { id: parent.ownerId } }),
    fileVersions: (parent) => prisma.fileVersion.findMany({ 
      where: { fileId: parent.id },
      orderBy: { versionNumber: 'desc' }
    }),
    filePermissions: (parent) => prisma.permission.findMany({ 
      where: { resourceType: 'file', resourceId: parent.id } 
    }),
    fileShares: (parent) => prisma.share.findMany({ 
      where: { resourceType: 'file', resourceId: parent.id } 
    })
  },
  
  FileVersion: {
    file: (parent) => prisma.file.findUnique({ where: { id: parent.fileId } }),
    modifiedBy: (parent) => prisma.user.findUnique({ where: { id: parent.modifiedById } })
  },
  
  Client: {
    accountManager: (parent) => prisma.user.findUnique({ where: { id: parent.accountManagerId } }),
    folders: (parent) => prisma.folder.findMany({ where: { clientId: parent.id } })
  },
  
  Permission: {
    user: (parent) => parent.userId ? prisma.user.findUnique({ where: { id: parent.userId } }) : null,
    group: (parent) => parent.groupId ? prisma.group.findUnique({ where: { id: parent.groupId } }) : null,
    folder: (parent) => parent.resourceType === 'folder' ? 
      prisma.folder.findUnique({ where: { id: parent.resourceId } }) : null,
    file: (parent) => parent.resourceType === 'file' ? 
      prisma.file.findUnique({ where: { id: parent.resourceId } }) : null
  },
  
  Share: {
    sharedBy: (parent) => prisma.user.findUnique({ where: { id: parent.sharedById } }),
    sharedWithUser: (parent) => parent.sharedWithUserId ? 
      prisma.user.findUnique({ where: { id: parent.sharedWithUserId } }) : null,
    folder: (parent) => parent.resourceType === 'folder' ? 
      prisma.folder.findUnique({ where: { id: parent.resourceId } }) : null,
    file: (parent) => parent.resourceType === 'file' ? 
      prisma.file.findUnique({ where: { id: parent.resourceId } }) : null
  },
  
  Group: {
    members: (parent) => prisma.groupMember.findMany({ where: { groupId: parent.id } }),
    permissions: (parent) => prisma.permission.findMany({ where: { groupId: parent.id } })
  },
  
  GroupMember: {
    group: (parent) => prisma.group.findUnique({ where: { id: parent.groupId } }),
    user: (parent) => prisma.user.findUnique({ where: { id: parent.userId } })
  },
  
  AuditLog: {
    user: (parent) => parent.userId ? prisma.user.findUnique({ where: { id: parent.userId } }) : null
  },
  
  // Query resolvers
  Query: {
    me: (_, __, context) => {
      const userId = getUserId(context);
      return prisma.user.findUnique({ where: { id: userId } });
    },
    
    user: async (_, { id }, context) => {
      const userId = getUserId(context);
      const currentUser = await prisma.user.findUnique({ where: { id: userId } });
      
      // Only admins or the user themselves can query specific user details
      if (currentUser.role !== 'admin' && userId !== parseInt(id)) {
        throw new Error('Not authorized');
      }
      
      return prisma.user.findUnique({ where: { id: parseInt(id) } });
    },
    
    users: async (_, { where, orderBy, skip, take }, context) => {
      const userId = getUserId(context);
      const currentUser = await prisma.user.findUnique({ where: { id: userId } });
      
      if (currentUser.role !== 'admin') {
        throw new Error('Not authorized');
      }
      
      const whereClause = where ? {
        ...(where.role && { role: where.role.toLowerCase() }),
        ...(where.department && { department: where.department }),
        ...(where.isActive !== undefined && { isActive: where.isActive }),
        ...(where.createdAt_gte && { createdAt: { gte: where.createdAt_gte } }),
        ...(where.createdAt_lte && { createdAt: { lte: where.createdAt_lte } }),
        ...(where.search && {
          OR: [
            { email: { contains: where.search } },
            { fullName: { contains: where.search } }
          ]
        })
      } : {};
      
      const orderByClause = orderBy ? {
        [orderBy.field.toLowerCase()]: orderBy.direction.toLowerCase()
      } : { id: 'asc' };
      
      return prisma.user.findMany({
        where: whereClause,
        orderBy: orderByClause,
        skip: skip || 0,
        take: take || 50
      });
    },
    
    usersCount: async (_, { where }, context) => {
      const userId = getUserId(context);
      const currentUser = await prisma.user.findUnique({ where: { id: userId } });
      
      if (currentUser.role !== 'admin') {
        throw new Error('Not authorized');
      }
      
      const whereClause = where ? {
        ...(where.role && { role: where.role.toLowerCase() }),
        ...(where.department && { department: where.department }),
        ...(where.isActive !== undefined && { isActive: where.isActive }),
        ...(where.createdAt_gte && { createdAt: { gte: where.createdAt_gte } }),
        ...(where.createdAt_lte && { createdAt: { lte: where.createdAt_lte } }),
        ...(where.search && {
          OR: [
            { email: { contains: where.search } },
            { fullName: { contains: where.search } }
          ]
        })
      } : {};
      
      return prisma.user.count({ where: whereClause });
    },
    
    folder: async (_, { id }, context) => {
      const userId = getUserId(context);
      const folderId = parseInt(id);
      
      // Check if user has access to this folder
      try {
        await checkPermission(userId, 'folder', folderId, 'viewer');
        return prisma.folder.findUnique({ where: { id: folderId } });
      } catch (error) {
        throw new Error('Not authorized to access this folder');
      }
    },
    
    folders: async (_, { where, orderBy, skip, take }, context) => {
      const userId = getUserId(context);
      
      // Build where clause based on provided filters
      const whereClause = {
        ...(where?.ownerId && { ownerId: parseInt(where.ownerId) }),
        ...(where?.folderType && { folderType: where.folderType.toLowerCase() }),
        ...(where?.parentFolderId && { parentFolderId: parseInt(where.parentFolderId) }),
        ...(where?.clientId && { clientId: parseInt(where.clientId) }),
        ...(where?.dataClassification && { dataClassification: where.dataClassification.toLowerCase() }),
        ...(where?.search && { name: { contains: where.search } })
      };
      
      // First get all folders the user has direct access to
      const userPermissions = await prisma.permission.findMany({
        where: {
          userId,
          resourceType: 'folder'
        }
      });
      
      // Also get group-based permissions
      const userGroups = await prisma.groupMember.findMany({
        where: { userId },
        select: { groupId: true }
      });
      
      const groupIds = userGroups.map(g => g.groupId);
      
      const groupPermissions = await prisma.permission.findMany({
        where: {
          groupId: { in: groupIds },
          resourceType: 'folder'
        }
      });
      
      // Combine all folder IDs the user has access to
      const accessibleFolderIds = [
        ...userPermissions.map(p => p.resourceId),
        ...groupPermissions.map(p => p.resourceId)
      ];
      
      // Find folders owned by the user or accessible via permissions
      return prisma.folder.findMany({
        where: {
          AND: [
            whereClause,
            {
              OR: [
                { ownerId: userId },
                { id: { in: accessibleFolderIds } }
              ]
            }
          ]
        },
        orderBy: orderBy ? {
          [orderBy.field.toLowerCase()]: orderBy.direction.toLowerCase()
        } : { name: 'asc' },
        skip: skip || 0,
        take: take || 50
      });
    },
    
    rootFolders: async (_, { folderType }, context) => {
      const userId = getUserId(context);
      
      return prisma.folder.findMany({
        where: {
          parentFolderId: null,
          ...(folderType && { folderType: folderType.toLowerCase() }),
          ownerId: userId
        }
      });
    },
    
    file: async (_, { id }, context) => {
      const userId = getUserId(context);
      const fileId = parseInt(id);
      
      try {
        await checkPermission(userId, 'file', fileId, 'viewer');
        return prisma.file.findUnique({ where: { id: fileId } });
      } catch (error) {
        throw new Error('Not authorized to access this file');
      }
    },
    
    files: async (_, { where, orderBy, skip, take }, context) => {
      const userId = getUserId(context);
      
      // Build where clause based on provided filters
      const whereClause = {
        ...(where?.folderId && { folderId: parseInt(where.folderId) }),
        ...(where?.ownerId && { ownerId: parseInt(where.ownerId) }),
        ...(where?.fileType && { fileType: where.fileType }),
        ...(where?.dataClassification && { dataClassification: where.dataClassification.toLowerCase() }),
        ...(where?.search && { name: { contains: where.search } })
      };
      
      // First get all files the user has direct access to
      const userPermissions = await prisma.permission.findMany({
        where: {
          userId,
          resourceType: 'file'
        }
      });
      
      // Also get group-based permissions
      const userGroups = await prisma.groupMember.findMany({
        where: { userId },
        select: { groupId: true }
      });
      
      const groupIds = userGroups.map(g => g.groupId);
      
      const groupPermissions = await prisma.permission.findMany({
        where: {
          groupId: { in: groupIds },
          resourceType: 'file'
        }
      });
      
      // Combine all file IDs the user has access to
      const accessibleFileIds = [
        ...userPermissions.map(p => p.resourceId),
        ...groupPermissions.map(p => p.resourceId)
      ];
      
      // If folder ID is specified, first check if user has access to that folder
      if (where?.folderId) {
        try {
          await checkPermission(userId, 'folder', parseInt(where.folderId), 'viewer');
        } catch (error) {
          throw new Error('Not authorized to access files in this folder');
        }
      }
      
      // Find files owned by the user or accessible via permissions
      return prisma.file.findMany({
        where: {
          AND: [
            whereClause,
            {
              OR: [
                { ownerId: userId },
                { id: { in: accessibleFileIds } },
                {
                  folderId: {
                    in: (await prisma.permission.findMany({
                      where: {
                        OR: [
                          { userId },
                          { groupId: { in: groupIds } }
                        ],
                        resourceType: 'folder'
                      },
                      select: { resourceId: true }
                    })).map(p => p.resourceId)
                  }
                }
              ]
            }
          ]
        },
        orderBy: orderBy ? {
          [orderBy.field.toLowerCase()]: orderBy.direction.toLowerCase()
        } : { name: 'asc' },
        skip: skip || 0,
        take: take || 50
      });
    },
    
    fileVersions: async (_, { fileId }, context) => {
      const userId = getUserId(context);
      
      try {
        await checkPermission(userId, 'file', parseInt(fileId), 'viewer');
        
        return prisma.fileVersion.findMany({
          where: { fileId: parseInt(fileId) },
          orderBy: { versionNumber: 'desc' }
        });
      } catch (error) {
        throw new Error('Not authorized to view file versions');
      }
    },
    
    client: async (_, { id }, context) => {
      const userId = getUserId(context);
      const clientId = parseInt(id);
      
      // Check if user is the account manager or an admin
      const client = await prisma.client.findUnique({ where: { id: clientId } });
      if (!client) {
        throw new Error('Client not found');
      }
      
      const currentUser = await prisma.user.findUnique({ where: { id: userId } });
      if (currentUser.role !== 'admin' && client.accountManagerId !== userId) {
        throw new Error('Not authorized to access this client');
      }
      
      return client;
    },
    
    clients: async (_, { where, orderBy, skip, take }, context) => {
      const userId = getUserId(context);
      const currentUser = await prisma.user.findUnique({ where: { id: userId } });
      
      const whereClause = where ? {
        ...(where.name && { name: { contains: where.name } }),
        ...(where.email && { email: { contains: where.email } }),
        ...(where.company && { company: { contains: where.company } }),
        ...(where.isBusinessClient !== undefined && { isBusinessClient: where.isBusinessClient }),
        ...(where.accountManagerId && { accountManagerId: parseInt(where.accountManagerId) })
      } : {};
      
      // If admin, allow access to all clients
      // Otherwise, only show clients where the user is the account manager
      if (currentUser.role !== 'admin') {
        whereClause.accountManagerId = userId;
      }
      
      return prisma.client.findMany({
        where: whereClause,
        orderBy: orderBy ? {
          [orderBy.field.toLowerCase()]: orderBy.direction.toLowerCase()
        } : { name: 'asc' },
        skip: skip || 0,
        take: take || 50
      });
    },
    
    shares: async (_, { where, orderBy, skip, take }, context) => {
      const userId = getUserId(context);
      
      const whereClause = where ? {
        ...(where.resourceType && { resourceType: where.resourceType.toLowerCase() }),
        ...(where.resourceId && { resourceId: parseInt(where.resourceId) }),
        ...(where.sharedById && { sharedById: parseInt(where.sharedById) }),
        ...(where.sharedWithUserId && { sharedWithUserId: parseInt(where.sharedWithUserId) }),
        ...(where.sharedWithEmail && { sharedWithEmail: where.sharedWithEmail }),
        ...(where.isActive !== undefined && { isActive: where.isActive }),
        ...(where.shareLink && { shareLink: where.shareLink })
      } : {};
      
      return prisma.share.findMany({
        where: {
          AND: [
            whereClause,
            {
              OR: [
                { sharedById: userId },
                { sharedWithUserId: userId }
              ]
            }
          ]
        },
        orderBy: orderBy ? {
          [orderBy.field.toLowerCase()]: orderBy.direction.toLowerCase()
        } : { createdAt: 'desc' },
        skip: skip || 0,
        take: take || 50
      });
    },
    
    shareByLink: async (_, { shareLink }, context) => {
      const share = await prisma.share.findUnique({
        where: { shareLink }
      });
      
      if (!share || !share.isActive) {
        throw new Error('Share link is invalid or expired');
      }
      
      // Check if share has expired
      if (share.expiresAt && new Date(share.expiresAt) < new Date()) {
        // Update share to inactive
        await prisma.share.update({
          where: { id: share.id },
          data: { isActive: false }
        });
        throw new Error('Share link has expired');
      }
      
      return share;
    },
    
    groups: async (_, { where, orderBy, skip, take }, context) => {
      const userId = getUserId(context);
      const currentUser = await prisma.user.findUnique({ where: { id: userId } });
      
      const whereClause = where ? {
        ...(where.name && { name: { contains: where.name } })
      } : {};
      
      // If admin, show all groups
      // Otherwise, only show groups where the user is a member
      if (currentUser.role !== 'admin') {
        const userGroups = await prisma.groupMember.findMany({
          where: { userId },
          select: { groupId: true }
        });
        
        const groupIds = userGroups.map(g => g.groupId);
        whereClause.id = { in: groupIds };
      }
      
      return prisma.group.findMany({
        where: whereClause,
        orderBy: orderBy ? {
          [orderBy.field.toLowerCase()]: orderBy.direction.toLowerCase()
        } : { name: 'asc' },
        skip: skip || 0,
        take: take || 50
      });
    },
    
    group: async (_, { id }, context) => {
      const userId = getUserId(context);
      const groupId = parseInt(id);
      const currentUser = await prisma.user.findUnique({ where: { id: userId } });
      
      // Check if user is admin or a member of the group
      if (currentUser.role !== 'admin') {
        const isMember = await prisma.groupMember.findFirst({
          where: {
            groupId,
            userId
          }
        });
        
        if (!isMember) {
          throw new Error('Not authorized to access this group');
        }
      }
      
      return prisma.group.findUnique({ where: { id: groupId } });
    },
    
    auditLogs: async (_, { where, orderBy, skip, take }, context) => {
      const userId = getUserId(context);
      const currentUser = await prisma.user.findUnique({ where: { id: userId } });
      
      // Only admins can view all audit logs
      if (currentUser.role !== 'admin') {
        throw new Error('Not authorized to view audit logs');
      }
      
      const whereClause = where ? {
        ...(where.userId && { userId: parseInt(where.userId) }),
        ...(where.action && { action: { contains: where.action } }),
        ...(where.resourceType && { resourceType: where.resourceType }),
        ...(where.resourceId && { resourceId: parseInt(where.resourceId) }),
        ...(where.ipAddress && { ipAddress: { contains: where.ipAddress } }),
        ...(where.createdAt_gte && { createdAt: { gte: where.createdAt_gte } }),
        ...(where.createdAt_lte && { createdAt: { lte: where.createdAt_lte } })
      } : {};
      
      return prisma.auditLog.findMany({
        where: whereClause,
        orderBy: orderBy ? {
          [orderBy.field.toLowerCase()]: orderBy.direction.toLowerCase()
        } : { createdAt: 'desc' },
        skip: skip || 0,
        take: take || 50
      });
    },
    
    retentionPolicies: async (_, { where, orderBy, skip, take }, context) => {
      const userId = getUserId(context);
      const currentUser = await prisma.user.findUnique({ where: { id: userId } });
      
      // Only admins can view retention policies
      if (currentUser.role !== 'admin') {
        throw new Error('Not authorized to view retention policies');
      }
      
      const whereClause = where ? {
        ...(where.folderType && { folderType: where.folderType.toLowerCase() }),
        ...(where.name && { name: { contains: where.name } }),
        ...(where.autoArchive !== undefined && { autoArchive: where.autoArchive }),
        ...(where.autoDelete !== undefined && { autoDelete: where.autoDelete })
      } : {};
      
      return prisma.retentionPolicy.findMany({
        where: whereClause,
        orderBy: orderBy ? {
          [orderBy.field.toLowerCase()]: orderBy.direction.toLowerCase()
        } : { name: 'asc' },
        skip: skip || 0,
        take: take || 50
      });
    },
    
    retentionPolicy: async (_, { id }, context) => {
      const userId = getUserId(context);
      const currentUser = await prisma.user.findUnique({ where: { id: userId } });
      
      // Only admins can view retention policies
      if (currentUser.role !== 'admin') {
        throw new Error('Not authorized to view retention policies');
      }
      
      return prisma.retentionPolicy.findUnique({
        where: { id: parseInt(id) }
      });
    }
  
    getUser: async (_, { id }, context) => {
      const userId = getUserId(context);
      const requestedUserId = parseInt(id);

      // Only allow users to fetch their own data or admins to fetch any user's data
      if (userId !== requestedUserId) {
        const currentUser = await prisma.user.findUnique({ where: { id: userId } });
        if (currentUser.role !== 'admin') {
          throw new Error('Not authorized to fetch this user data');
        }
      }

      return prisma.user.findUnique({ where: { id: requestedUserId } });
    },

    getFolder: async (_, { id }, context) => {
      const userId = getUserId(context);
      const folderId = parseInt(id);

      try {
        await checkPermission(userId, 'folder', folderId, 'viewer');
      } catch (error) {
        throw new Error('Not authorized to access this folder');
      }

      return prisma.folder.findUnique({ where: { id: folderId } });
    },

    getFile: async (_, { id }, context) => {
      const userId = getUserId(context);
      const fileId = parseInt(id);

      try {
        await checkPermission(userId, 'file', fileId, 'viewer');
      } catch (error) {
        throw new Error('Not authorized to access this file');
      }

      return prisma.file.findUnique({ where: { id: fileId } });
    },

    listFolderContents: async (_, { folderId }, context) => {
      const userId = getUserId(context);
      const folderIdInt = parseInt(folderId);

      try {
        await checkPermission(userId, 'folder', folderIdInt, 'viewer');
      } catch (error) {
        throw new Error('Not authorized to access this folder');
      }

      const folders = await prisma.folder.findMany({
        where: { parentId: folderIdInt }
      });

      const files = await prisma.file.findMany({
        where: { folderId: folderIdInt }
      });

      return { folders, files };
    },

    getGroup: async (_, { id }, context) => {
      const userId = getUserId(context);
      const groupId = parseInt(id);

      const membership = await prisma.groupMember.findFirst({
        where: { groupId, userId }
      });

      if (!membership) {
        const currentUser = await prisma.user.findUnique({ where: { id: userId } });
        if (currentUser.role !== 'admin') {
          throw new Error('Not authorized to access this group');
        }
      }

      return prisma.group.findUnique({ where: { id: groupId } });
    },

    listGroups: async (_, __, context) => {
      const userId = getUserId(context);
      const currentUser = await prisma.user.findUnique({ where: { id: userId } });

      if (currentUser.role === 'admin') {
        return prisma.group.findMany();
      } else {
        const memberships = await prisma.groupMember.findMany({
          where: { userId },
          select: { groupId: true }
        });
        const groupIds = memberships.map(m => m.groupId);
        return prisma.group.findMany({
          where: { id: { in: groupIds } }
        });
      }
    },

    getShare: async (_, { id }, context) => {
      const userId = getUserId(context);
      const shareId = parseInt(id);

      const share = await prisma.share.findUnique({ where: { id: shareId } });

      if (!share) {
        throw new Error('Share not found');
      }

      if (share.sharedById !== userId) {
        const currentUser = await prisma.user.findUnique({ where: { id: userId } });
        if (currentUser.role !== 'admin') {
          throw new Error('Not authorized to access this share');
        }
      }

      return share;
    },

    listUserShares: async (_, __, context) => {
      const userId = getUserId(context);
      return prisma.share.findMany({ where: { sharedById: userId } });
    },
  },

  


// Mutation resolvers
Mutation: {
  // Authentication mutations
  login: async (_, { email, password }, context) => {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new Error('Invalid email or password');
    }
    
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      throw new Error('Invalid email or password');
    }
    
    if (!user.isActive) {
      throw new Error('User account is inactive');
    }
    
    // Update last login timestamp
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() }
    });
    
    // Create log entry
    await logAuditEvent(
      user.id,
      'USER_LOGIN',
      'user',
      user.id,
      { method: 'password' },
      context
    );
    
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: '8h'
    });
    
    return {
      token,
      user
    };
  },
  
  createUser: async (_, { data }, context) => {
    const userId = getUserId(context);
    const currentUser = await prisma.user.findUnique({ where: { id: userId } });
    
    // Only admins can create new users
    if (currentUser.role !== 'admin') {
      throw new Error('Not authorized');
    }
    
    const passwordHash = await bcrypt.hash(data.password, 10);
    
    const user = await prisma.user.create({
      data: {
        email: data.email,
        fullName: data.fullName,
        passwordHash,
        role: data.role.toLowerCase(),
        department: data.department,
        isActive: data.isActive !== undefined ? data.isActive : true
      }
    });
    
    await logAuditEvent(
      userId,
      'USER_CREATE',
      'user',
      user.id,
      { email: user.email, role: user.role },
      context
    );
    
    return user;
  },
  
  updateUser: async (_, { id, data }, context) => {
    const userId = getUserId(context);
    const currentUser = await prisma.user.findUnique({ where: { id: userId } });
    const targetUserId = parseInt(id);
    
    // Only admins or the user themselves can update user data
    if (currentUser.role !== 'admin' && userId !== targetUserId) {
      throw new Error('Not authorized');
    }
    
    // Prepare update data
    const updateData = {
      ...(data.fullName && { fullName: data.fullName }),
      ...(data.department && { department: data.department }),
      ...(data.isActive !== undefined && { isActive: data.isActive })
    };
    
    // Only admins can change role
    if (data.role && currentUser.role === 'admin') {
      updateData.role = data.role.toLowerCase();
    }
    
    // Handle password update
    if (data.password) {
      updateData.passwordHash = await bcrypt.hash(data.password, 10);
    }
    
    const updatedUser = await prisma.user.update({
      where: { id: targetUserId },
      data: updateData
    });
    
    await logAuditEvent(
      userId,
      'USER_UPDATE',
      'user',
      targetUserId,
      { fields: Object.keys(updateData) },
      context
    );
    
    return updatedUser;
  },
  
  createFolder: async (_, { data }, context) => {
    const userId = getUserId(context);
    
    // Check if parent folder exists and user has access
    if (data.parentFolderId) {
      try {
        await checkPermission(userId, 'folder', parseInt(data.parentFolderId), 'editor');
      } catch (error) {
        throw new Error('Not authorized to create folders in this location');
      }
    }
    
    // If client folder, verify the client exists and user has access
    if (data.folderType === 'client' && data.clientId) {
      const client = await prisma.client.findUnique({
        where: { id: parseInt(data.clientId) }
      });
      
      if (!client) {
        throw new Error('Client not found');
      }
      
      if (client.accountManagerId !== userId) {
        const currentUser = await prisma.user.findUnique({ where: { id: userId } });
        if (currentUser.role !== 'admin') {
          throw new Error('Not authorized to create folders for this client');
        }
      }
    }
    
    const folder = await prisma.folder.create({
      data: {
        name: data.name,
        ownerId: userId,
        parentFolderId: data.parentFolderId ? parseInt(data.parentFolderId) : null,
        folderType: data.folderType.toLowerCase(),
        clientId: data.clientId ? parseInt(data.clientId) : null,
        dataClassification: data.dataClassification ? 
          data.dataClassification.toLowerCase() : 'internal'
      }
    });
    
    // Create default permission for the owner
    await prisma.permission.create({
      data: {
        resourceType: 'folder',
        resourceId: folder.id,
        userId,
        accessLevel: 'owner'
      }
    });
    
    await logAuditEvent(
      userId,
      'FOLDER_CREATE',
      'folder',
      folder.id,
      { name: folder.name, folderType: folder.folderType },
      context
    );
    
    return folder;
  },
  
  updateFolder: async (_, { id, data }, context) => {
    const userId = getUserId(context);
    const folderId = parseInt(id);
    
    // Check if user has permission to update folder
    try {
      await checkPermission(userId, 'folder', folderId, 'editor');
    } catch (error) {
      throw new Error('Not authorized to update this folder');
    }
    
    // Check if folder exists
    const folder = await prisma.folder.findUnique({ where: { id: folderId } });
    if (!folder) {
      throw new Error('Folder not found');
    }
    
    // If moving folder, check permission on new parent
    if (data.parentFolderId && data.parentFolderId !== folder.parentFolderId?.toString()) {
      try {
        await checkPermission(userId, 'folder', parseInt(data.parentFolderId), 'editor');
      } catch (error) {
        throw new Error('Not authorized to move folder to this location');
      }
    }
    const updatedFolder = await prisma.folder.update({
      where: { id: folderId },
      data: {
        ...(data.name && { name: data.name }),
        ...(data.parentFolderId !== undefined && { 
          parentFolderId: data.parentFolderId ? parseInt(data.parentFolderId) : null 
        }),
        ...(data.dataClassification && { 
          dataClassification: data.dataClassification.toLowerCase() 
        })
      }
    });
    
    await logAuditEvent(
      userId,
      'FOLDER_UPDATE',
      'folder',
      folderId,
      { name: updatedFolder.name },
      context
    );
    
    return updatedFolder;
  },
  
  deleteFolder: async (_, { id }, context) => {
    const userId = getUserId(context);
    const folderId = parseInt(id);
    
    // Check if user has permission to delete folder
    try {
      await checkPermission(userId, 'folder', folderId, 'owner');
    } catch (error) {
      throw new Error('Not authorized to delete this folder');
    }
    
    // Get folder details for the audit log
    const folder = await prisma.folder.findUnique({ where: { id: folderId } });
    if (!folder) {
      throw new Error('Folder not found');
    }
    
    // Delete folder and cascade to all child entities
    await prisma.folder.delete({ where: { id: folderId } });
    
    await logAuditEvent(
      userId,
      'FOLDER_DELETE',
      'folder',
      folderId,
      { name: folder.name },
      context
    );
    
    return {
      id: folderId,
      success: true,
      message: 'Folder deleted successfully'
    };
  },
  
  uploadFile: async (_, { data }, context) => {
    const userId = getUserId(context);
    
    // Check if user has permission to upload to the folder
    try {
      await checkPermission(userId, 'folder', parseInt(data.folderId), 'editor');
    } catch (error) {
      throw new Error('Not authorized to upload files to this folder');
    }
    
    // Process file upload
    const { createReadStream, filename, mimetype, encoding } = await data.file;
    const fileExtension = path.extname(filename);
    const fileBaseName = path.basename(filename, fileExtension);
    const sanitizedName = fileBaseName.replace(/[^a-zA-Z0-9-_]/g, '_');
    const uniqueFilename = `${sanitizedName}-${uuidv4()}${fileExtension}`;
    
    // Create upload directory based on date
    const today = new Date();
    const uploadSubDir = path.join(
      UPLOAD_DIR,
      `${today.getFullYear()}`,
      `${String(today.getMonth() + 1).padStart(2, '0')}`
    );
    
    if (!fs.existsSync(uploadSubDir)) {
      fs.mkdirSync(uploadSubDir, { recursive: true });
    }
    
    const filePath = path.join(uploadSubDir, uniqueFilename);
    const relativePath = path.relative(UPLOAD_DIR, filePath);
    
    // Save file to disk
    const stream = createReadStream();
    const writeStream = fs.createWriteStream(filePath);
    await new Promise((resolve, reject) => {
      stream.pipe(writeStream)
        .on('finish', resolve)
        .on('error', reject);
    });
    
    // Get file size
    const stats = fs.statSync(filePath);
    const fileSize = stats.size;
    
    // Create file record
    const file = await prisma.file.create({
      data: {
        name: data.name || filename,
        folderId: parseInt(data.folderId),
        ownerId: userId,
        filePath: relativePath,
        fileSize,
        fileType: mimetype,
        dataClassification: data.dataClassification ? 
          data.dataClassification.toLowerCase() : 'internal'
      }
    });
    
    // Create initial file version
    await prisma.fileVersion.create({
      data: {
        fileId: file.id,
        versionNumber: 1,
        filePath: relativePath,
        fileSize,
        modifiedById: userId
      }
    });
    
    // Create default permission for the owner
    await prisma.permission.create({
      data: {
        resourceType: 'file',
        resourceId: file.id,
        userId,
        accessLevel: 'owner'
      }
    });
    
    await logAuditEvent(
      userId,
      'FILE_UPLOAD',
      'file',
      file.id,
      { name: file.name, fileType: file.fileType, fileSize },
      context
    );
    
    return file;
  },
  
  updateFile: async (_, { id, data }, context) => {
    const userId = getUserId(context);
    const fileId = parseInt(id);
    
    // Check if user has permission to update file
    try {
      await checkPermission(userId, 'file', fileId, 'editor');
    } catch (error) {
      throw new Error('Not authorized to update this file');
    }
    
    // Check if file exists and is not locked
    const file = await prisma.file.findUnique({ where: { id: fileId } });
    if (!file) {
      throw new Error('File not found');
    }
    
    if (file.isLocked) {
      // Check if user is owner or manager to allow updating locked files
      const permission = await prisma.permission.findFirst({
        where: {
          resourceType: 'file',
          resourceId: fileId,
          userId,
          accessLevel: { in: ['owner', 'manager'] }
        }
      });
      
      if (!permission) {
        throw new Error('File is locked and cannot be updated');
      }
    }
    
    // Update file metadata
    const updateData = {
      ...(data.name && { name: data.name }),
      ...(data.isLocked !== undefined && { isLocked: data.isLocked }),
      ...(data.dataClassification && { 
        dataClassification: data.dataClassification.toLowerCase() 
      })
    };
    
    // If moving file to a different folder, check permission on new folder
    if (data.folderId && parseInt(data.folderId) !== file.folderId) {
      try {
        await checkPermission(userId, 'folder', parseInt(data.folderId), 'editor');
        updateData.folderId = parseInt(data.folderId);
      } catch (error) {
        throw new Error('Not authorized to move file to this folder');
      }
    }
    
    const updatedFile = await prisma.file.update({
      where: { id: fileId },
      data: updateData
    });
    
    await logAuditEvent(
      userId,
      'FILE_UPDATE',
      'file',
      fileId,
      { name: updatedFile.name, fields: Object.keys(updateData) },
      context
    );
    
    return updatedFile;
  },
  
  updateFileContent: async (_, { id, file: fileUpload }, context) => {
    const userId = getUserId(context);
    const fileId = parseInt(id);
    
    // Check if user has permission to update file
    try {
      await checkPermission(userId, 'file', fileId, 'editor');
    } catch (error) {
      throw new Error('Not authorized to update this file');
    }
    
    // Check if file exists and is not locked
    const file = await prisma.file.findUnique({ where: { id: fileId } });
    if (!file) {
      throw new Error('File not found');
    }
    
    if (file.isLocked) {
      // Check if user is owner or manager to allow updating locked files
      const permission = await prisma.permission.findFirst({
        where: {
          resourceType: 'file',
          resourceId: fileId,
          userId,
          accessLevel: { in: ['owner', 'manager'] }
        }
      });
      
      if (!permission) {
        throw new Error('File is locked and cannot be updated');
      }
    }
    
    // Process file upload
    const { createReadStream, filename, mimetype } = await fileUpload;
    const fileExtension = path.extname(filename);
    const fileBaseName = path.basename(file.name, path.extname(file.name));
    const sanitizedName = fileBaseName.replace(/[^a-zA-Z0-9-_]/g, '_');
    const uniqueFilename = `${sanitizedName}-v${file.version + 1}-${uuidv4()}${fileExtension}`;
    
    // Create upload directory based on date
    const today = new Date();
    const uploadSubDir = path.join(
      UPLOAD_DIR,
      `${today.getFullYear()}`,
      `${String(today.getMonth() + 1).padStart(2, '0')}`
    );
    
    if (!fs.existsSync(uploadSubDir)) {
      fs.mkdirSync(uploadSubDir, { recursive: true });
    }
    
    const filePath = path.join(uploadSubDir, uniqueFilename);
    const relativePath = path.relative(UPLOAD_DIR, filePath);
    
    // Save file to disk
    const stream = createReadStream();
    const writeStream = fs.createWriteStream(filePath);
    await new Promise((resolve, reject) => {
      stream.pipe(writeStream)
        .on('finish', resolve)
        .on('error', reject);
    });
    
    // Get file size
    const stats = fs.statSync(filePath);
    const fileSize = stats.size;
    
    // Create new file version
    await prisma.fileVersion.create({
      data: {
        fileId,
        versionNumber: file.version + 1,
        filePath: relativePath,
        fileSize,
        modifiedById: userId
      }
    });
    
    // Update file record
    const updatedFile = await prisma.file.update({
      where: { id: fileId },
      data: {
        filePath: relativePath,
        fileSize,
        fileType: mimetype,
        version: file.version + 1
      }
    });
    
    await logAuditEvent(
      userId,
      'FILE_CONTENT_UPDATE',
      'file',
      fileId,
      { name: file.name, newVersion: file.version + 1, fileSize },
      context
    );
    
    return updatedFile;
  },
  
  deleteFile: async (_, { id }, context) => {
    const userId = getUserId(context);
    const fileId = parseInt(id);
    
    // Check if user has permission to delete file
    try {
      await checkPermission(userId, 'file', fileId, 'owner');
    } catch (error) {
      throw new Error('Not authorized to delete this file');
    }
    
    // Get file details for the audit log
    const file = await prisma.file.findUnique({ where: { id: fileId } });
    if (!file) {
      throw new Error('File not found');
    }
    
    // Delete file record (cascade will handle related entities)
    await prisma.file.delete({ where: { id: fileId } });
    
    // Note: Physical file deletion could be handled by a separate cleanup process
    // rather than deleting immediately, especially if versioning is important
    
    await logAuditEvent(
      userId,
      'FILE_DELETE',
      'file',
      fileId,
      { name: file.name },
      context
    );
    
    return {
      id: fileId,
      success: true,
      message: 'File deleted successfully'
    };
  },
  
  createPermission: async (_, { data }, context) => {
    const userId = getUserId(context);
    const resourceType = data.resourceType.toLowerCase();
    const resourceId = parseInt(data.resourceId);
    
    // Check if the current user has permission to manage permissions
    try {
      await checkPermission(userId, resourceType, resourceId, 'manager');
    } catch (error) {
      throw new Error(`Not authorized to manage permissions for this ${resourceType}`);
    }
    
    // Verify that the target exists
    let resource;
    if (resourceType === 'folder') {
      resource = await prisma.folder.findUnique({ where: { id: resourceId } });
    } else if (resourceType === 'file') {
      resource = await prisma.file.findUnique({ where: { id: resourceId } });
    }
    
    if (!resource) {
      throw new Error(`${resourceType.charAt(0).toUpperCase() + resourceType.slice(1)} not found`);
    }
    
    // Verify user or group exists
    if (data.userId) {
      const targetUser = await prisma.user.findUnique({ 
        where: { id: parseInt(data.userId) } 
      });
      if (!targetUser) {
        throw new Error('User not found');
      }
    } else if (data.groupId) {
      const targetGroup = await prisma.group.findUnique({ 
        where: { id: parseInt(data.groupId) } 
      });
      if (!targetGroup) {
        throw new Error('Group not found');
      }
    } else {
      throw new Error('Either userId or groupId must be provided');
    }
    
    // Check if permission already exists and update it if it does
    const existingPermission = await prisma.permission.findFirst({
      where: {
        resourceType,
        resourceId,
        ...(data.userId ? { userId: parseInt(data.userId) } : {}),
        ...(data.groupId ? { groupId: parseInt(data.groupId) } : {})
      }
    });
    
    if (existingPermission) {
      const updatedPermission = await prisma.permission.update({
        where: { id: existingPermission.id },
        data: { accessLevel: data.accessLevel.toLowerCase() }
      });
      
      await logAuditEvent(
        userId,
        'PERMISSION_UPDATE',
        resourceType,
        resourceId,
        { 
          accessLevel: data.accessLevel,
          ...(data.userId ? { userId: parseInt(data.userId) } : {}),
          ...(data.groupId ? { groupId: parseInt(data.groupId) } : {})
        },
        context
      );
      
      return updatedPermission;
    }
    
    // Create new permission
    const permission = await prisma.permission.create({
      data: {
        resourceType,
        resourceId,
        ...(data.userId ? { userId: parseInt(data.userId) } : {}),
        ...(data.groupId ? { groupId: parseInt(data.groupId) } : {}),
        accessLevel: data.accessLevel.toLowerCase()
      }
    });
    
    await logAuditEvent(
      userId,
      'PERMISSION_CREATE',
      resourceType,
      resourceId,
      { 
        accessLevel: data.accessLevel,
        ...(data.userId ? { userId: parseInt(data.userId) } : {}),
        ...(data.groupId ? { groupId: parseInt(data.groupId) } : {})
      },
      context
    );
    
    return permission;
  },
  
  deletePermission: async (_, { id }, context) => {
    const userId = getUserId(context);
    const permissionId = parseInt(id);
    
    // Get permission details
    const permission = await prisma.permission.findUnique({
      where: { id: permissionId }
    });
    
    if (!permission) {
      throw new Error('Permission not found');
    }
  // Check if the current user has permission to manage permissions
  try {
    await checkPermission(userId, permission.resourceType, permission.resourceId, 'manager');
  } catch (error) {
    throw new Error(`Not authorized to manage permissions for this ${permission.resourceType}`);
  }
  
  // Don't allow deletion of owner permissions
  if (permission.accessLevel === 'owner') {
    throw new Error('Owner permissions cannot be deleted');
  }
  
  // Delete the permission
  await prisma.permission.delete({ where: { id: permissionId } });
  
  await logAuditEvent(
    userId,
    'PERMISSION_DELETE',
    permission.resourceType,
    permission.resourceId,
    { 
      permissionId,
      ...(permission.userId ? { userId: permission.userId } : {}),
      ...(permission.groupId ? { groupId: permission.groupId } : {})
    },
    context
  );
  
  return {
    id: permissionId,
    success: true,
    message: 'Permission deleted successfully'
  };
  },
  
  createShare: async (_, { data }, context) => {
  const userId = getUserId(context);
  const resourceType = data.resourceType.toLowerCase();
  const resourceId = parseInt(data.resourceId);
  
  // Check if the current user has permission to share
  try {
    await checkPermission(userId, resourceType, resourceId, 'editor');
  } catch (error) {
    throw new Error(`Not authorized to share this ${resourceType}`);
  }
  
  // Verify that the target exists
  let resource;
  if (resourceType === 'folder') {
    resource = await prisma.folder.findUnique({ where: { id: resourceId } });
  } else if (resourceType === 'file') {
    resource = await prisma.file.findUnique({ where: { id: resourceId } });
  }
  
  if (!resource) {
    throw new Error(`${resourceType.charAt(0).toUpperCase() + resourceType.slice(1)} not found`);
  }
  
  // Create a unique share link if needed
  let shareLink = null;
  if (data.createShareLink) {
    shareLink = `${uuidv4()}-${Date.now()}`;
  }
  
  // Hash password if provided
  let passwordHash = null;
  if (data.password) {
    passwordHash = await bcrypt.hash(data.password, 10);
  }
  
  // Create the share
  const share = await prisma.share.create({
    data: {
      resourceType,
      resourceId,
      sharedById: userId,
      sharedWithUserId: data.sharedWithUserId ? parseInt(data.sharedWithUserId) : null,
      sharedWithEmail: data.sharedWithEmail,
      accessLevel: data.accessLevel.toLowerCase(),
      shareLink,
      passwordProtected: !!data.password,
      passwordHash,
      expiresAt: data.expiresAt,
      viewOnly: data.viewOnly !== undefined ? data.viewOnly : false,
      allowDownload: data.allowDownload !== undefined ? data.allowDownload : true
    }
  });
  
  await logAuditEvent(
    userId,
    'SHARE_CREATE',
    resourceType,
    resourceId,
    { 
      accessLevel: data.accessLevel,
      ...(data.sharedWithUserId ? { sharedWithUserId: parseInt(data.sharedWithUserId) } : {}),
      ...(data.sharedWithEmail ? { sharedWithEmail: data.sharedWithEmail } : {}),
      hasShareLink: !!shareLink,
      isPasswordProtected: !!data.password
    },
    context
  );
  
  return share;
  },
  
  updateShare: async (_, { id, data }, context) => {
  const userId = getUserId(context);
  const shareId = parseInt(id);
  
  // Get share details
  const share = await prisma.share.findUnique({
    where: { id: shareId }
  });
  
  if (!share) {
    throw new Error('Share not found');
  }
  
  // Only the creator can update a share
  if (share.sharedById !== userId) {
    const currentUser = await prisma.user.findUnique({ where: { id: userId } });
    if (currentUser.role !== 'admin') {
      throw new Error('Not authorized to update this share');
    }
  }
  
  // Prepare update data
  const updateData = {
    ...(data.accessLevel && { accessLevel: data.accessLevel.toLowerCase() }),
    ...(data.expiresAt !== undefined && { expiresAt: data.expiresAt }),
    ...(data.isActive !== undefined && { isActive: data.isActive }),
    ...(data.viewOnly !== undefined && { viewOnly: data.viewOnly }),
    ...(data.allowDownload !== undefined && { allowDownload: data.allowDownload })
  };
  
  // Update password if provided
  if (data.password) {
    updateData.passwordHash = await bcrypt.hash(data.password, 10);
    updateData.passwordProtected = true;
  } else if (data.removePassword) {
    updateData.passwordHash = null;
    updateData.passwordProtected = false;
  }
  
  // Update share link if requested
  if (data.updateShareLink) {
    updateData.shareLink = `${uuidv4()}-${Date.now()}`;
  } else if (data.removeShareLink) {
    updateData.shareLink = null;
  }
  
  const updatedShare = await prisma.share.update({
    where: { id: shareId },
    data: updateData
  });
  
  await logAuditEvent(
    userId,
    'SHARE_UPDATE',
    share.resourceType,
    share.resourceId,
    { 
      shareId,
      fields: Object.keys(updateData)
    },
    context
  );
  
  return updatedShare;
  },
  
  deleteShare: async (_, { id }, context) => {
  const userId = getUserId(context);
  const shareId = parseInt(id);
  
  // Get share details
  const share = await prisma.share.findUnique({
    where: { id: shareId }
  });
  
  if (!share) {
    throw new Error('Share not found');
  }
  
  // Only the creator can delete a share
  if (share.sharedById !== userId) {
    const currentUser = await prisma.user.findUnique({ where: { id: userId } });
    if (currentUser.role !== 'admin') {
      throw new Error('Not authorized to delete this share');
    }
  }
  
  // Delete the share
  await prisma.share.delete({ where: { id: shareId } });
  
  await logAuditEvent(
    userId,
    'SHARE_DELETE',
    share.resourceType,
    share.resourceId,
    { shareId },
    context
  );
  
  return {
    id: shareId,
    success: true,
    message: 'Share deleted successfully'
  };
  },
  
  accessSharedResource: async (_, { shareLink, password }, context) => {
  const share = await prisma.share.findUnique({
    where: { shareLink }
  });
  
  if (!share || !share.isActive) {
    throw new Error('Invalid or expired share link');
  }
  
  // Check if share has expired
  if (share.expiresAt && new Date(share.expiresAt) < new Date()) {
    // Update share to inactive
    await prisma.share.update({
      where: { id: share.id },
      data: { isActive: false }
    });
    throw new Error('Share link has expired');
  }
  
  // Check password if protected
  if (share.passwordProtected) {
    if (!password) {
      throw new Error('Password is required');
    }
    
    const valid = await bcrypt.compare(password, share.passwordHash);
    if (!valid) {
      throw new Error('Invalid password');
    }
  }
  
  // Get resource details
  let resource;
  if (share.resourceType === 'folder') {
    resource = await prisma.folder.findUnique({ where: { id: share.resourceId } });
  } else if (share.resourceType === 'file') {
    resource = await prisma.file.findUnique({ where: { id: share.resourceId } });
  }
  
  if (!resource) {
    throw new Error('Shared resource not found');
  }
  
  // Log access event
  await logAuditEvent(
    null, // No user id for anonymous access
    'SHARE_ACCESS',
    share.resourceType,
    share.resourceId,
    { shareId: share.id },
    context
  );
  
  return {
    share,
    resource
  };
  },
  
  createGroup: async (_, { data }, context) => {
  const userId = getUserId(context);
  const currentUser = await prisma.user.findUnique({ where: { id: userId } });
  
  // Only admins can create groups
  if (currentUser.role !== 'admin') {
    throw new Error('Not authorized to create groups');
  }
  
  const group = await prisma.group.create({
    data: {
      name: data.name,
      description: data.description
    }
  });
  
  // Add creator as admin
  await prisma.groupMember.create({
    data: {
      groupId: group.id,
      userId,
      role: 'admin'
    }
  });
  
  await logAuditEvent(
    userId,
    'GROUP_CREATE',
    'group',
    group.id,
    { name: group.name },
    context
  );
  
  return group;
  },
  
  updateGroup: async (_, { id, data }, context) => {
  const userId = getUserId(context);
  const groupId = parseInt(id);
  
  // Check if user is admin of the group
  const membership = await prisma.groupMember.findFirst({
    where: {
      groupId,
      userId,
      role: 'admin'
    }
  });
  
  if (!membership) {
    // Check if user is a system admin
    const currentUser = await prisma.user.findUnique({ where: { id: userId } });
    if (currentUser.role !== 'admin') {
      throw new Error('Not authorized to update this group');
    }
  }
  
  const updatedGroup = await prisma.group.update({
    where: { id: groupId },
    data: {
      ...(data.name && { name: data.name }),
      ...(data.description !== undefined && { description: data.description })
    }
  });
  
  await logAuditEvent(
    userId,
    'GROUP_UPDATE',
    'group',
    groupId,
    { fields: Object.keys(data) },
    context
  );
  
  return updatedGroup;
  },
  
  deleteGroup: async (_, { id }, context) => {
  const userId = getUserId(context);
  const groupId = parseInt(id);
  
  // Check if user is admin of the group
  const membership = await prisma.groupMember.findFirst({
    where: {
      groupId,
      userId,
      role: 'admin'
    }
  });
  
  if (!membership) {
    // Check if user is a system admin
    const currentUser = await prisma.user.findUnique({ where: { id: userId } });
    if (currentUser.role !== 'admin') {
      throw new Error('Not authorized to delete this group');
    }
  }
  
  // Get group details for the audit log
  const group = await prisma.group.findUnique({ where: { id: groupId } });
  if (!group) {
    throw new Error('Group not found');
  }
  
  // Delete group (cascade will handle members and permissions)
  await prisma.group.delete({ where: { id: groupId } });
  
  await logAuditEvent(
    userId,
    'GROUP_DELETE',
    'group',
    groupId,
    { name: group.name },
    context
  );
  
  return {
    id: groupId,
    success: true,
    message: 'Group deleted successfully'
  };
  },
  
  addGroupMember: async (_, { data }, context) => {
  const userId = getUserId(context);
  const groupId = parseInt(data.groupId);
  const memberUserId = parseInt(data.userId);
  
  // Check if user is admin of the group
  const membership = await prisma.groupMember.findFirst({
    where: {
      groupId,
      userId,
      role: 'admin'
    }
  });
  
  if (!membership) {
    // Check if user is a system admin
    const currentUser = await prisma.user.findUnique({ where: { id: userId } });
    if (currentUser.role !== 'admin') {
      throw new Error('Not authorized to add members to this group');
    }
  }
  
  // Check if user exists
  const targetUser = await prisma.user.findUnique({ where: { id: memberUserId } });
  if (!targetUser) {
    throw new Error('User not found');
  }
  
  // Check if user is already a member
  const existingMembership = await prisma.groupMember.findFirst({
    where: {
      groupId,
      userId: memberUserId
    }
  });
  
  if (existingMembership) {
    throw new Error('User is already a member of this group');
  }
  
  // Add user to group
  const groupMember = await prisma.groupMember.create({
    data: {
      groupId,
      userId: memberUserId,
      role: data.role ? data.role.toLowerCase() : 'member'
    }
  });
  
  await logAuditEvent(
    userId,
    'GROUP_MEMBER_ADD',
    'group',
    groupId,
    { userId: memberUserId, role: groupMember.role },
    context
  );
  
  return groupMember;
  },
  
  updateGroupMember: async (_, { id, data }, context) => {
  const userId = getUserId(context);
  const membershipId = parseInt(id);
  
  // Get membership details
  const membership = await prisma.groupMember.findUnique({
    where: { id: membershipId }
  });
  
  if (!membership) {
    throw new Error('Group membership not found');
  }
  
  // Check if user is admin of the group
  const isAdmin = await prisma.groupMember.findFirst({
    where: {
      groupId: membership.groupId,
      userId,
      role: 'admin'
    }
  });
  
  if (!isAdmin) {
    // Check if user is a system admin
    const currentUser = await prisma.user.findUnique({ where: { id: userId } });
    if (currentUser.role !== 'admin') {
      throw new Error('Not authorized to update group membership');
    }
  }
  
  // Update membership
  const updatedMembership = await prisma.groupMember.update({
    where: { id: membershipId },
    data: {
      role: data.role.toLowerCase()
    }
  });
  
  await logAuditEvent(
    userId,
    'GROUP_MEMBER_UPDATE',
    'group',
    membership.groupId,
    { userId: membership.userId, role: data.role },
    context
  );
  
  return updatedMembership;
  },
  
  removeGroupMember: async (_, { id }, context) => {
    const userId = getUserId(context);
    const membershipId = parseInt(id);
  
    // Get membership details
    const membership = await prisma.groupMember.findUnique({
      where: { id: membershipId }
    });
  
    if (!membership) {
      throw new Error('Group membership not found');
    }
  
    // Check if user is admin of the group
    const isAdmin = await prisma.groupMember.findFirst({
      where: {
        groupId: membership.groupId,
        userId,
        role: 'admin'
      }
    });
  
    if (!isAdmin) {
      // Check if user is a system admin
      const currentUser = await prisma.user.findUnique({ where: { id: userId } });
      if (currentUser.role !== 'admin') {
        throw new Error('Not authorized to remove group members');
      }
    }
  
    // Remove membership
    await prisma.groupMember.delete({ where: { id: membershipId } });
  
    await logAuditEvent(
      userId,
      'GROUP_MEMBER_REMOVE',
      'group',
      membership.groupId,
      { userId: membership.userId },
      context
    );
  
    return {
      id: membershipId,
      success: true,
      message: 'Group member removed successfully'
    };
  }
},




 // Add custom type resolvers
 User: {
  groups: async (parent, _, context) => {
    return prisma.groupMember.findMany({
      where: { userId: parent.id },
      include: { group: true }
    }).then(memberships => memberships.map(m => m.group));
  }
},

Group: {
  members: async (parent, _, context) => {
    return prisma.groupMember.findMany({
      where: { groupId: parent.id },
      include: { user: true }
    }).then(memberships => memberships.map(m => ({
      ...m.user,
      role: m.role
    })));
  }
},

Folder: {
  parent: async (parent, _, context) => {
    if (!parent.parentId) return null;
    return prisma.folder.findUnique({ where: { id: parent.parentId } });
  },
  subfolders: async (parent, _, context) => {
    return prisma.folder.findMany({ where: { parentId: parent.id } });
  },
  files: async (parent, _, context) => {
    return prisma.file.findMany({ where: { folderId: parent.id } });
  }
},

File: {
  folder: async (parent, _, context) => {
    return prisma.folder.findUnique({ where: { id: parent.folderId } });
  },
  versions: async (parent, _, context) => {
    return prisma.fileVersion.findMany({
      where: { fileId: parent.id },
      orderBy: { versionNumber: 'desc' }
    });
  }
},

Share: {
  resource: async (parent, _, context) => {
    if (parent.resourceType === 'folder') {
      return prisma.folder.findUnique({ where: { id: parent.resourceId } });
    } else if (parent.resourceType === 'file') {
      return prisma.file.findUnique({ where: { id: parent.resourceId } });
    }
    return null;
  },
  sharedBy: async (parent, _, context) => {
    return prisma.user.findUnique({ where: { id: parent.sharedById } });
  },
  sharedWithUser: async (parent, _, context) => {
    if (!parent.sharedWithUserId) return null;
    return prisma.user.findUnique({ where: { id: parent.sharedWithUserId } });
  }
}
};

export default resolvers;