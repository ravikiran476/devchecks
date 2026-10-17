import type { ArchCheckConfig } from './analyze.js';

/** Starting points for common project shapes. Copy one into archcheck.config.json and adapt it. */
export const presets: Record<'react' | 'vue' | 'node', ArchCheckConfig> = {
  react: {
    aliases: { '@/*': ['src/*'] },
    layers: [
      { name: 'ui', include: ['src/components/**', 'src/pages/**', 'src/views/**', 'src/app/**', 'src/routes/**'] },
      { name: 'hooks', include: ['src/hooks/**'] },
      { name: 'service', include: ['src/services/**', 'src/api/**'] },
      { name: 'data', include: ['src/data/**', 'src/repositories/**', 'src/db/**'] },
      { name: 'shared', include: ['src/utils/**', 'src/lib/**', 'src/types/**', 'src/constants/**'] },
    ],
    allowed: {
      ui: ['hooks', 'service', 'shared'],
      hooks: ['service', 'shared'],
      service: ['data', 'shared'],
      data: ['shared'],
      shared: [],
    },
    restricted: [
      {
        from: ['src/components/**', 'src/pages/**', 'src/views/**'],
        to: ['axios', 'node-fetch', 'ky'],
        message: 'UI code must call a service instead of making HTTP requests directly',
      },
    ],
    boundaries: [{ name: 'feature', pattern: 'src/features/*' }],
  },
  vue: {
    aliases: { '@/*': ['src/*'] },
    layers: [
      { name: 'ui', include: ['src/components/**', 'src/views/**', 'src/pages/**', 'src/layouts/**'] },
      { name: 'composables', include: ['src/composables/**'] },
      { name: 'store', include: ['src/stores/**', 'src/store/**'] },
      { name: 'service', include: ['src/services/**', 'src/api/**'] },
      { name: 'shared', include: ['src/utils/**', 'src/lib/**', 'src/types/**'] },
    ],
    allowed: {
      ui: ['composables', 'store', 'service', 'shared'],
      composables: ['store', 'service', 'shared'],
      store: ['service', 'shared'],
      service: ['shared'],
      shared: [],
    },
    restricted: [
      {
        from: ['src/components/**', 'src/views/**', 'src/pages/**'],
        to: ['axios'],
        message: 'Components must use a service or store action instead of HTTP clients',
      },
    ],
    boundaries: [{ name: 'module', pattern: 'src/modules/*' }],
  },
  node: {
    layers: [
      { name: 'http', include: ['src/routes/**', 'src/controllers/**', 'src/handlers/**', 'src/middleware/**'] },
      { name: 'service', include: ['src/services/**', 'src/domain/**', 'src/use-cases/**'] },
      { name: 'data', include: ['src/repositories/**', 'src/models/**', 'src/db/**'] },
      { name: 'shared', include: ['src/utils/**', 'src/lib/**', 'src/config/**', 'src/types/**'] },
    ],
    allowed: {
      http: ['service', 'shared'],
      service: ['data', 'shared'],
      data: ['shared'],
      shared: [],
    },
    restricted: [
      {
        from: ['src/routes/**', 'src/controllers/**', 'src/handlers/**'],
        to: ['pg', 'mysql2', 'mongoose', 'mongodb', '@prisma/client', 'sequelize', 'knex', 'typeorm'],
        message: 'HTTP handlers must go through services and repositories, not the database driver',
      },
      {
        from: ['src/domain/**'],
        to: ['express', 'fastify', 'koa', '@nestjs/common'],
        message: 'Domain logic must not depend on the web framework',
      },
    ],
  },
};
