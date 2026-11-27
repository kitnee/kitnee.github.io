import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const posts = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/posts' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    pubDate: z.coerce.date(),
    updatedDate: z.coerce.date().optional(),
    lang: z.enum(['vi', 'en']).default('vi'),
    category: z.enum(['writeup', 'article']).default('writeup'),
    tags: z.array(z.string()).default([]),
    cover: z.string().optional(),
    ctf: z.string().optional(),
    difficulty: z.enum(['Very Easy', 'Easy', 'Medium', 'Hard', 'Insane']).optional(),
    draft: z.boolean().default(false),
  }),
});

export const collections = { posts };
