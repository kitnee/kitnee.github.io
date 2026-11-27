import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { sortPosts } from '../utils/posts';

export const GET: APIRoute = async () => {
  const posts = sortPosts(await getCollection('posts'));

  const index = posts.map((post) => ({
    slug: post.id,
    title: post.data.title,
    description: post.data.description,
    lang: post.data.lang,
    category: post.data.category,
    tags: post.data.tags,
    ctf: post.data.ctf ?? '',
    pubDate: post.data.pubDate.toISOString(),
    excerpt: (post.body ?? '')
      .replace(/```[\s\S]*?```/g, ' ')
      .replace(/[#*_`>\-\[\]()]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 280),
  }));

  return new Response(JSON.stringify(index), {
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
};
