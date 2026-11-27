import rss from '@astrojs/rss';
import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { SITE } from '../config/site';
import { sortPosts } from '../utils/posts';

export const GET: APIRoute = async (context) => {
  const posts = sortPosts(await getCollection('posts'));

  return rss({
    title: SITE.title,
    description: SITE.description.en,
    site: context.site ?? SITE.url,
    items: posts.map((post) => ({
      title: post.data.title,
      pubDate: post.data.pubDate,
      description: post.data.description,
      link: `/posts/${post.id}/`,
      categories: post.data.tags,
    })),
  });
};
