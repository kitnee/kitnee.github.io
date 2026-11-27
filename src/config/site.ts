export interface TimelineItem {
  period: string;
  org: string;
  role: {
    vi: string;
    en: string;
  };
  note?: {
    vi: string;
    en: string;
  };
}

export interface AchievementItem {
  year: string;
  title: string;
  rank: string;
  detail?: {
    vi: string;
    en: string;
  };
}

export const SITE = {
  handle: 'kitnee',
  title: 'KITNEE // NETRUNNER LOGS',
  url: 'https://kitnee.github.io',
  description: {
    vi: 'Kho lưu trữ CTF write-ups và phân tích forensics artifacts của kítnê.',
    en: 'A living archive of CTF write-ups and forensics artifacts analysis by kitnee.',
  },
  terminal: {
    prompt: 'netdive:~$',
    tagline: {
      vi: 'Kho lưu trữ CTF write-ups và phân tích forensics artifacts của kítnê.',
      en: 'A living archive of CTF write-ups and forensics artifacts analysis by kitnee.',
    },
    status: 'ICE_BREAKER // ONLINE',
    sector: 'NIGHT_CITY // LUNA_LINK',
  },
  about: {
    short: {
      vi: 'Mình là kitnee - sinh viên IT-EP K69 tại SoICT, ĐH Bách khoa Hà Nội. Mảng yêu thích chính là Digital Forensics & Incident Response (DFIR).',
      en: 'I\'m kitnee - IT-EP K69 at SoICT, Hanoi University of Science and Technology, obsessed with Digital Forensics & Incident Response (DFIR).',
    },
    intro: {
      vi: [
        'Bonjour, mình là kitnee.',
        'Mình là thành viên của lớp IT-EP K69 tại Trường Công nghệ Thông tin và Truyền thông (SoICT), Đại học Bách khoa Hà Nội. Niềm đam mê chính của mình là Digital Forensics & Incident Response (DFIR).',
        'Blog này là nơi lưu trữ các bài CTF write-ups, phân tích forensics artifacts và những ghi chú bảo mật trong quá trình học tập của mình.',
      ],
      en: [
        'Hey, I\'m kitnee.',
        'I am a proud member of IT-EP K69 at the School of Information and Communication Technology (SoICT), Hanoi University of Science and Technology. My primary obsession lies in Digital Forensics & Incident Response (DFIR).',
        'This blog is a living archive of my CTF write-ups, forensics artifacts analysis, and security notes.',
      ],
    },
    focus: ['Digital Forensics', 'Incident Response', 'Malware Analysis', 'Threat Intelligence'],
    interests: {
      vi: ['ngủ', 'LiQi mobile', 'Matcha-enjoyer', 'Manga & Anime lover'],
      en: ['sleep', 'Arena of Valor', 'Matcha-enjoyer', 'Manga & Anime lover'],
    },
  },
  timeline: [
    {
      period: '03/2026 - NOW',
      org: 'BKSEC',
      role: {
        vi: 'Thành viên BKSEC',
        en: 'BKSEC Member',
      },
      note: {
        vi: 'Tham gia sinh hoạt và tham gia đánh các giải CTF onsite/online cùng CLB (chủ yếu mảng Forensics).',
        en: 'Active member focusing on Forensics and competing in onsite/online CTFs with the club.',
      },
    },
    {
      period: '11/2025',
      org: 'CTF Journey',
      role: {
        vi: 'Bắt đầu hành trình CTF',
        en: 'Started CTF Journey',
      },
      note: {
        vi: 'Bắt đầu làm quen với CTF và Digital Forensics.',
        en: 'First steps into CTFs and Digital Forensics.',
      },
    },
  ] as TimelineItem[],
  achievements: [
    {
      year: '15/08/2026',
      title: 'MTA CTF 2026',
      rank: 'TOP 1',
      detail: {
        vi: 'Giải Nhất cuộc thi MTA CTF 2026.',
        en: '1st Place at MTA CTF 2026.',
      },
    },
  ] as AchievementItem[],
  socials: [
    {
      name: 'GitHub',
      href: 'https://github.com/kitnee',
      icon: 'github' as const,
    },
    {
      name: 'Gmail (kidlun2512@gmail.com)',
      href: 'mailto:kidlun2512@gmail.com',
      icon: 'mail' as const,
    },
    {
      name: 'Instagram (@thatthachatphac)',
      href: 'https://www.instagram.com/thatthachatphac/',
      icon: 'instagram' as const,
    },
    {
      name: 'LinkedIn (in/pham-gia-kien)',
      href: 'https://www.linkedin.com/in/pham-gia-kien',
      icon: 'linkedin' as const,
    },
    {
      name: 'Discord',
      href: 'https://discord.com/users/757567296586776657',
      icon: 'discord' as const,
    },
    {
      name: 'RSS',
      href: '/rss.xml',
      icon: 'rss' as const,
    },
  ],
  presence: {
    discordUserId: '757567296586776657',
    fallbackStatus: {
      vi: 'ngủ zzz ~~~',
      en: 'sleeping',
    },
    fallbackTrack: {
      title: 'I Really Want to Stay at Your House',
      artist: 'Rosa Walton, Hallie Coggins',
      url: 'https://open.spotify.com/track/7mykoq6R3BArsSpNDjFQTm',
    },
  },
};

export const UI = {
  vi: {
    navHome: 'HOME',
    navPosts: 'POSTS',
    navHtb: 'HTB',
    navAbout: 'ABOUT',
    search: 'SEARCH',
    searchTitle: 'BREACH // TÌM KIẾM',
    searchPlaceholder: 'Gõ tiêu đề, tag, CTF hoặc từ khóa...',
    searchEmpty: 'Không có log nào khớp.',
    searchHint: 'Gõ từ khóa để tìm trong toàn bộ writeup và bài viết.',
    enterArchive: 'Vào kho bài viết',
    aboutLabel: 'DOSSIER',
    aboutHeading: 'ABOUT_ME',
    aboutSub: 'Hồ sơ cá nhân, chặng đường, thành tích và sở thích.',
    pathTitle: 'PATH // TIMELINE',
    achievementsTitle: 'ACHIEVEMENTS',
    focusTitle: 'FOCUS_AREAS',
    interestsTitle: 'INTERESTS',
    latestPostsTitle: 'LATEST_LOGS',
    viewAllPosts: 'XEM TẤT CẢ',
    postsHeading: 'POSTS',
    postsSub: 'CTF writeups và blogs.',
    filterPlaceholder: 'Lọc theo tiêu đề, tag, CTF...',
    allLangs: 'Tất cả (VI / EN)',
    viLang: 'Tiếng Việt (vi)',
    enLang: 'English (en)',
    allCategories: 'Tất cả',
    readMore: 'READ_FILE',
    minRead: 'phút',
    prev: 'PREV',
    next: 'NEXT',
    noPosts: 'Không có bài viết nào khớp với bộ lọc.',
    resetFilters: 'RESET_FILTER',
    toc: 'INDEX',
    prevPost: 'BÀI CŨ HƠN',
    nextPost: 'BÀI MỚI HƠN',
  },
  en: {
    navHome: 'HOME',
    navPosts: 'POSTS',
    navHtb: 'HTB',
    navAbout: 'ABOUT',
    search: 'SEARCH',
    searchTitle: 'BREACH // SEARCH',
    searchPlaceholder: 'Type a title, tag, CTF, or keyword...',
    searchEmpty: 'No matching logs found.',
    searchHint: 'Type to search across all writeups and articles.',
    enterArchive: 'Enter archive',
    aboutLabel: 'DOSSIER',
    aboutHeading: 'ABOUT_ME',
    aboutSub: 'Profile, path, achievements, and interests.',
    pathTitle: 'PATH // TIMELINE',
    achievementsTitle: 'ACHIEVEMENTS',
    focusTitle: 'FOCUS_AREAS',
    interestsTitle: 'INTERESTS',
    latestPostsTitle: 'LATEST_LOGS',
    viewAllPosts: 'VIEW ALL',
    postsHeading: 'POSTS',
    postsSub: 'CTF writeups and blogs.',
    filterPlaceholder: 'Filter by title, tag, CTF...',
    allLangs: 'All languages (VI / EN)',
    viLang: 'Vietnamese (vi)',
    enLang: 'English (en)',
    allCategories: 'All',
    readMore: 'READ_FILE',
    minRead: 'min',
    prev: 'PREV',
    next: 'NEXT',
    noPosts: 'No posts match the current filters.',
    resetFilters: 'RESET_FILTER',
    toc: 'INDEX',
    prevPost: 'OLDER',
    nextPost: 'NEWER',
  },
} as const;
