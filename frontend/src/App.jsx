import { useEffect, useRef, useState } from 'react';

const messages = {
  zh: {
    pageTitle: 'Motoko 能力展示',
    brandTitle: 'Motoko Show',
    brandKicker: 'MOTOKO LAB',
    brandSubtitle: 'Internet Computer Canister Playground',
    heroTitle: '在一个页面里理解 Motoko 能做什么',
    heroDesc: '通过横向滑动卡片，快速查看 Motoko 在状态持久化、类型安全、Actor 异步和 canister 组合上的常见能力。',
    sliderTitle: 'Motoko 能力滑动列表',
    sliderHint: '左右滑动或点击按钮查看下一项',
    login: '登录',
    logout: '退出',
    statusAnon: '当前状态：未登录',
    statusGuest: '当前状态：访客已登录',
    panelTitle: '登录入口',
    panelDesc: '右上角按钮已预留登录交互，后续可直接接入 Internet Identity。',
    guestLogin: '访客登录',
    closePanel: '关闭',
    prev: '上一项',
    next: '下一项',
    footerText: '这个首页可以直接扩展为可交互的 canister 演示页。',
    cards: [
      {
        tag: 'State',
        accent: '#1d756f',
        title: '持久化状态',
        desc: '使用 stable 变量让关键数据跨升级保持不丢失。',
        points: ['适合配置和用户状态', '可升级迁移', '降低链上状态重建成本']
      },
      {
        tag: 'Calls',
        accent: '#de7f23',
        title: 'Query / Update 分离',
        desc: '用 query 实现快速读，用 update 进行共识写入。',
        points: ['弱化不必要的写入延迟', '可针对读写负载优化', '调用语义更清晰']
      },
      {
        tag: 'Types',
        accent: '#11708f',
        title: '强类型建模',
        desc: '用 record、variant、option 表达复杂业务结构，编译期提前拦截错误。',
        points: ['减少 runtime 异常', '可读性更高', '重构更安全']
      },
      {
        tag: 'Actor',
        accent: '#9a5f15',
        title: 'Actor 异步模型',
        desc: '通过 async/await 组织 canister 之间通信，自然支持并发交互。',
        points: ['节点间交互简洁', '适合流程编排', '天然适配链上异步']
      },
      {
        tag: 'Errors',
        accent: '#226b4f',
        title: '可预期的错误处理',
        desc: '基于 Result 或 variant 显式返回成功/失败，前后端协作更稳定。',
        points: ['失败场景可枚举', '便于观测和告警', '不依赖隐式异常']
      },
      {
        tag: 'Compose',
        accent: '#8d4f27',
        title: 'Canister 组合能力',
        desc: '将策略、资产、计费拆成独立 canister，再以 Motoko 组合为完整应用。',
        points: ['边界清晰', '更易复用', '可独立升级']
      },
      {
        tag: 'Identity',
        accent: '#1c6f63',
        title: '基于 Principal 的权限',
        desc: '用 caller principal 在 Motoko 中实现权限校验与访问控制。',
        points: ['可按账户细粒度授权', '可支持多角色逻辑', '易于审计']
      },
      {
        tag: 'Performance',
        accent: '#b56e1a',
        title: '程序性能与成本意识',
        desc: '在链上环境中，通过数据结构与调用策略设计经营 cycles 消耗。',
        points: ['少写多读降低开销', '结构选型影响资源用量', '为业务扩展提前规划']
      }
    ]
  },
  en: {
    pageTitle: 'Motoko Capability Showcase',
    brandTitle: 'Motoko Show',
    brandKicker: 'MOTOKO LAB',
    brandSubtitle: 'Internet Computer Canister Playground',
    heroTitle: 'Explore What Motoko Can Do In One Screen',
    heroDesc:
      'Browse horizontally to see how Motoko supports durable state, strong typing, actor async calls, and scalable canister composition.',
    sliderTitle: 'Motoko Capability Slider',
    sliderHint: 'Swipe horizontally or use buttons to move through cards',
    login: 'Login',
    logout: 'Logout',
    statusAnon: 'Status: Not logged in',
    statusGuest: 'Status: Guest signed in',
    panelTitle: 'Login Entry',
    panelDesc: 'This button is ready for auth flow and can be connected to Internet Identity later.',
    guestLogin: 'Guest Sign In',
    closePanel: 'Close',
    prev: 'Previous',
    next: 'Next',
    footerText: 'This homepage can be extended into a full canister interaction demo.',
    cards: [
      {
        tag: 'State',
        accent: '#1d756f',
        title: 'Durable State',
        desc: 'Use stable variables so critical data survives canister upgrades.',
        points: ['Ideal for app settings and user state', 'Supports upgrade migration', 'Reduces state reconstruction risk']
      },
      {
        tag: 'Calls',
        accent: '#de7f23',
        title: 'Query / Update Separation',
        desc: 'Use query for fast reads and update for consensus-backed writes.',
        points: ['Avoid unnecessary write latency', 'Optimize by read/write profile', 'Clearer call semantics']
      },
      {
        tag: 'Types',
        accent: '#11708f',
        title: 'Strong Type Modeling',
        desc: 'Use records, variants, and options to represent complex business rules safely.',
        points: ['Catch issues before runtime', 'Improve readability', 'Safer refactoring']
      },
      {
        tag: 'Actor',
        accent: '#9a5f15',
        title: 'Actor Async Model',
        desc: 'Coordinate canister-to-canister workflows with async/await and actor messaging.',
        points: ['Clean cross-canister communication', 'Good for workflow orchestration', 'Natural fit for on-chain async']
      },
      {
        tag: 'Errors',
        accent: '#226b4f',
        title: 'Explicit Error Handling',
        desc: 'Return success/failure via Result or variants for predictable behavior across front and back end.',
        points: ['Enumerate failure paths', 'Better observability', 'No hidden exceptions required']
      },
      {
        tag: 'Compose',
        accent: '#8d4f27',
        title: 'Canister Composition',
        desc: 'Split strategy, assets, and billing into focused canisters, then compose with Motoko.',
        points: ['Clear service boundaries', 'Higher reuse', 'Independent upgrades']
      },
      {
        tag: 'Identity',
        accent: '#1c6f63',
        title: 'Principal-Based Access',
        desc: 'Authorize and scope permissions in Motoko with caller principals.',
        points: ['Fine-grained account control', 'Supports multi-role logic', 'Simple to audit']
      },
      {
        tag: 'Performance',
        accent: '#b56e1a',
        title: 'Performance And Cost',
        desc: 'Choose data structures and call patterns deliberately to manage cycles consumption.',
        points: ['Read-heavy patterns cut cost', 'Data layout impacts resources', 'Plan ahead for scale']
      }
    ]
  }
};

function App() {
  const [lang, setLang] = useState('zh');
  const [loggedIn, setLoggedIn] = useState(false);
  const [loginPanelOpen, setLoginPanelOpen] = useState(false);

  const actionsRef = useRef(null);
  const cardsRef = useRef(null);

  const t = messages[lang];

  useEffect(() => {
    document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
    document.title = t.pageTitle;
  }, [lang, t.pageTitle]);

  useEffect(() => {
    if (cardsRef.current) {
      cardsRef.current.scrollTo({ left: 0, behavior: 'auto' });
    }
  }, [lang]);

  useEffect(() => {
    if (!loginPanelOpen) {
      return undefined;
    }

    const handleOutsideClick = (event) => {
      if (actionsRef.current?.contains(event.target)) {
        return;
      }

      setLoginPanelOpen(false);
    };

    document.addEventListener('click', handleOutsideClick);
    return () => document.removeEventListener('click', handleOutsideClick);
  }, [loginPanelOpen]);

  const scrollCards = (direction) => {
    const cardsTrack = cardsRef.current;
    if (!cardsTrack) {
      return;
    }

    const firstCard = cardsTrack.querySelector('.card');
    if (!firstCard) {
      return;
    }

    const gapValue = getComputedStyle(cardsTrack).gap || '0px';
    const gap = Number.parseFloat(gapValue) || 0;
    const step = firstCard.getBoundingClientRect().width + gap;

    cardsTrack.scrollBy({
      left: direction * step,
      behavior: 'smooth'
    });
  };

  const handleLoginClick = () => {
    if (loggedIn) {
      setLoggedIn(false);
      setLoginPanelOpen(false);
      return;
    }

    setLoginPanelOpen((open) => !open);
  };

  const handleGuestLogin = () => {
    setLoggedIn(true);
    setLoginPanelOpen(false);
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="logo" aria-hidden="true" />
          <div>
            <p className="brand-kicker">{t.brandKicker}</p>
            <p className="brand-title">{t.brandTitle}</p>
            <p className="brand-subtitle">{t.brandSubtitle}</p>
          </div>
        </div>

        <div className="actions" ref={actionsRef}>
          <div className="lang-switch" role="group" aria-label="Language">
            <button className={`lang-btn ${lang === 'zh' ? 'active' : ''}`} onClick={() => setLang('zh')} type="button">
              中
            </button>
            <button className={`lang-btn ${lang === 'en' ? 'active' : ''}`} onClick={() => setLang('en')} type="button">
              EN
            </button>
          </div>

          <button className="login-btn" onClick={handleLoginClick} type="button">
            {loggedIn ? t.logout : t.login}
          </button>

          <div className={`login-panel ${loginPanelOpen ? '' : 'hidden'}`} role="dialog" aria-modal="false">
            <p className="panel-title">{t.panelTitle}</p>
            <p className="panel-desc">{t.panelDesc}</p>
            <div className="panel-actions">
              <button className="panel-btn primary" onClick={handleGuestLogin} type="button">
                {t.guestLogin}
              </button>
              <button className="panel-btn" onClick={() => setLoginPanelOpen(false)} type="button">
                {t.closePanel}
              </button>
            </div>
          </div>
        </div>
      </header>

      <section className="hero">
        <div>
          <h1 className="hero-title">{t.heroTitle}</h1>
          <p className="hero-desc">{t.heroDesc}</p>
        </div>
        <div className="status-stack">
          <div className={`status-pill ${loggedIn ? 'active' : ''}`}>{loggedIn ? t.statusGuest : t.statusAnon}</div>
          <div className="signal-grid" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
        </div>
      </section>

      <section className="slider-shell" aria-label="Motoko capabilities">
        <div className="slider-head">
          <div>
            <h2 className="slider-title">{t.sliderTitle}</h2>
            <p className="slider-hint">{t.sliderHint}</p>
          </div>
          <div className="nav">
            <button className="nav-btn" onClick={() => scrollCards(-1)} type="button">
              <span aria-hidden="true">◀</span>
              {t.prev}
            </button>
            <button className="nav-btn" onClick={() => scrollCards(1)} type="button">
              <span aria-hidden="true">▶</span>
              {t.next}
            </button>
          </div>
        </div>

        <div className="cards" ref={cardsRef}>
          {t.cards.map((card, idx) => (
            <article
              className="card"
              key={`${card.tag}-${idx}`}
              style={{
                '--accent': card.accent,
                animationDelay: `${idx * 48}ms`
              }}
            >
              <span className="card-tag">{card.tag}</span>
              <h3 className="card-title">{card.title}</h3>
              <p className="card-desc">{card.desc}</p>
              <ul className="card-points">
                {card.points.map((point) => (
                  <li key={point}>{point}</li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </section>

      <p className="footer">{t.footerText}</p>
    </div>
  );
}

export default App;
