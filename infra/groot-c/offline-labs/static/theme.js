/* Console, Java and Apache display preference only. No requests, form values, or cookies. */
(function () {
  'use strict';

  var storageKey = 'groot-lab.theme.v1';
  var root = document.documentElement;
  var button;
  var label;
  var theme;

  function valid(value) {
    return value === 'dark' || value === 'light';
  }

  function themeIcon() {
    function svgNode(tag, attributes) {
      var node = document.createElementNS('http://www.w3.org/2000/svg', tag);
      Object.keys(attributes).forEach(function (name) {
        node.setAttribute(name, attributes[name]);
      });
      return node;
    }
    var svg = svgNode('svg', {viewBox: '0 0 24 24', width: '16', height: '16',
      fill: 'none', stroke: 'currentColor', 'stroke-width': '1.7',
      'stroke-linecap': 'round', 'stroke-linejoin': 'round',
      'aria-hidden': 'true', focusable: 'false', 'class': 'groot-theme-icon'});
    var sun = svgNode('g', {'class': 'groot-theme-sun'});
    sun.appendChild(svgNode('circle', {cx: '12', cy: '12', r: '3.5'}));
    sun.appendChild(svgNode('path', {d: 'M12 2v2m0 16v2M2 12h2m16 0h2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4'}));
    var moon = svgNode('g', {'class': 'groot-theme-moon'});
    moon.appendChild(svgNode('path', {d: 'M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z'}));
    svg.appendChild(sun);
    svg.appendChild(moon);
    return svg;
  }

  function pageKind() {
    if (document.querySelector('.app-shell')) return 'console';
    if (document.querySelector('.version-card')) return 'httpd';
    if (document.querySelector('#request-form')) return 'java';
    return 'generic';
  }

  function labNavigation(kind) {
    if (kind !== 'java' && kind !== 'httpd') return;
    var header = document.querySelector('.topbar');
    if (!header || header.querySelector('.groot-lab-nav')) return;
    var navigation = document.createElement('nav');
    navigation.className = 'groot-lab-nav';
    navigation.setAttribute('aria-label', '실습 탐색');
    var home = document.createElement('a');
    home.href = '/log4shell/';
    home.textContent = 'Lab Console';
    var arrow = document.createElement('span');
    arrow.setAttribute('aria-hidden', 'true');
    arrow.textContent = '↗';
    home.appendChild(arrow);
    var separator = document.createElement('span');
    separator.className = 'groot-lab-nav-separator';
    separator.setAttribute('aria-hidden', 'true');
    separator.textContent = '/';
    var current = document.createElement('span');
    current.setAttribute('aria-current', 'page');
    current.textContent = kind === 'java' ? 'Log4Shell' : 'Apache 실습';
    navigation.appendChild(home);
    navigation.appendChild(separator);
    navigation.appendChild(current);
    header.insertBefore(navigation, header.lastElementChild);
  }

  function storedTheme() {
    try {
      var value = window.localStorage.getItem(storageKey);
      return valid(value) ? value : null;
    } catch (error) {
      // Privacy settings may make persistent storage unavailable.
      return null;
    }
  }

  function apply(value, animate) {
    if (!valid(value)) return;
    // Initial paint and background-tab storage sync must settle immediately.
    // Only an explicit press of this document's toggle enables motion.
    root.setAttribute('data-groot-motion', animate ? 'enabled' : 'disabled');
    theme = value;
    root.setAttribute('data-groot-theme', theme);
    button.setAttribute('aria-pressed', String(theme === 'dark'));
    button.title = theme === 'dark' ? '화이트 모드로 전환' : '다크 모드로 전환';
    label.textContent = theme === 'dark' ? '다크' : '화이트';
  }

  function start() {
    if (!document.body || document.getElementById('groot-theme-toolbar')) return;
    var kind = pageKind();
    root.setAttribute('data-groot-page', kind);
    labNavigation(kind);

    var toolbar = document.createElement('div');
    toolbar.id = 'groot-theme-toolbar';
    toolbar.setAttribute('role', 'group');
    toolbar.setAttribute('aria-label', '화면 테마');
    button = document.createElement('button');
    button.id = 'groot-theme-toggle';
    button.type = 'button';
    // Keep the toggle's accessible name stable; pressed means dark mode.
    button.setAttribute('aria-label', '다크 모드');
    button.appendChild(themeIcon());
    label = document.createElement('span');
    label.setAttribute('aria-hidden', 'true');
    button.appendChild(label);
    toolbar.appendChild(button);
    var skip = document.querySelector('body > .skip-link');
    document.body.insertBefore(toolbar, skip ? skip.nextSibling : document.body.firstChild);

    // Every lab starts with the console's default; a saved choice always wins.
    apply(storedTheme() || (kind === 'generic' ? 'light' : 'dark'));
    button.addEventListener('click', function () {
      apply(theme === 'dark' ? 'light' : 'dark', true);
      try {
        window.localStorage.setItem(storageKey, theme);
      } catch (error) {
        // Switching this document still works when persistence is unavailable.
      }
    });
    window.addEventListener('storage', function (event) {
      if (event.key === storageKey && valid(event.newValue)) apply(event.newValue);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, {once: true});
  } else {
    start();
  }
}());
