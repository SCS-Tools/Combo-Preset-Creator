/* Consistent smooth document scrolling for tools hosted in Qt WebEngine. */
(() => {
  const style = document.createElement('style');
  style.textContent = `
    html { scroll-behavior: smooth; scrollbar-width: thin; scrollbar-color: #ee6b2f #101216; }
    body { scrollbar-width: thin; scrollbar-color: #ee6b2f #101216; }
    ::-webkit-scrollbar { width: 12px; height: 12px; }
    ::-webkit-scrollbar-track { background: #101216; border: 3px solid #101216; border-radius: 999px; }
    ::-webkit-scrollbar-thumb { background: linear-gradient(180deg, #ff814a, #d95320); border: 3px solid #101216; border-radius: 999px; min-height: 42px; }
    ::-webkit-scrollbar-thumb:hover { background: linear-gradient(180deg, #ff9a66, #ee6b2f); }
    ::-webkit-scrollbar-corner { background: #101216; }
  `;
  document.head.appendChild(style);

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  let target = null;
  let animation = 0;

  const scrollRoot = () => document.scrollingElement || document.documentElement;
  const position = () => scrollRoot().scrollTop;
  const limit = () => Math.max(0, scrollRoot().scrollHeight - window.innerHeight);
  const animate = () => {
    const current = position();
    const distance = target - current;
    if (Math.abs(distance) < 0.5) {
      scrollRoot().scrollTop = target;
      target = null;
      animation = 0;
      return;
    }
    scrollRoot().scrollTop = current + distance * 0.18;
    animation = requestAnimationFrame(animate);
  };

  window.addEventListener('scroll', () => {
    if (!animation) target = null;
  }, { passive: true });
  window.addEventListener('wheel', event => {
    if (event.ctrlKey || event.shiftKey || event.deltaY === 0) return;
    if (event.target.closest('select, textarea, [data-native-scroll]')) return;
    const maximum = limit();
    if (!maximum) return;
    event.preventDefault();
    const step = event.deltaMode === WheelEvent.DOM_DELTA_LINE ? 18 : event.deltaMode === WheelEvent.DOM_DELTA_PAGE ? window.innerHeight * 0.85 : 1;
    if (target === null) target = position();
    target = Math.max(0, Math.min(maximum, target + event.deltaY * step));
    if (!animation) animation = requestAnimationFrame(animate);
  }, { passive: false });
})();
