const root = document.documentElement;
const body = document.body;
const sidebar = document.getElementById('sidebar');
const layout = document.getElementById('layout');
const themeToggle = document.getElementById('themeToggle');
const sidebarDetach = document.getElementById('sidebarDetach');
const dragHandle = document.getElementById('sidebarDragHandle');

function setTheme(modern) {
  root.dataset.theme = modern ? 'modern' : 'classic';
  themeToggle?.setAttribute('aria-pressed', String(modern));
  if (themeToggle) {
    themeToggle.title = modern ? 'Switch to classic theme' : 'Switch to darker modern theme';
  }
}

themeToggle?.addEventListener('click', () => {
  setTheme(root.dataset.theme !== 'modern');
});

function setDetached(detached) {
  sidebar?.classList.toggle('detached', detached);
  body.classList.toggle('sidebar-detached', detached);
  sidebarDetach?.setAttribute('aria-pressed', String(detached));
  if (sidebarDetach) {
    sidebarDetach.title = detached ? 'Re-dock sidebar' : 'Detach and move the sidebar';
  }

  if (detached && sidebar) {
    const rect = sidebar.getBoundingClientRect();
    sidebar.style.left = `${Math.max(12, rect.left)}px`;
    sidebar.style.top = `${Math.max(84, rect.top)}px`;
  } else if (sidebar) {
    sidebar.style.left = '';
    sidebar.style.top = '';
  }
}

sidebarDetach?.addEventListener('click', () => {
  setDetached(!sidebar?.classList.contains('detached'));
});

let dragging = false;
let offsetX = 0;
let offsetY = 0;

function pointerPosition(event) {
  if (event.touches?.length) return { x: event.touches[0].clientX, y: event.touches[0].clientY };
  return { x: event.clientX, y: event.clientY };
}

function startDrag(event) {
  if (!sidebar?.classList.contains('detached')) return;
  if (event.target.closest('button, summary, input, select, textarea, a')) return;

  const pos = pointerPosition(event);
  const rect = sidebar.getBoundingClientRect();
  dragging = true;
  offsetX = pos.x - rect.left;
  offsetY = pos.y - rect.top;
  document.body.style.userSelect = 'none';
  event.preventDefault();
}

function moveDrag(event) {
  if (!dragging || !sidebar) return;
  const pos = pointerPosition(event);
  const rect = sidebar.getBoundingClientRect();
  const maxLeft = Math.max(12, window.innerWidth - rect.width - 12);
  const maxTop = Math.max(84, window.innerHeight - rect.height - 12);
  sidebar.style.left = `${Math.min(maxLeft, Math.max(12, pos.x - offsetX))}px`;
  sidebar.style.top = `${Math.min(maxTop, Math.max(84, pos.y - offsetY))}px`;
  event.preventDefault();
}

function endDrag() {
  dragging = false;
  document.body.style.userSelect = '';
}

dragHandle?.addEventListener('pointerdown', startDrag);
dragHandle?.addEventListener('touchstart', startDrag, { passive: false });
sidebar?.querySelector('.sidebar-head')?.addEventListener('pointerdown', startDrag);
window.addEventListener('pointermove', moveDrag, { passive: false });
window.addEventListener('touchmove', moveDrag, { passive: false });
window.addEventListener('pointerup', endDrag);
window.addEventListener('touchend', endDrag);

window.addEventListener('resize', () => {
  if (!sidebar?.classList.contains('detached')) return;
  const rect = sidebar.getBoundingClientRect();
  sidebar.style.left = `${Math.min(Math.max(12, rect.left), Math.max(12, innerWidth - rect.width - 12))}px`;
  sidebar.style.top = `${Math.min(Math.max(84, rect.top), Math.max(84, innerHeight - rect.height - 12))}px`;
});
