export const $ = (selector, root = document) =>
    root.querySelector(selector);

export const $$ = (selector, root = document) =>
    [...root.querySelectorAll(selector)];

export const escapeHtml = (value = '') =>
    String(value).replace(
        /[&<>"']/g,
        (char) =>
            ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;',
            })[char]
    );

export const formatBytes = (bytes) => {
    if (!Number.isFinite(bytes)) {
        return '—';
    }

    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];

    let unitIndex = 0;
    let value = bytes;

    while (
        value >= 1024 &&
        unitIndex < units.length - 1
    ) {
        value /= 1024;
        unitIndex++;
    }

    const decimals = unitIndex === 0 ? 0 : 2;

    return `${value.toFixed(decimals)} ${units[unitIndex]}`;
};

export const downloadText = (
    name,
    text,
    type = 'text/plain;charset=utf-8'
) => {
    const blob = new Blob([text], { type });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.style.display = 'none';

    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => {
        URL.revokeObjectURL(url);
    }, 1000);
};

export const readText = (file) => file.text();

export const csvParse = (text) => {
    const rows = [];

    let row = [];
    let cell = '';
    let inQuotes = false;

    for (let i = 0; i < text.length; i++) {
        const char = text[i];
        const nextChar = text[i + 1];

        if (inQuotes) {
            if (char === '"' && nextChar === '"') {
                cell += '"';
                i++;
            } else if (char === '"') {
                inQuotes = false;
            } else {
                cell += char;
            }

            continue;
        }

        if (char === '"') {
            inQuotes = true;
        } else if (char === ',') {
            row.push(cell);
            cell = '';
        } else if (char === '\n') {
            row.push(cell);
            rows.push(row);

            row = [];
            cell = '';
        } else if (char !== '\r') {
            cell += char;
        }
    }

    if (cell !== '' || row.length) {
        row.push(cell);
        rows.push(row);
    }

    const width = Math.max(
        0,
        ...rows.map((currentRow) => currentRow.length)
    );

    return rows.filter(
        (currentRow) =>
            currentRow.length === width &&
            currentRow.some((value) => value !== '')
    );
};

export const jsonPretty = (text) =>
    JSON.stringify(JSON.parse(text), null, 2);

export const downloadBlob = (name, blob) => {
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.style.display = 'none';

    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => {
        URL.revokeObjectURL(url);
    }, 1000);
};

export function dropBinder(element, onFiles) {
    element.addEventListener('dragover', (event) => {
        event.preventDefault();
        element.classList.add('drag');
    });

    element.addEventListener('dragleave', () => {
        element.classList.remove('drag');
    });

    element.addEventListener('drop', (event) => {
        event.preventDefault();
        element.classList.remove('drag');

        onFiles([...event.dataTransfer.files]);
    });
}

export function hex(buffer) {
    return [...new Uint8Array(buffer)]
        .map((byte) =>
            byte.toString(16).padStart(2, '0')
        )
        .join('');
}
/*
export function enableToolDragging(windowEl, handleEl) {
  if (!windowEl || !handleEl) {
    throw new Error('enableToolDragging requires a window element and drag handle.');
  }

  let dragging = false;
  let pointerId = null;
  let startX = 0;
  let startY = 0;
  let originX = 0;
  let originY = 0;
  handleEl.style.touchAction = 'none';
  handleEl.style.userSelect = 'none';

  handleEl.addEventListener('pointerdown', event => {
    if (event.button !== 0) return;
    if (event.target.closest('button, input, select, textarea, a')) {
      return;
    }

    const rect = windowEl.getBoundingClientRect();
    dragging = true;
    pointerId = event.pointerId;
    startX = event.clientX;
    startY = event.clientY;
    originX = rect.left;
    originY = rect.top;
    windowEl.style.position = 'fixed';
    windowEl.style.left = `${originX}px`;
    windowEl.style.top = `${originY}px`;
    windowEl.style.margin = '0';
    windowEl.style.zIndex = '1000';
    handleEl.setPointerCapture(pointerId);
    handleEl.classList.add('dragging');

    event.preventDefault();
  });

  handleEl.addEventListener('pointermove', event => {
    if (!dragging || event.pointerId !== pointerId) return;

    const dx = event.clientX - startX;
    const dy = event.clientY - startY;
    const rect = windowEl.getBoundingClientRect();
    const minVisible = 80;
    const margin = 20;
    let left = originX + dx;
    let top = originY + dy;
    left = Math.max(
      margin - rect.width + minVisible,
      Math.min(left, window.innerWidth - minVisible)
    );

    top = Math.max(
      margin,
      Math.min(top, window.innerHeight - minVisible)
    );

    windowEl.style.left = `${left}px`;
    windowEl.style.top = `${top}px`;
  });

  function stopDragging(event) {
    if (!dragging || event.pointerId !== pointerId) return;

    dragging = false;
    handleEl.classList.remove('dragging');

    try {
      handleEl.releasePointerCapture(pointerId);
    } catch { }

    pointerId = null;
  }

  handleEl.addEventListener('pointerup', stopDragging);
  handleEl.addEventListener('pointercancel', stopDragging);
}
*/
export function enableToolDragging(windowEl, handleEl, isEnabled = () => true) {
  if (!windowEl || !handleEl) {
    throw new Error('enableToolDragging requires a window element and drag handle.');
  }

  let dragging = false;
  let pointerId = null;
  let startX = 0;
  let startY = 0;
  let offsetX = 0;
  let offsetY = 0;
  handleEl.style.touchAction = 'none';
  handleEl.style.userSelect = 'none';

  handleEl.addEventListener('pointerdown', event => {
    if (!isEnabled()) return;
    if (event.button !== 0) return;

    if (event.target.closest('button, input, select, textarea, a')) {
      return;
    }

    dragging = true;
    pointerId = event.pointerId;
    startX = event.clientX;
    startY = event.clientY;
    offsetX = 0;
    offsetY = 0;
    handleEl.setPointerCapture(pointerId);
    handleEl.classList.add('dragging');

    event.preventDefault();
  });

  handleEl.addEventListener('pointermove', event => {
    if (!dragging || event.pointerId !== pointerId) return;
    offsetX = event.clientX - startX;
    offsetY = event.clientY - startY;
    windowEl.style.transform =
      `translate(${offsetX}px, ${offsetY}px)`;
  });

  function stopDragging(event) {
    if (!dragging || event.pointerId !== pointerId) return;
    dragging = false;
    handleEl.classList.remove('dragging');
    try {
      handleEl.releasePointerCapture(pointerId);
    } catch {}

    pointerId = null;
  }

  handleEl.addEventListener('pointerup', stopDragging);
  handleEl.addEventListener('pointercancel', stopDragging);
}