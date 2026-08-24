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