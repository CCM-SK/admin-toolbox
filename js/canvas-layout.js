const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

export function sortToolsBySpaceThenName(tools) {
  return [...tools].sort((a, b) =>
    collator.compare(a.category || '', b.category || '') || collator.compare(a.name || '', b.name || '')
  );
}

export function displaySpaceName(value) {
  return String(value || '').replace(/\b([a-z])/g, character => character.toUpperCase());
}

// Preserve imported panel dimensions independently of the current viewport.
// A Canvas created on a large monitor should retain its intended window sizes
// when opened later; overflow is handled by the scrollable Canvas board.
export function resolveCanvasPanelDimensions(layout, defaults) {
  const dimension = (value, fallback, minimum) => {
    if (typeof value !== 'number' || !Number.isFinite(value)) return fallback;
    return Math.max(minimum, Math.min(12000, value));
  };
  return {
    width: dimension(layout?.width, defaults.width, 340),
    height: dimension(layout?.height, defaults.height, 280)
  };
}

export function createCanvasLayoutExport(panels, exportedAt = new Date().toISOString()) {
  const cleanPanels = panels.map(panel => ({
    id: panel.id,
    name: panel.name,
    category: panel.category,
    left: Math.round(panel.left),
    top: Math.round(panel.top),
    width: Math.round(panel.width),
    height: Math.round(panel.height),
    minimized: Boolean(panel.minimized),
    maximized: Boolean(panel.maximized),
    zIndex: Math.max(0, Math.round(panel.zIndex || 0))
  })).sort((a, b) => a.zIndex - b.zIndex);

  return {
    application: 'Admin Toolbox',
    format: 'admin-toolbox-canvas',
    version: 1,
    exportedAt,
    panels: cleanPanels
  };
}

export function parseCanvasLayoutExport(data, knownToolIds, maxPanels = 16) {
  if (!data || typeof data !== 'object' || data.application !== 'Admin Toolbox' ||
      data.format !== 'admin-toolbox-canvas' || data.version !== 1 || !Array.isArray(data.panels)) {
    throw new Error('Unsupported Canvas file or version.');
  }
  if (data.panels.length < 1 || data.panels.length > maxPanels) {
    throw new Error(`Canvas file must contain between 1 and ${maxPanels} tools.`);
  }

  const seen = new Set();
  const panels = data.panels.map(item => {
    if (!item || typeof item !== 'object' || typeof item.id !== 'string' || !knownToolIds.has(item.id)) {
      throw new Error('Canvas file contains an unknown tool.');
    }
    if (seen.has(item.id)) throw new Error('Canvas file contains duplicate tools.');
    seen.add(item.id);

    const number = (key, minimum, maximum) => {
      const value = item[key];
      if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum || value > maximum) {
        throw new Error(`Canvas file contains an invalid ${key} value.`);
      }
      return value;
    };

    return {
      id: item.id,
      left: number('left', 0, 50000),
      top: number('top', 0, 50000),
      width: number('width', 340, 12000),
      height: number('height', 280, 12000),
      minimized: item.minimized === true,
      maximized: item.maximized === true,
      zIndex: typeof item.zIndex === 'number' && Number.isFinite(item.zIndex)
        ? Math.max(0, Math.min(100000, Math.round(item.zIndex)))
        : 0
    };
  });

  return { panels: panels.sort((a, b) => a.zIndex - b.zIndex) };
}
