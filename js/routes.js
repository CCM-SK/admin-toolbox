/** Parse the public hash route. #canvas is a first-class route; all other hashes are tool IDs. */
export function parseAppRoute(hash, knownToolIds) {
  const value = String(hash || '').replace(/^#/, '').trim();
  if (value.toLowerCase() === 'canvas') return { type: 'canvas' };
  if (value && knownToolIds.has(value)) return { type: 'tool', id: value };
  return { type: 'tool', id: 'dashboard' };
}
