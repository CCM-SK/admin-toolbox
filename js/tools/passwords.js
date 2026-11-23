import { $, downloadText } from '../utils.js';
const WORD_LIST = ['amber', 'apple', 'arrow', 'atlas', 'basil', 'beacon', 'binary', 'blaze',
  'bloom', 'bridge', 'bronze', 'breeze', 'canyon', 'canvas', 'caper', 'carbon',
  'cedar', 'cinder', 'circuit', 'cloud', 'cobalt', 'coral', 'crystal', 'delta',
  'dawn', 'dune', 'echo', 'eagle', 'elm', 'ember', 'engine', 'falcon', 'flame',
  'flint', 'forest', 'frost', 'galaxy', 'garden', 'glacier', 'granite', 'grove',
  'harbor', 'hazel', 'horizon', 'iris', 'island', 'jade', 'jungle', 'kernel',
  'lilac', 'linen', 'lunar', 'marble', 'maple', 'matrix', 'meadow', 'mercury',
  'meteor', 'mint', 'mirror', 'mosaic', 'nebula', 'nickel', 'north', 'oasis',
  'olive', 'onyx', 'opal', 'orange', 'orbit', 'packet', 'panda', 'parchment',
  'pebble', 'pepper', 'pine', 'planet', 'plasma', 'plum', 'prairie', 'quartz',
  'rain', 'raven', 'reed', 'ridge', 'rocket', 'ruby', 'sage', 'sand',
  'sapphire', 'scarlet', 'shadow', 'shale', 'shell', 'signal', 'silver', 'sky',
  'slate', 'socket', 'solar', 'spruce', 'stone', 'storm', 'subnet', 'summit',
  'sunset', 'terra', 'thunder', 'timber', 'topaz', 'trail', 'tulip', 'valley',
  'vector', 'velvet', 'violet', 'wave', 'willow', 'window', 'winter', 'woodland',
  'zephyr', 'zinc',];
const CHARSETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{}:,.?',
};
export function renderPasswords(app) {
  // Keep this tool instance's controls isolated when several tools are mounted.
  const $ = (selector, root = app) => root.querySelector(selector);
  app.innerHTML = `
    <section class="card">
      <h2>Password / passphrase generator</h2>
      <div class="grid-2">
        <div>
          <label for="pgMode">Mode</label>
          <select id="pgMode">
            <option value="password">Random password</option>
            <option value="passphrase">Word-based passphrase</option>
          </select>
        </div>
        <div>
          <label for="pgCount">Count</label>
          <input id="pgCount" type="number" min="1" max="100" value="8">
        </div>
      </div>
      <div class="grid-2 generated-style-56f43562">
        <div>
          <label for="pgLength">Length / words</label>
          <input id="pgLength" type="number" min="4" max="64" value="20">
        </div>
        <div id="charsetWrap">
          <label>Character sets</label>
          <div class="checkline"><input type="checkbox" id="lower" checked> lowercase</div>
          <div class="checkline"><input type="checkbox" id="upper" checked> uppercase</div>
          <div class="checkline"><input type="checkbox" id="digits" checked> digits</div>
          <div class="checkline"><input type="checkbox" id="symbols" checked> symbols</div>
        </div>
      </div>
      <div class="generated-style-1b0f4999">
        <button class="btn primary" id="gen">Generate</button>
        <button class="btn" id="copyAll">Copy</button>
        <button class="btn" id="download">Download text</button>
      </div>
      <textarea id="out" spellcheck="false" readonly class="generated-style-56f43562"></textarea>
      <p class="small">
        Randomness source: <span class="mono">crypto.getRandomValues()</span>.
        Generated values are not stored by the application.
      </p>
    </section>
  `;
  const mode = $('#pgMode');
  function toggleCharsetVisibility() {
    $('#charsetWrap').style.display = mode.value === 'password' ? 'block' : 'none';
  }
  mode.onchange = toggleCharsetVisibility;
  toggleCharsetVisibility();
  $('#gen').onclick = () => {
    try {
      $('#out').value = mode.value === 'password' ? generatePassword() : generatePassphrase();
    } catch (e) {
      $('#out').value = e.message;
    }
  };
  $('#copyAll').onclick = () => navigator.clipboard?.writeText($('#out').value);
  $('#download').onclick = () =>
    downloadText('generated-passwords.txt', $('#out').value + '\n');
  // Returns `n` cryptographically random 32-bit integers.
  function randomInts(n) {
    const buffer = new Uint32Array(n);
    crypto.getRandomValues(buffer);
    return buffer;
  }
  function getCount() {
    return Math.min(100, Math.max(1, +$('#pgCount').value || 10));
  }
  function generatePassword() {
    let chars = '';
    if ($('#lower').checked) chars += CHARSETS.lower;
    if ($('#upper').checked) chars += CHARSETS.upper;
    if ($('#digits').checked) chars += CHARSETS.digits;
    if ($('#symbols').checked) chars += CHARSETS.symbols;
    if (!chars) throw new Error('Choose at least one character set.');
    const length = Math.min(64, Math.max(4, +$('#pgLength').value || 20));
    const count = getCount();
    return Array.from({ length: count }, () => {
      let password = '';
      for (const int of randomInts(length)) {
        password += chars[int % chars.length];
      }
      return password;
    }).join('\n');
  }
  function generatePassphrase() {
    const count = getCount();
    const wordsPerPhrase = Math.min(30, Math.max(4, +$('#pgLength').value || 20));
    return Array.from({ length: count }, () =>
      [...randomInts(wordsPerPhrase)]
        .map((int) => WORD_LIST[int % WORD_LIST.length])
        .join('-')
    ).join('\n');
  }
}
