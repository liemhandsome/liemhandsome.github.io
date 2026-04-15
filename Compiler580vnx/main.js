// ═══════════════════════════════════════════════════
// EXAMPLE PROGRAMS
// ═══════════════════════════════════════════════════
const EXAMPLES = {
  hello: `org 0xe9e0

setlr
  buffer_clear
xr0 = 0x1111, adr_of text
printline
render.ddd4

text:
str "Hello~580VNX"`,

  waitshift: `org 0xe9e0

setlr
  buffer_clear
waitshift
xr0 = 0x1111, adr_of msg
printline
render.ddd4
  
msg:
str "Press~SHIFT"`,

  drawline: `org 0xe9e0

setlr
buffer_clear
xr0=0x0101,0x3131
line_draw
render.ddd4`,

  loop: `org 0xe9e0
home:
  waitshift
  setlr
  buffer_clear
  xr0 = 0x1111, adr_of msg
  printline
  render.ddd4
loop:
xr0=0xD630,0xD184
BL strcpy
er14=0xD62E
sp=er14,pop er14


msg:
str "Looping..."`,

  str: `org 0xe9e0

setlr
  buffer_clear
xr0 = 0x1111, adr_of line1
printline
xr0 = 0x2121, adr_of line2
printline
render.ddd4
line1:
str "Handsome~ROP"
line2:
str "fx-580VNX"`
};

// ═══════════════════════════════════════════════════
// UI REFERENCES
// ═══════════════════════════════════════════════════
const asmInput   = document.getElementById('asmInput');
const outputBox  = document.getElementById('outputBox');
const statusMsg  = document.getElementById('statusMsg');
const statsMsg   = document.getElementById('statsMsg');
const compileBtn = document.getElementById('compileBtn');
const clearBtn   = document.getElementById('clearBtn');
const copyHexBtn = document.getElementById('copyHexBtn');
const pasteBtn   = document.getElementById('pasteBtn');
const loaderBar  = document.getElementById('loaderBar');

let lastHexResult = '';
let pyodide = null;

function setStatus(txt, isErr=false) {
  statusMsg.textContent = txt;
  statusMsg.style.color = isErr ? '#ff5370' : '#8892b0';
}

function setOutput(html) { outputBox.innerHTML = html; }

// ═══════════════════════════════════════════════════
// PYODIDE BOOTSTRAP
// ═══════════════════════════════════════════════════
async function loadPyodide_() {
  const pyLoadLabel = document.getElementById('pyLoadLabel');
  const pyLoadBar   = document.getElementById('pyLoadBar');

  const setLabel = t => { if(pyLoadLabel) pyLoadLabel.textContent = t; };
  const setBar   = w => { if(loaderBar) loaderBar.style.width = w; };

  setLabel('⏳ fetching python...');
  setBar('10%');

  // Load pyodide.js script safely
  await new Promise((res, rej) => {
    if (window.loadPyodide) { res(); return; }
    const s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/pyodide/v0.26.2/full/pyodide.js';
    s.onload = res;
    s.onerror = () => rej(new Error('Failed to load pyodide.js'));
    document.head.appendChild(s);
  });

  setBar('40%');
  setLabel('⏳ initialising python...');
  if (pyLoadBar) pyLoadBar.classList.remove('indeterminate');

  pyodide = await window.loadPyodide({ indexURL: 'https://cdn.jsdelivr.net/pyodide/v0.26.2/full/' });

  setBar('75%');
  setLabel('⏳ setting up compiler...');

  // Inject compiler data + char table
  const data = JSON.parse(document.getElementById('compilerData').textContent);
  const charTable = JSON.parse(document.getElementById('charTable').textContent);
  pyodide.globals.set('_COMPILER_DATA', pyodide.toPy(data));
  pyodide.globals.set('_CHAR_TABLE', pyodide.toPy(charTable));

  // Build char_to_hex from safe JSON list (avoids Unicode literal parse errors)
  await pyodide.runPythonAsync(`
import sys, io

# ── char_to_hex loaded from JSON dict {codepoint: hexval} ─────────────
char_to_hex = {chr(int(cp)): hx for cp, hx in _CHAR_TABLE.items()}
print("char_to_hex loaded:", len(char_to_hex), "chars")
`);

  // Install core compiler (stripped version, no file I/O)
  await pyodide.runPythonAsync(`
import re, sys
from functools import lru_cache

max_call_adr = 0x3ffff

# ── font / npress (not needed for compile logic, stubs) ──
font = [' ']*256
font_assoc = {}
npress = [1]*256

def set_font(f): pass
def set_npress_array(n): pass
def to_font(c): return ''
def set_symbolrepr(s): pass

@lru_cache(maxsize=256)
def byte_to_key(byte):
    if byte == 0: return '<NUL>'
    return f'<{byte:02x}>'

def get_npress(charcodes):
    if isinstance(charcodes, int): charcodes = (charcodes,)
    return sum(npress[c] for c in charcodes)

def get_npress_adr(adrs):
    if isinstance(adrs, int): adrs = (adrs,)
    return sum(get_npress((a & 0xFF, (a >> 8) & 0xFF)) for a in adrs)

def optimize_adr_for_npress(adr):
    return min((adr, adr ^ 1), key=get_npress_adr)

def note(st):
    global _note_log
    _note_log += st

def to_lowercase(s): return s.lower()

def canonicalize(st):
    st = st.strip()
    st = re.sub(r' *([^a-z0-9]) *', r'\\1', st)
    return st

def del_inline_comment(line):
    return (line + '#')[:line.find('#')].rstrip()

# ── Load pre-computed commands & datalabels ──────────────
_data = _COMPILER_DATA
commands    = {k: (v['addr'], tuple(v['tags'])) for k,v in _data['commands'].items()}
datalabels  = dict(_data['datalabels'])

def sizeof_register(reg_name):
    return {'r':1,'e':2,'x':4,'q':8}[reg_name[0]]

# ── State (reset before each compile) ────────────────────
result = []
labels = {}
adr_of_cmds = []
adr_arith_cmds = []
pr_length_cmds = []
home = None
in_comment = False
string_vars = {}
_note_log = ''

def reset_state():
    global result, labels, adr_of_cmds, adr_arith_cmds, pr_length_cmds, home, in_comment, string_vars, _note_log
    result=[]; labels={}; adr_of_cmds=[]; adr_arith_cmds=[]; pr_length_cmds=[]
    home=None; in_comment=False; string_vars={}; _note_log=''

def process(line):
    global result, labels, adr_of_cmds, adr_arith_cmds, pr_length_cmds, home, string_vars, in_comment

    if not line or line.isspace(): return

    if line.startswith('/*'): in_comment=True; return
    if '*/' in line: in_comment=False; return
    if in_comment: return

    if ';' in line:
        for cmd in line.split(';'): process(to_lowercase(cmd))
        return

    if line.strip() and line.strip()[-1] == ':':
        label = to_lowercase(line[:-1])
        assert label not in labels, f'Duplicated label: {label}'
        labels[label] = len(result)
        return

    if line.startswith('0x'):
        if '+' in line:
            hp, dp = line.split('+')
            rv = int(hp,16)+int(dp)
            nb = len(hp)//2-1
            for _ in range(nb): result.append(rv&0xFF); rv>>=8
        elif '-' in line:
            hp, dp = line.split('-')
            rv = int(hp,16)-int(dp)
            nb = len(hp)//2-1
            for _ in range(nb): result.append(rv&0xFF); rv>>=8
        else:
            assert len(line)%2==0,'Invalid data length'
            nb = len(line)//2-1
            data = int(line,16)
            for _ in range(nb): result.append(data&0xFF); data>>=8
        return

    if line.startswith('hex'):
        hexdata = line[3:].strip()
        if not hexdata: raise ValueError('Missing hex data after "hex"')
        hexdata = ''.join(hexdata.split())
        if not all(c in '0123456789abcdefABCDEF' for c in hexdata):
            raise ValueError(f'Invalid hex data: {hexdata}')
        if len(hexdata) % 2 != 0:
            raise ValueError('Hex data must have even number of digits')
        for i in range(0, len(hexdata), 2):
            result.append(int(hexdata[i:i+2], 16))
        return

    if line.startswith('call'):
        try: adr = int(line[4:],16)
        except ValueError:
            adr, tags = commands[line[4:].strip()]
            for tag in tags:
                if tag.startswith('warning'): note(tag+'\\n')
        assert 0<=adr<=max_call_adr
        adr = optimize_adr_for_npress(adr)
        process(f'0x{adr+0x30300000:08x}')
        return

    if line.startswith('goto'):
        label = to_lowercase(line[4:])
        process(f'er14=adr_of [-2] {label}')
        process('call sp=er14,pop er14')
        return

    if line.startswith('adr_of'):
        line2 = to_lowercase(line[6:].strip())
        if line2[0]=='[':
            i=line2.index(']')
            offset=int(line2[1:i],0)
            label=line2[i+1:].strip()
        else:
            offset=0; label=line2.strip()
        adr_of_cmds.append((len(result),offset,label))
        result.extend((0,0))
        return

    if line in datalabels:
        process(f'{line}+0'); return

    if '+' in line and line[:line.find('+')] in datalabels:
        label, offset = line.split('+')
        process(f'0x{datalabels[label]+int(offset,0):04x}'); return

    if line in commands:
        process('call '+to_lowercase(line)); return

    if line.startswith('pr_length'):
        pr_length_cmds.append(len(result))
        result.extend((0,0)); return

    if line.startswith('str'):
        content = line[3:].strip()
        def string_to_bytes(text):
            bl=[]
            for c in text:
                try:
                    hv = char_to_hex[c]
                    if len(hv)==2: bl.append(int(hv,16))
                    elif len(hv)==4: bl.extend([int(hv[:2],16),int(hv[2:],16)])
                except KeyError: raise ValueError(f"Char '{c}' not in table")
            return bl
        if '"' in content:
            qp=content.find('"')
            vn=content[:qp].strip() if qp>0 else None
            text=content[qp+1:].rstrip('"')
            if vn: string_vars[vn]=text
            else: result.extend(string_to_bytes(text))
        elif content:
            vn=content.strip()
            if vn in string_vars: result.extend(string_to_bytes(string_vars[vn]))
            else: raise ValueError(f'Undefined string var: {vn}')
        else: raise ValueError('Invalid str syntax')
        return

    if '=' in line:
        i=line.index('=')
        register, value = line[:i], line[i+1:].lstrip()
        assert '=' not in value
        # Split on commas but preserve 'adr_of [offset] label' as one unit
        def split_value(v):
            parts = []; buf = ''; toks = v.split(',')
            j = 0
            while j < len(toks):
                t = toks[j].strip()
                if not buf:
                    buf = t
                else:
                    buf = buf + ',' + t
                # adr_of is complete when: no [ at all, OR brackets balanced
                s = buf.strip()
                if s.startswith('adr_of'):
                    if '[' not in s or s.count('[') == s.count(']'):
                        parts.append(s); buf = ''
                else:
                    parts.append(s); buf = ''
                j += 1
            if buf: parts.append(buf.strip())
            return parts
        process(f'call pop {register}')
        l1=len(result)
        for p in split_value(value):
            process(p)
        assert len(result)-l1==sizeof_register(register), f'Size mismatch in: {line}'
        return

    if line.startswith('org'):
        global home
        hx=eval(line[3:])
        home1=hx-len(result)
        assert home is None or home==home1,'Inconsistent home'
        home=home1; return

    if line.startswith('adr_arith'):
        lmp=len(line)-1
        while lmp>0:
            if line[lmp]=='-' and 'adr_arith' in line[lmp:]: break
            lmp-=1
        if lmp<=0: raise ValueError(f'Invalid adr_arith: {line}')
        left_part=line[9:lmp].strip()
        right_part=line[lmp+1:].strip()
        def parse_part(part):
            part=part.strip()
            if part.startswith('adr_arith'): part=part[9:].strip()
            offset=0
            if '[' in part and ']' in part:
                si=part.index('['); ei=part.index(']')
                offset=int(part[si+1:ei],0)
                label=part[ei+1:].strip()
            else: label=part.strip()
            return offset, label
        lo,ll=parse_part(left_part)
        ro,rl=parse_part(right_part)
        adr_arith_cmds.append((len(result),lo,ll,ro,rl))
        result.append(0); return

    if line.startswith('$'):
        x=eval(line[1:])
        if isinstance(x,str): process(x)
        elif isinstance(x,(list,tuple)):
            for c in x: process(c)
        return

    if line.startswith('setup_loop'):
        parts=line.split(',')
        if len(parts)==2: src=parts[0].split()[1].strip(); sb=parts[1].strip(); lbl='home'
        elif len(parts)==3: src=parts[0].split()[1].strip(); sb=parts[1].strip(); lbl=parts[2].strip() if parts[2].strip()!='None' else 'home'
        else: raise ValueError(f'Invalid setup_loop: {line}')
        code=f"""restore:
    setlr
    DI,RT
    xr0=adr_of length,0x01,0x00
    [er0]=er2,rt
    qr0=pr_length,{sb},{src},0x0000
    0x8932
length:
    0x0800
    0x0000
set_sp:
    er6=adr_of [-2] {lbl}
    sp=er6,pop er8"""
        for cl in code.strip().split('\\n'): process(canonicalize(del_inline_comment(cl)).lower())
        return

    assert False, f'Unrecognized: {line!r}'

def finish_processing():
    global result
    for pos,ll,left_lbl,rl,right_lbl in adr_arith_cmds:
        la=labels[left_lbl]+ll; ra=labels[right_lbl]+rl
        result[pos]=(la-ra)&0xFF
    for pos in pr_length_cmds:
        pl=len(result)
        result[pos]=pl&0xFF; result[pos+1]=(pl>>8)&0xFF

def compile_program(source_text, fmt='hex'):
    reset_state()
    program=[canonicalize(del_inline_comment(l)) for l in source_text.split('\\n')]
    for line in program:
        if not line.lower().startswith('str'):
            line=to_lowercase(line)
        try: process(line)
        except Exception as e:
            raise RuntimeError(f'Error on line {repr(line)}: {e}') from e
    finish_processing()
    adr_resolved=[(sa, labels[tl]+off) for sa,off,tl in adr_of_cmds]
    overflow_sp=0xE9E0
    global home
    if home is None:
        home=overflow_sp
        if 'home' in labels: home-=labels['home']
    for sa,ho in adr_resolved:
        ta=home+ho
        result[sa]=ta&0xFF; result[sa+1]=ta>>8

    # Build label info string
    label_lines = []
    for lbl, off in sorted(labels.items(), key=lambda x: x[1]):
        label_lines.append(f'{lbl}: 0x{home+off:04X}')

    if fmt=='hex':
        output = f'0x{home:04x}: ' + ' '.join(f'{b:02x}' for b in result)
    else:
        output = f'0x{home:04x}: ' + ' '.join(byte_to_key(b) for b in result)

    return output, '\\n'.join(label_lines), len(result)

print("Compiler ready! Commands:", len(commands), "| Data labels:", len(datalabels))
`);

  loaderBar.style.width = '100%';
  await new Promise(r => setTimeout(r, 300));

  document.getElementById('pyLoadLabel').textContent = '✓ compiler ready';
  document.getElementById('pyLoadBar').style.display = 'none';
  compileBtn.disabled = false;
  setStatus('> compiler ready_');
}

loadPyodide_().catch(e => {
  document.getElementById('pyLoadLabel').textContent = '❌ python failed — compiler unavailable';
  document.getElementById('pyLoadLabel').style.color = 'var(--red)';
  document.getElementById('pyLoadBar').style.display = 'none';
  setStatus('❌ compiler unavailable', true);
});

// ═══════════════════════════════════════════════════
// COMPILE
// ═══════════════════════════════════════════════════
async function doCompile(fmt) {
  if (!pyodide) { setStatus('⏳ Python not ready', true); return; }
  const src = asmInput.value.trim();
  if (!src) { setStatus('⚠️ No source code', true); return; }

  compileBtn.disabled = true;
  setStatus('⏳ Compiling…');
  setOutput('<span class="tok-note">// Compiling…</span>');

  try {
    const t0 = performance.now();
    pyodide.globals.set('_src', src);
    pyodide.globals.set('_fmt', fmt);
    const res = await pyodide.runPythonAsync('compile_program(_src, _fmt)');
    const arr = res.toJs ? res.toJs() : res;
    const [out, labelInfo, byteCount] = arr;
    const dt = ((performance.now() - t0) / 1000).toFixed(3);

    const colonIdx = out.indexOf(':');
    const addr = out.slice(0, colonIdx);
    const bytes = out.slice(colonIdx + 1).trim();
    const byteArr = bytes.split(' ');

    let labelHtml = '';
    if (labelInfo) {
      const lines = labelInfo.split('\n').map(l => {
        const [name, adr] = l.split(': ');
        return `<span class="tok-note">; ${escHtml(name)}: <span class="tok-addr">${adr}</span></span>`;
      });
      labelHtml = '\n\n' + lines.join('\n');
    }

    lastHexResult = out;
    const colored = byteArr.map(b => `<span class="tok-hex">${b}</span>`).join(' ');
    setOutput(`<span class="tok-addr">${addr}:</span>\n${colored}${labelHtml}`);

    statsMsg.textContent = `bytes: ${byteCount} | time: ${dt}s`;
    setStatus(`> compiled ${byteCount} bytes_`);
  } catch(e) {
    const msg = e.message || String(e);
    setOutput(`<span class="tok-err">// Compile error:\n${escHtml(msg)}</span>`);
    setStatus('❌ compile error', true);
    statsMsg.textContent = '';
  } finally {
    compileBtn.disabled = false;
  }
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

compileBtn.onclick = () => doCompile('hex');

// Ctrl+Enter to compile
asmInput.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); doCompile('hex'); }
});

clearBtn.onclick = () => {
  asmInput.value = '';
  setOutput('<span class="tok-note">// ready — press [ COMPILE ] or ctrl+enter</span>');
  statsMsg.textContent = '';
  lastHexResult = '';
  setStatus('> cleared_');
};

copyHexBtn.onclick = async () => {
  const txt = lastHexResult || outputBox.innerText;
  if (!txt || txt.includes('// ')) { setStatus('⚠ nothing to copy', true); return; }
  await navigator.clipboard.writeText(txt).then(() => setStatus('> hex copied_')).catch(() => setStatus('❌ copy failed', true));
};

pasteBtn.onclick = async () => {
  try {
    const t = await navigator.clipboard.readText();
    asmInput.value = t;
    setStatus('📌 Pasted');
  } catch { setStatus('⚠️ Clipboard read failed', true); }
};

// Example buttons
document.querySelectorAll('.ex-btn').forEach(btn => {
  btn.onclick = () => {
    const key = btn.dataset.example;
    asmInput.value = EXAMPLES[key] || '';
    setOutput('<span class="tok-note">// Press COMPILE or Ctrl+Enter</span>');
    statsMsg.textContent = '';
    setStatus('> example loaded_');
  };
});

// ═══════════════════════════════════════════════════
// TAB SWITCHING
// ═══════════════════════════════════════════════════
document.getElementById('tabCompile').onclick = () => {
  document.getElementById('tabCompile').classList.add('active');
  document.getElementById('tabDecomp').classList.remove('active');
  document.getElementById('sectionCompile').style.display = '';
  document.getElementById('sectionDecomp').style.display = 'none';
};
document.getElementById('tabDecomp').onclick = () => {
  document.getElementById('tabDecomp').classList.add('active');
  document.getElementById('tabCompile').classList.remove('active');
  document.getElementById('sectionDecomp').style.display = '';
  document.getElementById('sectionCompile').style.display = 'none';
};

// ═══════════════════════════════════════════════════
// DECOMPILER ENGINE
// ═══════════════════════════════════════════════════
(function() {
// Build addrToName from compilerData (same source as compiler)
const addrToName = new Map();
(function(){
    const cd = JSON.parse(document.getElementById('compilerData').textContent);
    for (const [name, v] of Object.entries(cd.commands)) {
        const addr = v.addr;
        if (!addrToName.has(addr)) addrToName.set(addr, name);
        // also map addr^1 (odd variant) to same name
        if (!addrToName.has(addr^1)) addrToName.set(addr^1, name);
    }
})();


const specialNoPopGadgets=new Set(["sp=er14,pop er14,rt","sp=er14,pop qr8","sp=er14,pop qr8,pop qr0",
    "sp=er14,pop er14","sp=er6,pop er8","sp=er14,pop xr12","sp=er14,pop qr8,pop er6",
    "sp+=6,pop qr8","sp+=50,pop qr8","sp+=20,pop qr8","sp+=30,pop qr8","sp+=30,pop er14",
    "sp+=2,r0=0","sp+=20,pop xr12","sp+=10,pop er12","sp+=60,pop xr8","sp+=4,pop xr8",
    "sp+=64,pop er6,pop qr8","sp+=4,pop qr8,pop xr4","sp+=40,pop qr8,pop xr4",
    "sp+=60,pop qr8,pop xr4","sp+=50,pop qr8,pop xr4","sp+=50,pop xr4,pop qr8",
    "sp+=120,pop qr8,pop xr4","sp+=2,pop xr4,pop qr8","sp+=120,pop xr8",
    "sp+=2,r0=1,pop er8","sp+=32,r2=r0,pop xr8"]);

function getPopSizes(name) {
    if (!name) return null;
    let pops=[],regex=/pop\s+([^,]+(?:,[^,]+)*)/gi,match;
    while ((match=regex.exec(name))!==null) {
        for (let t of match[1].split(',')) {
            t=t.trim();
            if (!t||t==='rt'||t==='pop'||t==='sp') continue;
            if (t==='ea'||t==='pc') pops.push(2);
            else if (t==='psw') pops.push(1);
            else if (t.startsWith('qr')) for(let i=0;i<4;i++) pops.push(2);
            else if (t.startsWith('xr')) for(let i=0;i<2;i++) pops.push(2);
            else if (t.startsWith('er')) pops.push(2);
            else if (t.startsWith('r')) pops.push(1);
        }
    }
    return pops.length?pops:null;
}
const MIN_VALID_CALL_ADDR=0x8000;
function normalizeAddress(addr) {
    if (addr===0x09c21) return 0x09c20;
    if (addr===0x0947e) return 0x0947c;
    if ((addr&1)&&addrToName.has(addr-1)) return addr-1;
    return addr;
}
function hexToBytes(hexStr) {
    let clean=hexStr.replace(/\s+/g,'');
    if (!clean) return [];
    if (clean.length%2) clean=clean.slice(0,-1);
    let bytes=[];
    for (let i=0;i<clean.length;i+=2) bytes.push(parseInt(clean.substr(i,2),16));
    return bytes;
}
const keyMap=new Map([[0x0180,"SHIFT"],[0x0280,"ALPHA"],[0x0440,"←"],[0x0880,"→"],[0x0480,"↑"],[0x0840,"↓"],
    [0x1080,"MENU"],[0x0140,"OTPN"],[0x0240,"CALC"],[0x1040,"∫"],[0x0120,"⁄"],[0x0220,"√"],
    [0x0420,"x²"],[0x0820,"xˆ"],[0x1020,"log"],[0x2020,"IN"],[0x0110,"(-)"],[0x0210,"ĐỘ"],
    [0x0410,"x^-1"],[0x0810,"SIN"],[0x1010,"COS"],[0x2010,"TAN"],[0x0108,"STO"],[0x0208,"ENG"],
    [0x0408,"("],[0x0808,")"],[0x1008,"S<=>D"],[0x2008,"M+"],[0x1004,"AC"],[0x1002,"÷"],[0x1001,"-"],
    [0x4004,"x10"],[0x4001,"="],[0x4010,"0"],[0x0101,"1"],[0x0201,"2"],[0x0401,"3"],[0x0102,"4"],
    [0x0202,"5"],[0x0402,"6"],[0x0104,"7"],[0x0204,"8"],[0x0404,"9"],[0x0804,"DEL"],
    [0x0802,"×"],[0x0801,"+"],[0x4008,"."],[0x4002,"ANS"]]);
const addrNameMap=new Map([[0x83DA,"adrcvtkey"],[0xD000,"reg0"],[0xD009,"reg0.9"],
    [0xD110,"modifiers"],[0xD111,"mode"],[0xD112,"submode"],[0xD11A,"num_format"],
    [0xD11B,"num_format_i"],[0xD11D,"angle_unit"],[0xD138,"draw_mode"],[0xD180,"input_range"],
    [0xD318,"unstable_char"],[0xD31A,"var_m"],[0xD324,"var_ans"],[0xD32E,"var_a"],[0xD338,"var_b"],
    [0xD342,"var_c"],[0xD34C,"var_d"],[0xD356,"var_e"],[0xD360,"var_f"],[0xD36A,"var_x"],
    [0xD374,"var_y"],[0xD37E,"var_preans"],[0xD388,"var_z"],[0xD392,"calc_history"],
    [0xD139,"current_screen_buffer"],[0xDDD4,"screen_buffer"],[0xD137,"font_size"],
    [0xD113,"cursor_noflash"],[0xDBD0,"magic_string"]]);

function parseToItems(bytes,startAddrDest,startAddrSrc) {
    let items=[],offset=0,i=0;
    while (i<bytes.length) {
        let ramAddrDest=startAddrDest+offset,ramAddrSrc=startAddrSrc+offset;
        if (i+3<bytes.length) {
            let zz=bytes[i],yy=bytes[i+1],third=bytes[i+2],fourth=bytes[i+3];
            if (third>=0x30&&third<=0x39&&fourth===0x30) {
                let X=third-0x30,rawAddr=(X<<16)|(yy<<8)|zz;
                if (rawAddr===0x03030){items.push({type:'data',hexBytes:[zz,yy],value:(yy<<8)|zz,ramAddrDest,ramAddrSrc});i+=2;offset+=2;continue;}
                if (rawAddr<MIN_VALID_CALL_ADDR){
                    items.push({type:'data',hexBytes:[zz,yy],value:(yy<<8)|zz,ramAddrDest,ramAddrSrc});offset+=2;
                    items.push({type:'data',hexBytes:[third,fourth],value:(fourth<<8)|third,ramAddrDest:startAddrDest+offset,ramAddrSrc:startAddrSrc+offset});
                    i+=4;offset+=2;continue;
                }
                let fa=normalizeAddress(rawAddr),nm=addrToName.get(fa);
                items.push({type:'call',hexBytes:[zz,yy,third,fourth],addr:fa,name:nm||null,ramAddrDest,ramAddrSrc});
                i+=4;offset+=4;
                if (nm&&!specialNoPopGadgets.has(nm)){
                    let ps=getPopSizes(nm);
                    if (ps&&ps.length>0){
                        let tot=ps.reduce((a,b)=>a+b,0);
                        if (i+tot<=bytes.length){
                            for (let sz of ps){
                                let db=bytes.slice(i,i+sz),val=0;
                                for (let j=0;j<sz;j++) val|=(db[j]<<(8*j));
                                items.push({type:'data',hexBytes:db,value:val,ramAddrDest:startAddrDest+offset,ramAddrSrc:startAddrSrc+offset});
                                i+=sz;offset+=sz;
                            }
                            continue;
                        }
                    }
                }
                continue;
            }
        }
        if (i+1<bytes.length){
            items.push({type:'data',hexBytes:[bytes[i],bytes[i+1]],value:(bytes[i+1]<<8)|bytes[i],ramAddrDest,ramAddrSrc});
            i+=2;offset+=2;
        } else {
            items.push({type:'data',hexBytes:[bytes[i]],value:bytes[i],ramAddrDest,ramAddrSrc});
            i++;offset++;
        }
    }
    return items;
}
function resequenceLabels(items){
    let map=new Map(),c=1;
    for (let it of items) if (it.type==='label'&&!map.has(it.label)) map.set(it.label,`label${c++}`);
    for (let it of items){
        if (it.type==='label') it.label=map.get(it.label)||it.label;
        if (it.type==='data'&&it.labelRef) it.labelRef.label=map.get(it.labelRef.label)||it.labelRef.label;
    }
    return items;
}
function addLabelReferences(items,sDest,sSrc){
    let ai=new Map();
    for (let idx=0;idx<items.length;idx++){ai.set(items[idx].ramAddrDest,idx);ai.set(items[idx].ramAddrSrc,idx);}
    let lc=1,lmap=new Map();
    for (let it of items){
        if (it.type==='data'&&it.hexBytes.length===2&&ai.has(it.value)){
            let ti=ai.get(it.value),tit=items[ti];
            let isSrc=tit.ramAddrSrc===it.value?true:tit.ramAddrDest===it.value?false:null;
            if (isSrc===null) continue;
            if (!lmap.has(it.value)) lmap.set(it.value,`label${lc++}`);
            it.labelRef={label:lmap.get(it.value),isSrc,originalValue:it.value};
        }
    }
    let li=[];
    for (let [addr,ln] of lmap.entries()){let ti=ai.get(addr);if(ti!==undefined)li.push({type:'label',label:ln,insertBefore:ti,addr});}
    li.sort((a,b)=>b.insertBefore-a.insertBefore);
    for (let l of li) items.splice(l.insertBefore,0,{type:'label',label:l.label,addr:l.addr});
    let merged=false;
    do {
        merged=false;
        for (let i=0;i<items.length-1;i++){
            if (items[i].type==='label'&&items[i+1].type==='label'){
                let keep=items[i].label,rem=items[i+1].label;
                items.splice(i+1,1);
                for (let it of items) if (it.type==='data'&&it.labelRef&&it.labelRef.label===rem) it.labelRef.label=keep;
                merged=true;break;
            }
        }
    } while (merged);
    return items;
}
function getDataDisplay(it){
    if (it.labelRef){const r=it.labelRef;return r.isSrc?`adr_of [+4784] ${r.label}`:`adr_of ${r.label}`;}
    let v=it.hexBytes.length===2?`0x${it.value.toString(16).toUpperCase().padStart(4,'0')}`:`0x${it.value.toString(16).toUpperCase().padStart(2,'0')}`;
    if (it.hexBytes.length===2&&keyMap.has(it.value)) v+=` # [${keyMap.get(it.value)}]`;
    if (it.hexBytes.length===2&&addrNameMap.has(it.value)) v+=` # ${addrNameMap.get(it.value)}`;
    return v;
}
function fmtA(n){return '0x'+n.toString(16).toLowerCase();}
function renderItems(items,container){
    container.innerHTML='';
    const frag=document.createDocumentFragment();
    for (let it of items){
        const d=document.createElement('div');d.className='gadget-line';
        if (it.type==='label'){
            d.style.paddingLeft='0';
            const s=document.createElement('span');s.className='d-label';s.textContent=`${it.label}:`;d.appendChild(s);
            const loc=document.createElement('span');loc.className='d-loc';loc.textContent=fmtA(it.addr);d.appendChild(loc);
        } else {
            d.style.paddingLeft='14px';
            const badge=document.createElement('span');badge.className='hex-badge';
            badge.textContent=it.hexBytes.map(b=>b.toString(16).padStart(2,'0')).join(' ');d.appendChild(badge);
            const arr=document.createElement('span');arr.className='d-arrow';arr.textContent='➜';d.appendChild(arr);
            if (it.type==='call'){
                const as=it.addr.toString(16).toUpperCase().padStart(5,'0');
                const a=document.createElement('span');a.className='d-addr';a.textContent=as;d.appendChild(a);
                const ns=document.createElement('span');
                if (it.name){ns.className='d-name';ns.textContent=`→ ${it.name}`;}
                else{ns.className='d-unk';ns.textContent=`→ call ${as}`;}
                d.appendChild(ns);
            } else {
                const ds=document.createElement('span');ds.className='d-data';ds.textContent=`→ ${getDataDisplay(it)}`;d.appendChild(ds);
            }
            const loc=document.createElement('span');loc.className='d-loc';
            loc.textContent=`${fmtA(it.ramAddrDest)} ${fmtA(it.ramAddrSrc)}`;d.appendChild(loc);
        }
        frag.appendChild(d);
    }
    container.appendChild(frag);
}

const hexInput=document.getElementById('hexInput');
const decompOut=document.getElementById('decompOutput');
const dStatus=document.getElementById('dStatusMsg');
const dStats=document.getElementById('dStatsMsg');
const decompBtn=document.getElementById('decompBtn');
const dClearBtn=document.getElementById('dClearBtn');
const dCopyBtn=document.getElementById('dCopyBtn');
const dPasteBtn=document.getElementById('dPasteBtn');
const startAddrIn=document.getElementById('startAddrInput');
const backupAddrIn=document.getElementById('backupAddrInput');
const dModeDetail=document.getElementById('dModeDetail');
const dModeSimple=document.getElementById('dModeSimple');
let dItems=[],dByteCount=0,dMode='detail';

function dSetStatus(t,err=false){dStatus.textContent=t;dStatus.style.color=err?'var(--red)':'var(--dim)';}

function formatSimple(){
    return dItems.map(it=>{
        if (it.type==='label') return `${it.label}:`;
        if (it.type==='call') return `  ${it.name||'call '+it.addr.toString(16).toUpperCase().padStart(5,'0')}`;
        return `  ${getDataDisplay(it)}`;
    }).join('\n');
}

function refreshDecomp(){
    if (!dItems.length) return;
    if (dMode==='detail') renderItems(dItems,decompOut);
    else { decompOut.innerText=formatSimple(); }
}

dModeDetail.onclick=()=>{
    dMode='detail';
    dModeDetail.classList.add('active'); dModeSimple.classList.remove('active');
    refreshDecomp();
};
dModeSimple.onclick=()=>{
    dMode='simple';
    dModeSimple.classList.add('active'); dModeDetail.classList.remove('active');
    refreshDecomp();
};

decompBtn.onclick=()=>{
    const raw=hexInput.value.trim();
    if (!raw){dSetStatus('> no input_',true);return;}
    let dest=parseInt(startAddrIn.value.trim(),16),src=parseInt(backupAddrIn.value.trim(),16);
    if (isNaN(dest)) dest=0xd730;
    if (isNaN(src)) src=0xe9e0;
    dSetStatus('> decompiling…');
    setTimeout(()=>{
        try {
            let bytes=hexToBytes(raw);
            if (!bytes.length) throw new Error('Invalid hex');
            dByteCount=bytes.length;
            let items=parseToItems(bytes,dest,src);
            items=addLabelReferences(items,dest,src);
            items=resequenceLabels(items);
            dItems=items;
            refreshDecomp();
            dStats.textContent=`bytes: ${dByteCount} | items: ${items.length}`;
            dSetStatus(`> ok — ${items.length} items_`);
        } catch(e){
            decompOut.innerHTML=`<span style="color:var(--red)">// Error: ${e.message}</span>`;
            dSetStatus('> error_',true);dStats.textContent='';
        }
    },10);
};
dCopyBtn.onclick=()=>{
    const txt=formatSimple();
    if (!txt){dSetStatus('> nothing to copy_',true);return;}
    navigator.clipboard.writeText(txt).then(()=>dSetStatus('> copied_')).catch(()=>dSetStatus('> copy failed_',true));
};
dClearBtn.onclick=()=>{
    hexInput.value='';
    decompOut.innerHTML='<span class="tok-note">// paste hex and press [ DECOMPILE ]</span>';
    dItems=[];dByteCount=0;dStats.textContent='';dSetStatus('> cleared_');
};
dPasteBtn.onclick=async()=>{
    try{hexInput.value=await navigator.clipboard.readText();dSetStatus('> pasted_');}
    catch{dSetStatus('> clipboard error_',true);}
};
})();