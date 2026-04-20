'use strict';

// ═══════════════════════════════════════════════
// DECOMPILER PYTHON SOURCE — defined at top level
// so loadPyodide_ can run it before any data injection
// ═══════════════════════════════════════════════
const DECOMP_PY = `
import re

_addr_to_name = {}
_disas_label  = {}

def _get_name(addr):
    nm = _addr_to_name.get(addr) or _addr_to_name.get(addr ^ 1)
    if nm: return nm
    entry = _disas_label.get(addr) or _disas_label.get(addr ^ 1)
    if entry:
        return entry['label'].lower() if entry['known'] else None
    return None

SPECIAL_NO_POP = {
    "sp=er14,pop er14,rt","sp=er14,pop qr8","sp=er14,pop qr8,pop qr0",
    "sp=er14,pop er14","sp=er6,pop er8","sp=er14,pop xr12",
    "sp=er14,pop qr8,pop er6","sp+=6,pop qr8","sp+=50,pop qr8",
    "sp+=20,pop qr8","sp+=30,pop qr8","sp+=30,pop er14","sp+=2,r0=0",
    "sp+=20,pop xr12","sp+=10,pop er12","sp+=60,pop xr8","sp+=4,pop xr8",
    "sp+=64,pop er6,pop qr8","sp+=4,pop qr8,pop xr4","sp+=40,pop qr8,pop xr4",
    "sp+=60,pop qr8,pop xr4","sp+=50,pop qr8,pop xr4","sp+=50,pop xr4,pop qr8",
    "sp+=120,pop qr8,pop xr4","sp+=2,pop xr4,pop qr8","sp+=120,pop xr8",
    "sp+=2,r0=1,pop er8","sp+=32,r2=r0,pop xr8",
}
KEY_MAP = {
    0x0180:"SHIFT",0x0280:"ALPHA",0x0440:"←",0x0880:"→",0x0480:"↑",0x0840:"↓",
    0x1080:"MENU",0x0140:"OTPN",0x0240:"CALC",0x1040:"∫",0x0120:"⁄",0x0220:"√",
    0x0420:"x²",0x0820:"xˆ",0x1020:"log",0x2020:"IN",0x0110:"(-)",0x0210:"ĐỘ",
    0x0410:"x^-1",0x0810:"SIN",0x1010:"COS",0x2010:"TAN",0x0108:"STO",0x0208:"ENG",
    0x0408:"(",0x0808:")",0x1008:"S<=>D",0x2008:"M+",0x1004:"AC",0x1002:"÷",
    0x1001:"-",0x4004:"x10",0x4001:"=",0x4010:"0",0x0101:"1",0x0201:"2",
    0x0401:"3",0x0102:"4",0x0202:"5",0x0402:"6",0x0104:"7",0x0204:"8",
    0x0404:"9",0x0804:"DEL",0x0802:"×",0x0801:"+",0x4008:".",0x4002:"ANS",
}
ADDR_MAP = {
    0x83DA:"adrcvtkey",0xD000:"reg0",0xD009:"reg0.9",0xD110:"modifiers",
    0xD111:"mode",0xD112:"submode",0xD11A:"num_format",0xD11B:"num_format_i",
    0xD11D:"angle_unit",0xD138:"draw_mode",0xD180:"input_range",
    0xD318:"unstable_char",0xD31A:"var_m",0xD324:"var_ans",0xD32E:"var_a",
    0xD338:"var_b",0xD342:"var_c",0xD34C:"var_d",0xD356:"var_e",0xD360:"var_f",
    0xD36A:"var_x",0xD374:"var_y",0xD37E:"var_preans",0xD388:"var_z",
    0xD392:"calc_history",0xD139:"current_screen_buffer",0xDDD4:"screen_buffer",
    0xD137:"font_size",0xD113:"cursor_noflash",0xDBD0:"magic_string",
}
MIN_CALL = 0x8000

def hb(s):
    c = s.replace('0x','').replace(':','').replace(' ','').replace('\\n','').strip()
    if len(c) % 2: c = c[:-1]
    return [int(c[i:i+2], 16) for i in range(0, len(c), 2)]

def norm(a):
    if a == 0x09C21: return 0x09C20
    if a == 0x0947E: return 0x0947C
    if (a & 1) and (a - 1) in _addr_to_name: return a - 1
    return a

def popsz(name):
    if not name: return None
    pops = []
    for m in re.finditer(r'pop\\s+([^,]+(?:,[^,]+)*)', name):
        for t in m.group(1).split(','):
            t = t.strip()
            if not t or t in ('rt','pop','sp'): continue
            if t in ('ea','pc'):   pops.append(2)
            elif t == 'psw':       pops.append(1)
            elif t.startswith('qr'): pops.extend([2,2,2,2])
            elif t.startswith('xr'): pops.extend([2,2])
            elif t.startswith('er'): pops.append(2)
            elif t.startswith('r'):  pops.append(1)
    return pops if pops else None

def parse_items(bs, sd, ss):
    items = []; off = 0; i = 0
    while i < len(bs):
        rd = sd + off; rs = ss + off
        if i + 3 < len(bs):
            zz,yy,th,fo = bs[i],bs[i+1],bs[i+2],bs[i+3]
            if 0x30 <= th <= 0x39 and fo == 0x30:
                X = th - 0x30; ra = (X << 16) | (yy << 8) | zz
                if ra == 0x03030:
                    items.append({'t':'data','hb':[zz,yy],'v':(yy<<8)|zz,'rd':rd,'rs':rs})
                    i += 2; off += 2; continue
                if ra < MIN_CALL:
                    items.append({'t':'data','hb':[zz,yy],'v':(yy<<8)|zz,'rd':rd,'rs':rs})
                    off += 2
                    items.append({'t':'data','hb':[th,fo],'v':(fo<<8)|th,'rd':sd+off,'rs':ss+off})
                    i += 4; off += 2; continue
                fa = norm(ra); nm = _get_name(fa)
                items.append({'t':'call','hb':[zz,yy,th,fo],'addr':fa,'name':nm,'rd':rd,'rs':rs})
                i += 4; off += 4
                if nm and nm not in SPECIAL_NO_POP:
                    ps = popsz(nm)
                    if ps and i + sum(ps) <= len(bs):
                        for sz in ps:
                            db = bs[i:i+sz]
                            val = sum(db[j] << (8*j) for j in range(sz))
                            items.append({'t':'data','hb':db,'v':val,'rd':sd+off,'rs':ss+off})
                            i += sz; off += sz
                        continue
                continue
        if i + 1 < len(bs):
            items.append({'t':'data','hb':[bs[i],bs[i+1]],'v':(bs[i+1]<<8)|bs[i],'rd':rd,'rs':rs})
            i += 2; off += 2
        else:
            items.append({'t':'data','hb':[bs[i]],'v':bs[i],'rd':rd,'rs':rs})
            i += 1; off += 1
    return items

def add_labels(items, sd, ss):
    ai = {}
    for idx, it in enumerate(items):
        ai[it['rd']] = idx; ai[it['rs']] = idx
    lc = 1; lm = {}
    for it in items:
        if it['t'] == 'data' and len(it['hb']) == 2:
            val = it['v']
            if val in ai:
                ti = ai[val]; tit = items[ti]
                isSrc = tit['rs'] == val
                if not isSrc and tit['rd'] != val: continue
                if val not in lm: lm[val] = f'label{lc}'; lc += 1
                it['lr'] = {'l': lm[val], 's': isSrc}
    ins = sorted([{'l':ln,'ib':ai[a],'a':a} for a,ln in lm.items() if a in ai], key=lambda x: -x['ib'])
    for li in ins:
        items.insert(li['ib'], {'t':'label','l':li['l'],'a':li['a']})
    merged = True
    while merged:
        merged = False
        for i in range(len(items) - 1):
            if items[i]['t'] == 'label' and items[i+1]['t'] == 'label':
                keep = items[i]['l']; rem = items[i+1]['l']; items.pop(i+1)
                for it in items:
                    if it['t'] == 'data' and it.get('lr') and it['lr']['l'] == rem:
                        it['lr']['l'] = keep
                merged = True; break
    return items

def reseq(items):
    lm = {}; c = 1
    for it in items:
        if it['t'] == 'label' and it['l'] not in lm: lm[it['l']] = f'label{c}'; c += 1
    for it in items:
        if it['t'] == 'label': it['l'] = lm.get(it['l'], it['l'])
        if it['t'] == 'data' and it.get('lr'):
            it['lr']['l'] = lm.get(it['lr']['l'], it['lr']['l'])
    return items

def ddisplay(it):
    if it.get('lr'):
        r = it['lr']
        return f"adr_of [+4784] {r['l']}" if r['s'] else f"adr_of {r['l']}"
    val = it['v']; hl = len(it['hb'])
    v = f"0x{val:04X}" if hl == 2 else f"0x{val:02X}"
    if hl == 2 and val in KEY_MAP:  v += f"  # [{KEY_MAP[val]}]"
    if hl == 2 and val in ADDR_MAP: v += f"  # {ADDR_MAP[val]}"
    return v

def decomp(hex_in, sd, ss, mode):
    bs = hb(hex_in)
    if not bs: return 'ERROR: empty', 0, 0
    items = parse_items(bs, sd, ss)
    items = add_labels(items, sd, ss)
    items = reseq(items)
    lines = []
    if mode == 'detail':
        for it in items:
            if it['t'] == 'label':
                lines.append(f"LABEL|{it['l']}|{it['a']:x}")
            elif it['t'] == 'call':
                hx = ' '.join(f'{b:02x}' for b in it['hb'])
                nm = f"-> {it['name']}" if it['name'] else f"-> call {it['addr']:05X}"
                ok = 1 if it['name'] else 0
                lines.append(f"CALL|{hx}|{it['addr']:05X}|{nm}|{it['rd']:x}|{it['rs']:x}|{ok}")
            else:
                hx = ' '.join(f'{b:02x}' for b in it['hb'])
                lines.append(f"DATA|{hx}|{ddisplay(it)}|{it['rd']:x}|{it['rs']:x}")
    else:
        for it in items:
            if it['t'] == 'label':
                lines.append(f"{it['l']}:")
            elif it['t'] == 'call':
                lines.append(f"  {it['name'] or 'call ' + format(it['addr'], '05X')}")
            else:
                lines.append(f"  {ddisplay(it)}")
    return '\\n'.join(lines), len(bs), len(items)

print("Decomp ready")
`;

// ═══════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════
let pyodide      = null;
let dpReady      = false;
let lastHex      = '';
let dLastSimple  = '';
let dMode        = 'detail';

const EXAMPLES = {
  hello:     `org 0xe9e0

setlr
buffer_clear
xr0 = 0x1111, adr_of text
printline
render.ddd4
text:
hex 48 65 6c 6c 6f 20 35 38 30 56 4e 58
0x00`,
  waitshift: `org 0xe9e0

setlr
buffer_clear
waitshift
xr0 = 0x1111, adr_of msg
printline
render.ddd4
msg:
hex 50 72 65 73 73 20 53 48 49 46 54
0x00`,
  drawline:  `org 0xe9e0

setlr
xr0=0x0101,0x3131
line_draw
render.ddd4`,
  loop:      `org 0xe9e0

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
hex 4c 6f 6f 70 69 6e 67
0x00`,
};

// ═══════════════════════════════════════════════
// UI HELPERS
// ═══════════════════════════════════════════════
const $ = id => document.getElementById(id);
function setStatus(t, err=false) {
  $('statusMsg').textContent = t;
  $('statusMsg').style.color = err ? 'var(--red)' : 'var(--dim)';
}
function setOut(html) { $('outputBox').innerHTML = html; }
function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// ═══════════════════════════════════════════════
// PYODIDE BOOTSTRAP
// Sequence: load pyodide → run compiler Python → run DECOMP_PY → expose instance
// Only then does loadDataFiles() inject _addr_to_name / _disas_label
// ═══════════════════════════════════════════════
async function bootPyodide() {
  const lbl  = $('pyLabel');
  const bar  = $('pyBar');
  const fill = $('pyFill');
  const setL = t => { lbl.textContent = t; };
  const setF = w => { fill.style.width = w; };

  try {
    setL('⏳ fetching pyodide...');
    setF('10%');
    await new Promise((res, rej) => {
      if (window.loadPyodide) { res(); return; }
      const s = document.createElement('script');
      s.src = 'https://cdn.jsdelivr.net/pyodide/v0.26.2/full/pyodide.js';
      s.onload = res;
      s.onerror = () => rej(new Error('Failed to load pyodide.js'));
      document.head.appendChild(s);
    });

    setF('30%'); setL('⏳ initialising python...');
    bar.classList.remove('run');
    pyodide = await window.loadPyodide({
      indexURL: 'https://cdn.jsdelivr.net/pyodide/v0.26.2/full/'
    });

    setF('60%'); setL('⏳ setting up compiler...');
    const charTable = JSON.parse($('charTable').textContent);
    pyodide.globals.set('_CHAR_TABLE', pyodide.toPy(charTable));

    await pyodide.runPythonAsync(`
import re, sys
from functools import lru_cache

max_call_adr = 0x3ffff
npress = [1] * 256

def byte_to_key(b):
    return '<NUL>' if b == 0 else f'<{b:02x}>'

def get_npress_adr(adrs):
    if isinstance(adrs, int): adrs = (adrs,)
    return sum(npress[a & 0xFF] + npress[(a >> 8) & 0xFF] for a in adrs)

def optimize_adr(adr):
    return min((adr, adr ^ 1), key=get_npress_adr)

_note_log = ''
def note(st):
    global _note_log
    _note_log += st

def to_lc(s): return s.lower()

def canon(st):
    st = st.strip()
    st = re.sub(r' *([^a-z0-9]) *', r'\\1', st)
    return st

def del_comment(line):
    return (line + '#')[:line.find('#')].rstrip()

char_to_hex = {chr(int(cp)): hx for cp, hx in _CHAR_TABLE.items()}
commands   = {}
datalabels = {}

def sizeof_reg(r):
    return {'r':1,'e':2,'x':4,'q':8}[r[0]]

result=[]; labels={}; adr_of_cmds=[]; adr_arith_cmds=[]; pr_len_cmds=[]
home=None; in_comment=False

def reset_state():
    global result, labels, adr_of_cmds, adr_arith_cmds, pr_len_cmds, home, in_comment, _note_log
    result=[]; labels={}; adr_of_cmds=[]; adr_arith_cmds=[]; pr_len_cmds=[]
    home=None; in_comment=False; _note_log=''

def process(line):
    global result, labels, adr_of_cmds, adr_arith_cmds, pr_len_cmds, home, in_comment
    if not line or line.isspace(): return
    if line.startswith('/*'): in_comment=True; return
    if '*/' in line: in_comment=False; return
    if in_comment: return
    if ';' in line:
        for c in line.split(';'): process(to_lc(c))
        return
    if line.strip() and line.strip()[-1] == ':':
        lbl = to_lc(line[:-1])
        assert lbl not in labels, f'Duplicated label: {lbl}'
        labels[lbl] = len(result); return
    if line.startswith('0x'):
        if '+' in line:
            hp,dp = line.split('+'); rv = int(hp,16)+int(dp); nb = len(hp)//2-1
            for _ in range(nb): result.append(rv&0xFF); rv>>=8
        elif '-' in line:
            hp,dp = line.split('-'); rv = int(hp,16)-int(dp); nb = len(hp)//2-1
            for _ in range(nb): result.append(rv&0xFF); rv>>=8
        else:
            assert len(line)%2==0, f'Invalid data length: {line}'
            nb = len(line)//2-1; data = int(line,16)
            for _ in range(nb): result.append(data&0xFF); data>>=8
        return
    if line.startswith('hex'):
        hd = line[3:].strip()
        if not hd: raise ValueError('Missing hex data after "hex"')
        hd = ''.join(hd.split())
        if not all(c in '0123456789abcdefABCDEF' for c in hd):
            raise ValueError(f'Invalid hex: {hd}')
        if len(hd) % 2 != 0: raise ValueError('Hex must have even digits')
        for i in range(0, len(hd), 2): result.append(int(hd[i:i+2], 16))
        return
    if line.startswith('call'):
        rest = line[4:].strip()
        try: adr = int(rest, 16)
        except ValueError:
            # normalize key the same way as injection
            key = _re.sub(r'\s+', ' ', rest.strip().lower())
            key = _re.sub(r'^bl ', 'bl', key)
            entry = commands.get(key)
            if entry is None:
                # show closest keys for debugging
                close = [k for k in commands if k.startswith(key[:4])][:5]
                raise AssertionError(f'Unknown command: {repr(key)}'
                    + (f' — similar: {close}' if close else ''))
            adr, tags = entry
            for tag in tags:
                if tag.startswith('warning'): note(tag+'\\n')
        assert 0 <= adr <= max_call_adr, f'Address out of range: {adr:#x}'
        adr = optimize_adr(adr)
        process(f'0x{adr+0x30300000:08x}'); return
    if line.startswith('goto'):
        lbl = to_lc(line[4:].strip())
        process(f'er14=adr_of [-2] {lbl}')
        process('call sp=er14,pop er14'); return
    if line.startswith('adr_of'):
        l2 = to_lc(line[6:].strip())
        if l2[0] == '[':
            i = l2.index(']'); off = int(l2[1:i], 0); lbl = l2[i+1:].strip()
        else:
            off = 0; lbl = l2.strip()
        adr_of_cmds.append((len(result), off, lbl)); result.extend((0,0)); return
    if line in datalabels:
        process(f'{line}+0'); return
    if '+' in line and line[:line.find('+')] in datalabels:
        lbl, off = line.split('+')
        process(f'0x{datalabels[lbl]+int(off,0):04x}'); return
    if line in commands:
        process('call ' + line); return
    # try normalized key in case of whitespace/case mismatch
    _nline = _re.sub(r'^bl ', 'bl', _re.sub(r'\s+', ' ', line.strip()))
    if _nline != line and _nline in commands:
        process('call ' + _nline); return
    if line.startswith('pr_length'):
        pr_len_cmds.append(len(result)); result.extend((0,0)); return
    if line.startswith('str'):
        raise ValueError('str"..." not supported — use hex XX XX or 0xXXXX')
    if '=' in line:
        i = line.index('='); reg = line[:i]; val = line[i+1:].lstrip()
        assert '=' not in val
        def split_val(v):
            parts=[]; buf=''; toks=v.split(','); j=0
            while j < len(toks):
                t = toks[j].strip()
                buf = (buf+','+t) if buf else t
                s = buf.strip()
                if s.startswith('adr_of'):
                    if '[' not in s or s.count('[')==s.count(']'):
                        parts.append(s); buf=''
                else:
                    parts.append(s); buf=''
                j += 1
            if buf: parts.append(buf.strip())
            return parts
        process(f'call pop {reg}'); l1 = len(result)
        for p in split_val(val): process(p)
        assert len(result)-l1 == sizeof_reg(reg), f'Size mismatch: {line}'; return
    if line.startswith('org'):
        global home
        hx = eval(line[3:]); h1 = hx - len(result)
        assert home is None or home == h1, 'Inconsistent org'
        home = h1; return
    if line.startswith('adr_arith'):
        lmp = len(line)-1
        while lmp > 0:
            if line[lmp]=='-' and 'adr_arith' in line[lmp:]: break
            lmp -= 1
        if lmp <= 0: raise ValueError(f'Invalid adr_arith: {line}')
        def pp(part):
            part = part.strip()
            if part.startswith('adr_arith'): part = part[9:].strip()
            off = 0
            if '[' in part and ']' in part:
                si = part.index('['); ei = part.index(']')
                off = int(part[si+1:ei], 0); lbl = part[ei+1:].strip()
            else: lbl = part.strip()
            return off, lbl
        lo,ll = pp(line[9:lmp].strip()); ro,rl = pp(line[lmp+1:].strip())
        adr_arith_cmds.append((len(result),lo,ll,ro,rl)); result.append(0); return
    if line.startswith('$'):
        x = eval(line[1:])
        if isinstance(x, str): process(x)
        elif isinstance(x, (list,tuple)):
            for c in x: process(c)
        return
    if line.startswith('setup_loop'):
        parts = line.split(',')
        if len(parts)==2: src=parts[0].split()[1].strip(); sb=parts[1].strip(); lbl='home'
        elif len(parts)==3: src=parts[0].split()[1].strip(); sb=parts[1].strip(); lbl=parts[2].strip() if parts[2].strip()!='None' else 'home'
        else: raise ValueError(f'Invalid setup_loop: {line}')
        code = f"""restore:
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
        for cl in code.strip().split('\\n'): process(canon(del_comment(cl)).lower())
        return
    assert False, f'Unrecognized: {line!r}'

def finish():
    global result
    for pos,ll,lbl_l,rl,lbl_r in adr_arith_cmds:
        la = labels[lbl_l]+ll; ra = labels[lbl_r]+rl; result[pos] = (la-ra)&0xFF
    for pos in pr_len_cmds:
        pl = len(result); result[pos]=pl&0xFF; result[pos+1]=(pl>>8)&0xFF

def compile_program(src_text):
    reset_state()
    for line in src_text.split('\\n'):
        line = canon(del_comment(line)).lower()
        try: process(line)
        except Exception as e:
            raise RuntimeError(f'Error on line {repr(line)}: {e}') from e
    finish()
    adr_res = [(sa, labels[tl]+off) for sa,off,tl in adr_of_cmds]
    global home
    if home is None:
        home = 0xE9E0
        if 'home' in labels: home -= labels['home']
    for sa, ho in adr_res:
        ta = home+ho; result[sa]=ta&0xFF; result[sa+1]=ta>>8
    lbls = []
    for lbl,off in sorted(labels.items(), key=lambda x: x[1]):
        lbls.append(f'{lbl}: 0x{home+off:04X}')
    out = f'0x{home:04x}: ' + ' '.join(f'{b:02x}' for b in result)
    return out, '\\n'.join(lbls), len(result)

print("Compiler ready")
`);

    setF('85%'); setL('⏳ setting up decompiler...');
    // Run DECOMP_PY NOW — before exposing pyodide instance
    // loadDataFiles will inject _addr_to_name/_disas_label after this
    await pyodide.runPythonAsync(DECOMP_PY);
    dpReady = true;

    setF('100%');
    await new Promise(r => setTimeout(r, 150));
    setL('✓ python ready');
    bar.style.display = 'none';
    setStatus('> python ready — loading gadgets...');

  } catch(e) {
    lbl.textContent = '❌ python failed: ' + e.message;
    lbl.style.color = 'var(--red)';
    bar.style.display = 'none';
    setStatus('❌ compiler unavailable', true);
    console.error('bootPyodide error:', e);
    return;
  }

  // Expose after DECOMP_PY has run — loadDataFiles checks this
  window._pyReady = true;
  loadDataFiles();
}

bootPyodide();

// ═══════════════════════════════════════════════
// DATA FILE LOADER
// Fetches ./gadgets, ./labels, ./disas.txt
// Called automatically after pyodide boots
// ═══════════════════════════════════════════════
async function fetchText(path) {
  try {
    const r = await fetch(path, { headers: { 'Accept': 'text/plain, */*' } });
    return r.ok ? await r.text() : null;
  } catch { return null; }
}

function parseGadgets(text) {
  const out = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split('#')[0].trim();
    if (!line) continue;
    const parts = line.split(/\t+/);
    if (parts.length < 2) continue;
    const addr = parseInt(parts[0].trim(), 16);
    let name = parts.slice(1).join(' ').trim()
      .replace(/\s*=\s*/g,'=').replace(/\s*\+=\s*/g,'+=')
      .replace(/\s*-=\s*/g,'-=').replace(/\s*,\s*/g,',')
      .replace(/\s+/g,' ').toLowerCase();
    // "bl strcpy" -> "blstrcpy"
    name = name.replace(/^bl\s+/, 'bl');
    if (!isNaN(addr) && name) out[name] = { addr, tags: [] };
  }
  return out;
}

function parseLabels(text) {
  const commands = {}, datalabels = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split('#')[0].trim();
    if (!line || line.startsWith('.')) continue;
    const parts = line.split(/\t+/);
    if (parts.length < 2) continue;
    const key = parts[0].trim();
    const name = parts[1].trim();
    if (!name || name.startsWith('.')) continue;
    const dm = key.match(/^d_([0-9a-fA-F]+)$/i);
    if (dm) { datalabels[name] = parseInt(dm[1], 16); continue; }
    const am = key.match(/^([0-9a-fA-F]+)$/i);
    if (am) commands[name.toLowerCase()] = { addr: parseInt(am[1], 16), tags: [] };
  }
  return { commands, datalabels };
}

function parseDisas(text) {
  // Returns:
  //   addrToLabel: { addr -> labelName }  (first addr wins)
  //   labelToAddrs: { labelName -> [addr, ...] }
  const addrToLabel = {};
  const labelToAddrs = {};
  let curLabel = null;
  for (const raw of text.split(/\r?\n/)) {
    const lm = raw.match(/^([a-zA-Z_][a-zA-Z0-9_.]*):/);
    if (lm) {
      curLabel = lm[1];
      if (!labelToAddrs[curLabel]) labelToAddrs[curLabel] = [];
      continue;
    }
    if (!curLabel) continue;
    const am = raw.match(/;\s*([0-9A-Fa-f]{5})\s*\|/);
    if (am) {
      const addr = parseInt(am[1], 16);
      if (!(addr in addrToLabel)) addrToLabel[addr] = curLabel;
      labelToAddrs[curLabel].push(addr);
    }
  }
  return { addrToLabel, labelToAddrs };
}

async function loadDataFiles() {
  const [gadgetsTxt, labelsTxt, disasTxt] = await Promise.all([
    fetchText('./gadgets'),
    fetchText('./labels'),
    fetchText('./disas.txt'),
  ]);

  let commands = {}, datalabels = {};
  if (gadgetsTxt) Object.assign(commands, parseGadgets(gadgetsTxt));
  if (labelsTxt) {
    const r = parseLabels(labelsTxt);
    Object.assign(commands, r.commands);
    Object.assign(datalabels, r.datalabels);
  }

  // Always include setlr_pc
  commands['setlr_pc'] = { addr: 0x308D0, tags: [] };

  // Build disas map: addr -> { label, known }
  // Auto-rename: if a gadget's addr appears anywhere in a disas block,
  // rename that block's label to the gadget name so ALL addrs in that
  // block resolve to the gadget name (not just the exact entry point).
  let disasMap = {};
  if (disasTxt) {
    const { addrToLabel, labelToAddrs } = parseDisas(disasTxt);

    // Build reverse: disas labelName -> gadget name (if any gadget addr hits this block)
    // addrToGadgetName: disas addr -> gadget name
    const addrToGadget = {};
    for (const [gName, gData] of Object.entries(commands)) {
      const gAddr = gData.addr;
      // Check exact addr and addr^1
      for (const probe of [gAddr, gAddr ^ 1]) {
        const disasLabel = addrToLabel[probe];
        if (disasLabel) {
          // This gadget's addr is inside disas block `disasLabel`
          // Map ALL addrs of that block -> gadget name
          for (const a of (labelToAddrs[disasLabel] || [])) {
            if (!(a in addrToGadget)) addrToGadget[a] = gName;
          }
          break;
        }
      }
    }

    // Build final disasMap: addr -> { label, known }
    for (const [addrStr, disasLabel] of Object.entries(addrToLabel)) {
      const addr = parseInt(addrStr);
      const gadgetName = addrToGadget[addr];
      if (gadgetName) {
        // Gadget exists -> known, use gadget name
        disasMap[addrStr] = { label: gadgetName, known: true };
      } else {
        // No gadget covers this addr -> unknown, use disas label
        const known = disasLabel.toLowerCase() in commands;
        disasMap[addrStr] = { label: disasLabel, known };
      }
    }
  }

  // Save raw disas text for patching later
  window._rawDisasTxt = disasTxt || '';
  // Save rename map: old disas label -> new gadget name (only changed ones)
  window._disasRenameMap = {};
  if (disasTxt) {
    const { addrToLabel, labelToAddrs } = parseDisas(disasTxt);
    for (const [gName, gData] of Object.entries(commands)) {
      const gAddr = gData.addr;
      for (const probe of [gAddr, gAddr ^ 1]) {
        const disasLabel = addrToLabel[probe];
        if (disasLabel && disasLabel.toLowerCase() !== gName.toLowerCase()) {
          window._disasRenameMap[disasLabel] = gName;
          break;
        }
      }
    }
  }

  if (!gadgetsTxt && !labelsTxt) {
    setStatus('> ⚠ gadgets/labels not found — place files next to index.html', true);
    return;
  }

  const nCmd = Object.keys(commands).length;
  const nDl  = Object.keys(datalabels).length;
  const nDis = Object.keys(disasMap).length;

  // Inject into compiler
  pyodide.globals.set('_CMD_DATA', pyodide.toPy({ commands, datalabels }));
  await pyodide.runPythonAsync(`
import re as _re
_d = _CMD_DATA

def _norm_key(k):
    # Strip whitespace, lowercase, collapse internal spaces, normalize BL prefix
    k = k.strip().lower()
    k = _re.sub(r'\\s+', ' ', k)
    # collapse "bl xxx" -> "blxxx"  (matches parseGadgets JS logic)
    k = _re.sub(r'^bl ', 'bl', k)
    return k

commands   = {_norm_key(k): (v['addr'], tuple(v['tags'])) for k,v in _d['commands'].items()}
datalabels = dict(_d['datalabels'])
print(f"Commands: {len(commands)}, Datalabels: {len(datalabels)}")
`);
  $('compileBtn').disabled = false;

  // Inject into decompiler (DECOMP_PY already ran, so _addr_to_name/_disas_label exist)
  const cdJson = JSON.stringify({ commands, datalabels });
  pyodide.globals.set('_DECOMP_CD_JSON', cdJson);
  pyodide.globals.set('_DISAS_MAP_JS', pyodide.toPy(disasMap));
  await pyodide.runPythonAsync(`
import json as _j2
_cd = _j2.loads(_DECOMP_CD_JSON)
_addr_to_name = {}
for _n, _v in _cd['commands'].items():
    _a = _v['addr']
    if _a not in _addr_to_name:       _addr_to_name[_a]     = _n
    if (_a ^ 1) not in _addr_to_name: _addr_to_name[_a ^ 1] = _n

_disas_label = {}
for _k, _v in _DISAS_MAP_JS.items():
    try:
        _disas_label[int(_k)] = {'label': _v['label'], 'known': bool(_v['known'])}
    except Exception: pass

print(f"Decompiler: {len(_addr_to_name)} addr entries, {len(_disas_label)} disas entries")
`);

  setStatus(`> ${nCmd} gadgets | ${nDl} datalabels | ${nDis} disas_`);
}

// ═══════════════════════════════════════════════
// COMPILER
// ═══════════════════════════════════════════════
async function doCompile() {
  if (!pyodide) { setStatus('⏳ Python not ready', true); return; }
  const src = $('asmInput').value.trim();
  if (!src) { setStatus('⚠ no source code', true); return; }
  $('compileBtn').disabled = true;
  setStatus('⏳ compiling…');
  setOut('<span class="tok-note">// compiling…</span>');
  try {
    const t0 = performance.now();
    pyodide.globals.set('_src', src);
    const res = await pyodide.runPythonAsync("compile_program(_src)");
    const arr = res.toJs ? res.toJs() : res;
    const [out, lblInfo, byteCount] = arr;
    const dt = ((performance.now()-t0)/1000).toFixed(3);
    const ci = out.indexOf(':');
    const addr = out.slice(0, ci);
    const bytes = out.slice(ci+1).trim();
    let lblHtml = '';
    if (lblInfo) {
      lblHtml = '\n\n' + lblInfo.split('\n').map(l => {
        const [n, a] = l.split(': ');
        return `<span class="tok-label">; ${esc(n)}: <span class="tok-addr">${a}</span></span>`;
      }).join('\n');
    }
    lastHex = out;
    const colored = bytes.split(' ').map(b => `<span class="tok-hex">${b}</span>`).join(' ');
    setOut(`<span class="tok-addr">${addr}:</span>\n${colored}${lblHtml}`);
    $('statsMsg').textContent = `bytes: ${byteCount} | time: ${dt}s`;
    setStatus(`> compiled ${byteCount} bytes_`);
  } catch(e) {
    setOut(`<span class="tok-err">// Error:\n${esc(e.message||String(e))}</span>`);
    setStatus('❌ compile error', true);
    $('statsMsg').textContent = '';
  } finally {
    $('compileBtn').disabled = false;
  }
}

$('compileBtn').onclick = doCompile;

// ═══════════════════════════════════════════════
// PATCH DISAS + GITHUB COMMIT
// ═══════════════════════════════════════════════

// Build patched disas text from rename map
function buildPatchedDisas() {
  const raw = window._rawDisasTxt || '';
  const renameMap = window._disasRenameMap || {};
  if (!raw || !Object.keys(renameMap).length) return { patched: raw, changes: 0 };
  let patched = raw;
  for (const [oldName, newName] of Object.entries(renameMap)) {
    const esc2 = oldName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    patched = patched.replace(new RegExp(`^(${esc2}):`, 'gm'), `${newName}:`);
  }
  return { patched, changes: Object.keys(renameMap).length };
}

function patchDisas() {
  const raw = window._rawDisasTxt;
  if (!raw) { setStatus('> ⚠ disas.txt not loaded', true); return; }
  const { patched, changes } = buildPatchedDisas();
  if (changes === 0) { setStatus('> disas already up to date_'); return; }

  // Download
  const blob = new Blob([patched], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'disas.txt'; a.click();
  URL.revokeObjectURL(url);

  const list = Object.entries(window._disasRenameMap).map(([o,n])=>`${o}→${n}`).join(', ');
  setStatus(`> downloaded patched disas (${changes} renames: ${list})_`);

  // Show GitHub bar for easy commit
  $('ghBar').style.display = '';
}

// Load saved GitHub settings
(function() {
  const repo  = localStorage.getItem('gh_repo')  || '';
  const token = localStorage.getItem('gh_token') || '';
  if ($('ghRepo'))  $('ghRepo').value  = repo;
  if ($('ghToken')) $('ghToken').value = token;
  if (repo && token) $('ghCommitBtn').disabled = false;
})();

$('ghSaveBtn').onclick = () => {
  const repo  = $('ghRepo').value.trim();
  const token = $('ghToken').value.trim();
  if (!repo || !token) { $('ghStatus').textContent = '⚠ fill both fields'; return; }
  localStorage.setItem('gh_repo',  repo);
  localStorage.setItem('gh_token', token);
  $('ghCommitBtn').disabled = false;
  $('ghStatus').textContent = '✓ saved';
  $('ghStatus').style.color = 'var(--green)';
};

$('ghCommitBtn').onclick = async () => {
  const repo  = $('ghRepo').value.trim()  || localStorage.getItem('gh_repo')  || '';
  const token = $('ghToken').value.trim() || localStorage.getItem('gh_token') || '';
  if (!repo || !token) {
    $('ghStatus').textContent = '⚠ need owner/repo and token';
    $('ghStatus').style.color = 'var(--red)'; return;
  }

  const { patched, changes } = buildPatchedDisas();
  if (!patched) { $('ghStatus').textContent = '⚠ no disas loaded'; return; }

  $('ghCommitBtn').disabled = true;
  $('ghStatus').textContent = '⏳ committing...';
  $('ghStatus').style.color = 'var(--dim)';

  try {
    const apiBase = `https://api.github.com/repos/${repo}/contents/disas.txt`;
    const headers = {
      'Authorization': `token ${token}`,
      'Accept': 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
    };

    // Get current file SHA (needed for update)
    let sha = null;
    const getRes = await fetch(apiBase, { headers });
    if (getRes.ok) {
      const info = await getRes.json();
      sha = info.sha;
    } else if (getRes.status !== 404) {
      throw new Error(`GET failed: ${getRes.status} ${getRes.statusText}`);
    }

    // Encode content as base64
    const b64 = btoa(unescape(encodeURIComponent(patched)));
    const renames = Object.entries(window._disasRenameMap || {})
      .map(([o,n]) => `${o} → ${n}`).join(', ');
    const body = {
      message: `patch disas.txt: rename ${changes} label(s) [${renames}]`,
      content: b64,
      ...(sha ? { sha } : {}),
    };

    const putRes = await fetch(apiBase, {
      method: 'PUT',
      headers,
      body: JSON.stringify(body),
    });

    if (!putRes.ok) {
      const err = await putRes.json().catch(() => ({}));
      throw new Error(`${putRes.status}: ${err.message || putRes.statusText}`);
    }

    $('ghStatus').textContent = `✓ committed (${changes} renames)`;
    $('ghStatus').style.color = 'var(--green)';
    // Update cached disas so patch button reflects new state
    window._rawDisasTxt = patched;
    window._disasRenameMap = {};
    setStatus(`> disas.txt committed to ${repo}_`);
  } catch(e) {
    $('ghStatus').textContent = `❌ ${e.message}`;
    $('ghStatus').style.color = 'var(--red)';
  } finally {
    $('ghCommitBtn').disabled = false;
  }
};

$('patchDisasBtn').onclick = patchDisas;
$('asmInput').addEventListener('keydown', e => {
  if ((e.ctrlKey||e.metaKey) && e.key==='Enter') { e.preventDefault(); doCompile(); }
});
$('clearBtn').onclick = () => {
  $('asmInput').value = ''; lastHex = ''; $('statsMsg').textContent = '';
  setOut('<span class="tok-note">// ready — press [ COMPILE ] or ctrl+enter</span>');
  setStatus('> cleared_');
};
$('copyHexBtn').onclick = () => {
  const t = lastHex || $('outputBox').innerText;
  if (!t || t.includes('// ')) { setStatus('⚠ nothing to copy', true); return; }
  navigator.clipboard.writeText(t).then(()=>setStatus('> hex copied_')).catch(()=>setStatus('❌ copy failed',true));
};
$('pasteBtn').onclick = async () => {
  try { $('asmInput').value = await navigator.clipboard.readText(); setStatus('> pasted_'); }
  catch { setStatus('⚠ clipboard error', true); }
};
document.querySelectorAll('.ex-btn').forEach(btn => {
  btn.onclick = () => {
    $('asmInput').value = EXAMPLES[btn.dataset.ex] || '';
    setOut('<span class="tok-note">// press [ COMPILE ] or ctrl+enter</span>');
    $('statsMsg').textContent = ''; setStatus('> example loaded_');
  };
});

// ═══════════════════════════════════════════════
// TABS
// ═══════════════════════════════════════════════
$('tabCompile').onclick = () => {
  $('tabCompile').classList.add('active'); $('tabDecomp').classList.remove('active');
  $('sectionCompile').style.display = ''; $('sectionDecomp').style.display = 'none';
};
$('tabDecomp').onclick = () => {
  $('tabDecomp').classList.add('active'); $('tabCompile').classList.remove('active');
  $('sectionDecomp').style.display = ''; $('sectionCompile').style.display = 'none';
};

// ═══════════════════════════════════════════════
// DECOMPILER UI
// ═══════════════════════════════════════════════
function dSetSt(t, err=false) {
  $('dStatus').textContent = t;
  $('dStatus').style.color = err ? 'var(--red)' : 'var(--dim)';
}

function simpleToHtml(text) {
  return text.split('\n').map(l =>
    `<div style="white-space:pre">${esc(l)}</div>`
  ).join('');
}

function renderDetail(lines) {
  const frag = document.createDocumentFragment();
  for (const line of lines) {
    if (!line) continue;
    const p = line.split('|');
    const d = document.createElement('div'); d.className = 'gadget-line';
    if (p[0] === 'LABEL') {
      d.style.paddingLeft = '0';
      const s = document.createElement('span'); s.className='d-label';
      s.textContent = p[1]+':'; d.appendChild(s);
      const loc = document.createElement('span'); loc.className='d-loc';
      loc.textContent = '0x'+p[2]; d.appendChild(loc);
    } else if (p[0] === 'CALL') {
      d.style.paddingLeft = '14px';
      const badge = document.createElement('span'); badge.className='hex-badge';
      badge.textContent = p[1]; d.appendChild(badge);
      const arr = document.createElement('span'); arr.className='d-arrow';
      arr.textContent = '➜'; d.appendChild(arr);
      const as = document.createElement('span'); as.className='d-addr';
      as.textContent = p[2]; d.appendChild(as);
      const ns = document.createElement('span'); ns.className = p[6]==='1'?'d-name':'d-unk';
      ns.textContent = p[3]; d.appendChild(ns);
      const loc = document.createElement('span'); loc.className='d-loc';
      loc.textContent = '0x'+p[4]+' 0x'+p[5]; d.appendChild(loc);
    } else {
      d.style.paddingLeft = '14px';
      const badge = document.createElement('span'); badge.className='hex-badge';
      badge.textContent = p[1]; d.appendChild(badge);
      const arr = document.createElement('span'); arr.className='d-arrow';
      arr.textContent = '➜'; d.appendChild(arr);
      const ds = document.createElement('span'); ds.className='d-data';
      ds.textContent = '-> '+p[2]; d.appendChild(ds);
      const loc = document.createElement('span'); loc.className='d-loc';
      loc.textContent = '0x'+p[3]+' 0x'+p[4]; d.appendChild(loc);
    }
    frag.appendChild(d);
  }
  $('decompOut').innerHTML = '';
  $('decompOut').appendChild(frag);
}

async function runDecomp() {
  const raw = $('hexInput').value.trim();
  if (!raw) { dSetSt('> no input_', true); return; }
  if (!dpReady) { dSetSt('> python not ready_', true); return; }
  let dest = parseInt($('addrDest').value.trim(), 16);
  let src  = parseInt($('addrSrc').value.trim(), 16);
  if (isNaN(dest)) dest = 0xd730;
  if (isNaN(src))  src  = 0xe9e0;
  dSetSt('> decompiling…');
  try {
    pyodide.globals.set('_dh', raw);
    pyodide.globals.set('_dd', dest);
    pyodide.globals.set('_ds', src);
    const rD = await pyodide.runPythonAsync("decomp(_dh,_dd,_ds,'detail')");
    const rS = await pyodide.runPythonAsync("decomp(_dh,_dd,_ds,'simple')");
    const aD = rD.toJs ? rD.toJs() : rD;
    const aS = rS.toJs ? rS.toJs() : rS;
    const [detStr, bc, ic] = aD;
    const [simStr]         = aS;
    dLastSimple = simStr;
    if (dMode === 'detail') renderDetail(detStr.split('\n'));
    else $('decompOut').innerHTML = simpleToHtml(simStr);
    $('dStats').textContent = `bytes: ${bc} | items: ${ic}`;
    dSetSt(`> ok — ${ic} items_`);
  } catch(e) {
    $('decompOut').innerHTML = `<span style="color:var(--red)">// Error: ${esc(e.message||String(e))}</span>`;
    dSetSt('> error_', true); $('dStats').textContent = '';
  }
}

$('decompBtn').onclick = runDecomp;
$('dDetail').onclick = () => {
  dMode = 'detail';
  $('dDetail').classList.add('active'); $('dSimple').classList.remove('active');
  if (dLastSimple) runDecomp();
};
$('dSimple').onclick = () => {
  dMode = 'simple';
  $('dSimple').classList.add('active'); $('dDetail').classList.remove('active');
  if (dLastSimple) $('decompOut').innerHTML = simpleToHtml(dLastSimple);
};
$('dClearBtn').onclick = () => {
  $('hexInput').value = '';
  $('decompOut').innerHTML = '<span class="tok-note">// paste hex and press [ DECOMPILE ]</span>';
  dLastSimple = ''; $('dStats').textContent = ''; dSetSt('> cleared_');
};
$('dCopyBtn').onclick = () => {
  if (!dLastSimple) { dSetSt('> nothing to copy_', true); return; }
  navigator.clipboard.writeText(dLastSimple)
    .then(() => dSetSt('> copied_'))
    .catch(() => dSetSt('> copy failed_', true));
};
$('dPasteBtn').onclick = async () => {
  try { $('hexInput').value = await navigator.clipboard.readText(); dSetSt('> pasted_'); }
  catch { dSetSt('> clipboard error_', true); }
};
