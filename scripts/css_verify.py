#!/usr/bin/env python3
"""css_verify.py — verifie qu'une refonte CSS ne change rien au rendu.

Compare deux feuilles CSS et vérifie que, pour chaque couple
(element, propriete), la valeur gagnante de la cascade est identique dans
les deux. Le modele reproduit la cascade reelle a une largeur de viewport
donnee :

    gagnant = max( rang_de_couche, specificite, ordre_dans_la_source )
    parmi les regles ACTIVES (media query satisfaite, hors :hover/... )

Les elements testes sont extraits du vrai balisage (templates Askama, conditions
{% if %} developpees) plus un petit jeu injecte par le JS / fabrique cote Rust.

LIMITES :
  - ne couvre QUE l'etat de repos : :hover / :focus / ::before / :has() sont
    ignores. Un changement touchant un etat doit etre verifie a la main.
  - les elements sont ceux du corpus (templates + reglages ci-dessous).

Usage :
    python3 scripts/css_verify.py static/css/input.css static/css/input.css
    python3 scripts/css_verify.py --against-git HEAD
    cp static/css/input.css /tmp/avant.css && ... && \
        python3 scripts/css_verify.py /tmp/avant.css static/css/input.css

Code de sortie : 0 si identique, 1 si differences (utilisable en pre-commit/CI).
"""
from __future__ import annotations
import argparse
import glob
import os
import re
import subprocess
import sys
from html.parser import HTMLParser

# ---------------------------------------------------------------- CSS model

LAYER_RANK = {'base': 0, 'components': 1}   # ordre de declaration des couches
STATE_PSEUDOS = {
    'hover', 'focus', 'focus-visible', 'focus-within', 'active', 'disabled',
    'checked', 'open', 'empty', 'has', 'visited', 'target', 'enabled',
    'required', 'valid', 'invalid', 'placeholder-shown',
}


class Rule:
    __slots__ = ('selector', 'decls', 'pos', 'media', 'layer')

    def __init__(self, selector, decls, pos, media, layer):
        self.selector = selector
        self.decls = decls
        self.pos = pos
        self.media = media
        self.layer = layer


def strip_comments(css):
    return re.sub(r'/\*.*?\*/', '', css, flags=re.S)


def parse_decls(body):
    out = {}
    for chunk in body.split(';'):
        chunk = chunk.strip()
        if not chunk or ':' not in chunk:
            continue
        prop, val = chunk.split(':', 1)
        out[prop.strip()] = val.strip()   # derniere declaration gagne
    return out


def _find_close(s, i):
    assert s[i] == '{'
    depth = 0
    while i < len(s):
        if s[i] == '{':
            depth += 1
        elif s[i] == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError('accolade non fermee')


def parse_css(path):
    text = strip_comments(open(path, encoding='utf-8').read())
    rules = []
    order = [0]

    def emit(sel_group, body, media, layer):
        decls = parse_decls(body)
        for sel in sel_group.split(','):
            sel = sel.strip()
            if sel:
                rules.append(Rule(sel, dict(decls), order[0], media, layer))
                order[0] += 1

    def block(s, i, media, layer):
        n = len(s)
        while i < n:
            while i < n and s[i].isspace():
                i += 1
            if i >= n or s[i] == '}':
                return i + 1 if i < n else i
            if s[i] == '@':
                m = re.match(r'@([-\w]+)', s[i:])
                name = m.group(1).lower()
                b = s.index('{', i)
                e = _find_close(s, b)
                inner = s[b + 1:e]
                if name == 'layer':
                    nm = re.match(r'@layer\s+([-\w]+)', s[i:])
                    block(inner, 0, media, nm.group(1) if nm else layer)
                elif name == 'media':
                    block(inner, 0, s[i:b].strip(), layer)
                elif name == 'supports':
                    block(inner, 0, media, layer)
                # @theme / @keyframes / @font-face : ignores
                i = e + 1
            else:
                m = re.match(r'([^{}]+)\{', s[i:])
                b = i + m.end() - 1
                e = _find_close(s, b)
                emit(m.group(1), s[b + 1:e], media, layer)
                i = e + 1
        return i

    block(text, 0, None, None)
    return rules


# ---------------------------------------------------------- selector engine

def specificity(sel):
    ids = len(re.findall(r'#[A-Za-z0-9_-]+', sel))
    classes = len(re.findall(r'\.[A-Za-z0-9_-]+', sel))
    classes += len(re.findall(r'\[[^\]]+\]', sel))
    classes += len(re.findall(r':(?!:)[A-Za-z-]+(?:\([^)]*\))?', sel))
    elements = len(re.findall(r'(?<![A-Za-z0-9_.#:\[-])(?:[a-zA-Z][a-zA-Z0-9]*|\*)(?![A-Za-z0-9_(])', sel))
    elements += len(re.findall(r'::[A-Za-z-]+', sel))
    return (ids, classes, elements)


def has_state_pseudo(sel):
    return any(m.group(1) in STATE_PSEUDOS for m in re.finditer(r':(?!:)([A-Za-z-]+)', sel))


def parse_simple(simple):
    if '::' in simple or '[' in simple.strip():
        return None
    if has_state_pseudo(simple):
        return 'STATE'
    core = re.sub(r':[A-Za-z-]+(?:\([^)]*\))?', '', simple)
    tag = None
    m = re.match(r'^([a-zA-Z*][a-zA-Z0-9*]*)', core)
    if m:
        tag = m.group(1)
        core = core[m.end():]
    classes = tuple(re.findall(r'\.([A-Za-z0-9_-]+)', core))
    ids = tuple(re.findall(r'#([A-Za-z0-9_-]+)', core))
    # pseudo-classes structurelles reconnues
    pseudos = set(re.findall(r':([A-Za-z-]+)', simple))
    return (tag, classes, ids, pseudos)


def split_selector(sel):
    tokens = re.split(r'(\s*[>+~]\s*|\s+)', sel)
    seq, pending = [], ' '
    for tok in tokens:
        if not tok:
            continue
        if re.fullmatch(r'\s*[>+~]\s*|\s+', tok):
            pending = tok.strip() or ' '
            continue
        seq.append((pending, tok))
        pending = ' '
    return seq


def match_simple(parsed, el):
    if parsed is None:
        return 'UNKNOWN'
    if parsed == 'STATE':
        return False
    tag, classes, ids, pseudos = parsed
    if tag and tag != '*' and tag != el['tag']:
        return False
    if not set(classes).issubset(el['classes']):
        return False
    if ids and el.get('id') not in ids:
        return False
    if 'last-child' in pseudos and not el.get('is_last', False):
        return False
    if 'first-child' in pseudos and not el.get('is_first', False):
        return False
    return True


def match_selector(sel, el, ancestors):
    if '::' in sel:
        return False
    seq = split_selector(sel)
    if not seq:
        return False
    first = match_simple(parse_simple(seq[-1][1]), el)
    if first != True:
        return first
    anc = list(ancestors)
    k = len(seq) - 1
    while k > 0:
        comb = seq[k][0]
        left = parse_simple(seq[k - 1][1])
        if left is None:
            return 'UNKNOWN'
        if left == 'STATE':
            return False
        if comb == '>':
            if not anc:
                return False
            m = match_simple(left, anc[0])
            if m != True:
                return m
            anc = anc[1:]
        elif comb == ' ':
            found = False
            for j, a in enumerate(anc):
                m = match_simple(left, a)
                if m == 'UNKNOWN':
                    return 'UNKNOWN'
                if m:
                    found = True
                    anc = anc[j + 1:]
                    break
            if not found:
                return False
        else:                       # '+' et '~' : non modelises -> conservateur
            return 'UNKNOWN'
        k -= 1
    return True


# -------------------------------------------------------------- DOM corpus

def expand_conditionals(s):
    """Developpe les {% if %}...{% else %}...{% endif %} d'un attribut class."""
    m = re.search(r'\{%\s*if\b.*?\{%\s*endif\s*%\}', s, flags=re.S)
    if not m:
        return [re.sub(r'\{%.*?%\}|{{.*?}}', ' ', s)]
    pre, blk, post = s[:m.start()], m.group(0), s[m.end():]
    parts = re.split(r'\{%\s*else\s*%\}', blk)
    opts = [re.sub(r'\{%.*?%\}', ' ', p) for p in parts] if len(parts) == 2 \
        else [re.sub(r'\{%.*?%\}', ' ', blk), ' ']
    out = []
    for p in expand_conditionals(pre):
        for o in opts:
            for q in expand_conditionals(post):
                out.append(p + o + q)
    return out


class DOMParser(HTMLParser):
    VOID = {'img', 'br', 'hr', 'input', 'meta', 'link', 'source', 'wbr',
            'circle', 'path', 'rect', 'line', 'polyline', 'use'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.elements = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        raw = d.get('class') or ''
        eid = d.get('id')
        ancs = [(t, set(c), i) for (t, c, i) in self.stack]
        for variant in expand_conditionals(raw):
            classes = {c for c in variant.split() if '{' not in c and '}' not in c}
            self.elements.append({'tag': tag, 'classes': classes, 'id': eid,
                                  'ancestors': ancs})
        if tag not in self.VOID:
            union = set()
            for variant in expand_conditionals(raw):
                union.update(c for c in variant.split() if '{' not in c and '}' not in c)
            self.stack.append((tag, union, eid))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if self.stack and self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_endtag(self, tag):
        for j in range(len(self.stack) - 1, -1, -1):
            if self.stack[j][0] == tag:
                del self.stack[j:]
                return


def extract_templates(root):
    els = []
    for path in glob.glob(os.path.join(root, '**', '*.html'), recursive=True):
        src = re.sub(r'\{#.*?#\}', '', open(path, encoding='utf-8').read(), flags=re.S)
        p = DOMParser()
        try:
            p.feed(src)
        except Exception as exc:                       # pragma: no cover
            print(f'css_verify: WARN parsing {path}: {exc}', file=sys.stderr)
        for e in p.elements:
            e['file'] = path
            els.append(e)
    return els


def dynamic_elements():
    """Elements injectes par app.js / fabriques par admin.rs (personnalisable
    pour d'autres projets ; laisser vide si non pertinent)."""
    els = []

    def add(tag, classes, ancestors, origin='dyn'):
        els.append({'tag': tag, 'classes': set(classes), 'id': None,
                    'ancestors': ancestors, 'file': origin})

    modal = [('div', {'modal__body'}, None),
             ('div', {'modal__in'}, None), ('dialog', {'modal'}, 'modal')]
    add('div', {'toast'}, [('div', {'toasts'}, 'toasts')], 'app.js')
    add('img', {'qr', 'qr--modal'}, modal, 'app.js')
    add('form', {'modal__f'}, modal, 'app.js')
    field_anc = [('label', {'flabel'}, None), ('form', {'modal__f'}, 'mf')] + modal
    add('label', {'flabel'}, [('form', {'modal__f'}, 'mf')] + modal, 'app.js')
    add('span', {'hud'}, field_anc, 'app.js')
    add('input', {'field'}, field_anc, 'app.js')
    add('button', {'btn'}, [('form', {'modal__f'}, 'mf')] + modal, 'app.js')
    for classes in ({'btn'}, {'btn', 'btn--danger', 'btn--wrap'},
                    {'btn', 'btn--danger'}, {'btn', 'btn--ghost'}):
        for ancs in (
            [('div', {'actions'}, None), ('section', {'panel'}, None)],
            [('div', {'actions'}, None), ('form', {'form'}, None),
             ('section', {'panel'}, None)],
            [('div', {'actions'}, None),
             ('section', {'panel', 'panel--danger'}, None)],
        ):
            add('button', classes, ancs, 'admin.rs')
    return els


# ------------------------------------------------------------- media + calc

def _to_px(value):
    value = value.strip().lower()
    if value.endswith('rem'):
        return float(value[:-3]) * 16
    if value.endswith('em'):
        return float(value[:-2]) * 16
    if value.endswith('px'):
        return float(value[:-2])
    return float(value)


def media_matches(query, width):
    if query is None:
        return True
    q = query.lower()
    if 'prefers-color-scheme' in q:          # n'influe pas sur *quelles* regles
        return True                            # s'appliquent, seulement sur var()
    m = re.search(r'min-width:\s*([0-9.]+(?:rem|px|em))', q)
    M = re.search(r'max-width:\s*([0-9.]+(?:rem|px|em))', q)
    if m and width < _to_px(m.group(1)):
        return False
    if M and width > _to_px(M.group(1)):
        return False
    return True


def compute(rules, elements, width):
    active = [r for r in rules if media_matches(r.media, width)]
    out = {}
    for idx, el in enumerate(elements):
        ancs = [{'tag': t, 'classes': set(c), 'id': i}
                for (t, c, i) in el['ancestors']]
        ego = {'tag': el['tag'], 'classes': set(el['classes']), 'id': el.get('id')}
        win = {}
        for r in active:
            if '::' in r.selector or has_state_pseudo(r.selector):
                continue
            if match_selector(r.selector, ego, ancs) is not True:
                continue
            key = (LAYER_RANK.get(r.layer, 2), specificity(r.selector), r.pos)
            for prop, val in r.decls.items():
                if prop not in win or key >= win[prop][0]:
                    win[prop] = (key, val)
        out[idx] = {p: v for p, (k, v) in win.items()}
    return out


def el_label(el):
    chain = '>'.join(f'{t}.{".".join(sorted(c))}'
                     for (t, c, _) in el['ancestors'][-3:])
    return (f"{os.path.basename(el.get('file', '?'))} :: {chain} >> "
            f"{el['tag']}.{'.'.join(sorted(el['classes']))}"
            f"#{el.get('id') or ''}")


def default_widths():
    return [320, 500, 639, 700, 767, 767.984, 768, 800, 900, 959, 959.984,
            960, 1000, 1087, 1087.984, 1088, 1100, 1152, 1200, 1300, 1500]


# ------------------------------------------------------------------- driver

def git_show(ref, path):
    out = subprocess.check_output(['git', 'show', f'{ref}:{path}'],
                                  stderr=subprocess.DEVNULL)
    tmp = '/tmp/css_verify_base.css'
    open(tmp, 'wb').write(out)
    return tmp


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('before', nargs='?', help='CSS de reference (avant)')
    ap.add_argument('after', nargs='?', help='CSS a verifier (apres)')
    ap.add_argument('--against-git', metavar='REF',
                    help='compare REF:<file> a l\'arbre de travail')
    ap.add_argument('--file', default='static/css/input.css',
                    help='CSS cible (defaut: static/css/input.css)')
    ap.add_argument('--widths', default=None,
                    help='largeurs separees par des virgules')
    args = ap.parse_args(argv)

    if args.against_git:
        before = git_show(args.against_git, args.file)
        after = args.file
    elif args.before and args.after:
        before, after = args.before, args.after
    else:
        ap.error('fournir BEFORE AFTER, ou --against-git REF')

    root = os.getcwd()
    if not os.path.isdir(os.path.join(root, 'templates')):
        root = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'],
                                       text=True).strip()
    elements = extract_templates(os.path.join(root, 'templates'))
    elements += dynamic_elements()
    if not elements:
        print('css_verify: aucun element trouve (templates/ absent ?)', file=sys.stderr)
        return 2

    widths = ([float(x) for x in args.widths.split(',')] if args.widths
              else default_widths())

    rules_before = parse_css(before)
    rules_after = parse_css(after)
    diffs = []
    for w in widths:
        b = compute(rules_before, elements, w)
        a = compute(rules_after, elements, w)
        for idx in b:
            for prop in set(b[idx]) | set(a[idx]):
                bv, av = b[idx].get(prop), a[idx].get(prop)
                if bv != av:
                    diffs.append((w, el_label(elements[idx]), prop, bv, av))

    if not diffs:
        print(f'IDENTIQUE — {len(elements)} elements x {len(widths)} largeurs '
              f'({before} vs {after})')
        return 0
    print(f'{len(diffs)} DIFFERENCE(S) ({before} vs {after})')
    seen = 0
    for w, label, prop, bv, av in diffs:
        print(f'  w={w:>8}  {label}\n      {prop}: {bv!r} -> {av!r}')
        seen += 1
        if seen >= 60:
            print(f'  ... et {len(diffs) - seen} autres')
            break
    return 1


if __name__ == '__main__':
    sys.exit(main())
