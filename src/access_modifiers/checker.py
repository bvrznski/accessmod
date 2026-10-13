"""Conservative AST-based API boundary linter. No code execution.

AM001 private cross-module import; AM002 internal cross-package import;
AM003 protected cross-module import; AM004 private types in public annotations;
AM005 conflicting access declarations; AM006 implicit exports with __all__.

The checker intentionally reports only statically resolvable imports. Dynamic
getattr/importlib, re-exports, and method-level permissions need deeper analysis.
"""
from __future__ import annotations
import argparse
import ast
from dataclasses import dataclass
from pathlib import Path
import sys

CODES = {'private':'AM001','internal':'AM002','protected':'AM003'}
MODIFIERS = {'public','internal','private','protected'}

@dataclass(frozen=True)
class Diagnostic:
    path: str
    line: int
    code: str
    message: str
    def __str__(self):
        return f'{self.path}:{self.line}: {self.code} {self.message}'

def _decorator_name(node):
    if isinstance(node, ast.Call): node = node.func
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return node.attr
    return None

def _module(path: Path, root: Path) -> str:
    parts = list(path.relative_to(root).with_suffix('').parts)
    if parts[-1] == '__init__': parts.pop()
    return '.'.join(parts)

def check_paths(paths: list[str | Path], *, root: str | Path = '.') -> list[Diagnostic]:
    root = Path(root).resolve()
    sources = []
    for entry in paths:
        entry = Path(entry)
        sources.extend(sorted(entry.rglob('*.py')) if entry.is_dir() else [entry])
    parsed = {}
    diagnostics = []
    for path in sources:
        path = path.resolve()
        try:
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        except (SyntaxError, UnicodeError, OSError) as exc:
            diagnostics.append(Diagnostic(str(path), getattr(exc,'lineno',1) or 1,'AM000',str(exc)))
            continue
        try: module = _module(path,root)
        except ValueError: module = path.stem
        parsed[module] = (path,tree)
    contracts = {}
    for module,(path,tree) in parsed.items():
        declared = {}
        explicit_all = None
        for node in tree.body:
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                marks = [m for m in map(_decorator_name,node.decorator_list) if m in MODIFIERS]
                if len(set(marks)) > 1:
                    diagnostics.append(Diagnostic(str(path),node.lineno,'AM005',f'conflicting access declarations on {node.name}'))
                if marks: declared[node.name] = marks[-1]
            elif isinstance(node,ast.Assign):
                if any(isinstance(t,ast.Name) and t.id=='__all__' for t in node.targets):
                    if isinstance(node.value,(ast.List,ast.Tuple)):
                        explicit_all = {v.value for v in node.value.elts if isinstance(v,ast.Constant) and isinstance(v.value,str)}
        contracts[module] = declared
        if explicit_all is not None:
            for name in explicit_all:
                if name in declared and declared[name] != 'public':
                    diagnostics.append(Diagnostic(str(path),1,'AM006',f'non-public name {name} included in __all__'))
        for node in tree.body:
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and declared.get(node.name)=='public':
                for annotation in [node.returns,*[a.annotation for a in node.args.posonlyargs+node.args.args+node.args.kwonlyargs]]:
                    if annotation:
                        for child in ast.walk(annotation):
                            if isinstance(child,ast.Name) and declared.get(child.id)=='private':
                                diagnostics.append(Diagnostic(str(path),node.lineno,'AM004',f'public API {node.name} exposes private type {child.id}'))
    for module,(path,tree) in parsed.items():
        for node in ast.walk(tree):
            if not isinstance(node,ast.ImportFrom) or node.level: continue
            target = node.module or ''
            exported = contracts.get(target,{})
            for alias in node.names:
                mark = exported.get(alias.name)
                if mark not in CODES: continue
                allowed = (module==target if mark!='internal' else module==target or module.startswith(target.rpartition('.')[0]+'.') and bool(target.rpartition('.')[0]))
                if not allowed:
                    diagnostics.append(Diagnostic(str(path),node.lineno,CODES[mark],f'{alias.name} is {mark} in {target}'))
    return sorted(diagnostics,key=lambda d:(d.path,d.line,d.code))

def main(argv=None):
    parser=argparse.ArgumentParser(description='Check declared Python API boundaries (static, conservative).')
    parser.add_argument('paths',nargs='+',help='Python files or directories')
    parser.add_argument('--root',default='.',help='Python import root, e.g. src')
    args=parser.parse_args(argv)
    found=check_paths(args.paths,root=args.root)
    for item in found: print(item)
    return 1 if found else 0

if __name__=='__main__':
    sys.exit(main())
