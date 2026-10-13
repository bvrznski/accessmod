"""Declarative Python API boundaries; not a security mechanism."""
from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
import inspect
import sys
from typing import Any

__version__ = '1.0.0'
__all__ = ['public', 'internal', 'private', 'protected', 'access_info', 'AccessPolicy', 'AccessViolation', 'ProtectedField', 'protected_property']

class AccessViolation(PermissionError):
    """A cooperative access check rejected an operation."""

@dataclass(frozen=True)
class AccessPolicy:
    modifier: str
    scope: Any = None
    runtime: bool = False
    read: Any = None
    write: Any = None

def _package(module: str) -> str:
    mod = sys.modules.get(module)
    package = getattr(mod, '__package__', None)
    return package if package else module.rpartition('.')[0] or module

def _allowed(caller: str, owner: str, scope: Any) -> bool:
    if scope == 'public':
        return True
    if scope in (None, 'module', 'class', 'instance', 'self'):
        return caller == owner
    if scope == 'package':
        root = _package(owner)
        return caller == root or caller.startswith(root + '.')
    if isinstance(scope, str):
        return caller == scope or caller == owner
    if isinstance(scope, (tuple, list, set, frozenset)):
        return caller == owner or any(_allowed(caller, owner, s) for s in scope)
    raise TypeError('scope must be a string or a collection of strings')

def _caller_module(depth: int = 2) -> str:
    frame = inspect.currentframe()
    try:
        for _ in range(depth):
            frame = frame.f_back
        return frame.f_globals.get('__name__', '')
    finally:
        del frame

def _record(target: Any, policy: AccessPolicy) -> Any:
    try:
        target.__access_policy__ = policy
    except (AttributeError, TypeError) as exc:
        raise TypeError('access decorators require an object supporting metadata attributes') from exc
    return target

def _exports(frame: Any, target: Any, kind: str) -> None:
    if frame is None or frame.f_code.co_name != '<module>':
        return
    name = getattr(target, '__name__', None)
    if not name:
        return
    namespace = frame.f_globals
    # An absent __all__ is intentionally created: only explicit exports remain.
    current = namespace.get('__all__', ())
    if not isinstance(current, (list, tuple)):
        raise TypeError('module __all__ must be a list or tuple')
    names = list(current)
    if kind == 'public':
        if name not in names:
            names.append(name)
    else:
        names = [item for item in names if item != name]
    namespace['__all__'] = names

def _apply(target: Any, policy: AccessPolicy, frame: Any) -> Any:
    if not (inspect.isclass(target) or callable(target)):
        raise TypeError('access decorator requires a class or callable; use ProtectedField for data')
    owner = getattr(target, '__module__', '')
    result = target
    if policy.runtime:
        if inspect.isclass(target):
            raise TypeError('runtime checks on classes are not supported; decorate methods instead')
        if inspect.iscoroutinefunction(target):
            @wraps(target)
            async def guarded(*args, **kwargs):
                caller = _caller_module()
                if not _allowed(caller, owner, policy.scope):
                    raise AccessViolation(f'{target.__qualname__}: {caller} is outside {policy.scope!r}')
                return await target(*args, **kwargs)
        else:
            @wraps(target)
            def guarded(*args, **kwargs):
                caller = _caller_module()
                if not _allowed(caller, owner, policy.scope):
                    raise AccessViolation(f'{target.__qualname__}: {caller} is outside {policy.scope!r}')
                return target(*args, **kwargs)
        result = guarded
    _record(result, policy)
    _exports(frame, target, policy.modifier)
    return result

def _decorator(kind: str, obj: Any = None, *, scope: Any = None, runtime: bool = False,
               read: Any = None, write: Any = None):
    policy = AccessPolicy(kind, scope, runtime, read, write)
    if obj is not None:
        frame = inspect.currentframe().f_back.f_back
        try:
            return _apply(obj, policy, frame)
        finally:
            del frame
    def decorate(target):
        frame = inspect.currentframe().f_back
        try:
            return _apply(target, policy, frame)
        finally:
            del frame
    return decorate

def public(obj: Any = None):
    """Mark a definition public, adding its name to module ``__all__``."""
    return _decorator('public', obj, scope='public')

def internal(obj: Any = None, *, runtime: bool = False):
    """Declare package-internal API; enforcement is opt-in."""
    return _decorator('internal', obj, scope='package', runtime=runtime)

def private(obj: Any = None, *, scope: Any = 'module', runtime: bool = False):
    """Declare an implementation detail with an optional scope."""
    return _decorator('private', obj, scope=scope, runtime=runtime)

def protected(obj: Any = None, *, scope: Any = 'module', read: Any = None,
              write: Any = None, runtime: bool = False):
    """Describe interface access. For enforced data access use ProtectedField."""
    return _decorator('protected', obj, scope=scope, runtime=runtime, read=read, write=write)

def access_info(obj: Any) -> AccessPolicy | None:
    """Return immutable access metadata, or None for undecorated objects."""
    return getattr(obj, '__access_policy__', None)

class ProtectedField:
    """Opt-in data descriptor with read/write permissions checked by caller module.

    ``read`` and ``write`` accept 'public', 'module', 'package', or module names.
    These checks are cooperative and are NOT a security boundary.
    """
    def __init__(self, default: Any = None, *, read: Any = 'public', write: Any = 'module'):
        self.default, self.read, self.write = default, read, write
        self.name = None
        self.owner_module = None

    def __set_name__(self, owner, name):
        self.name = name
        self.owner_module = owner.__module__
        self.storage_name = f'__accessmod_{name}'

    def _check(self, scope):
        caller = _caller_module(3)
        if not _allowed(caller, self.owner_module, scope):
            raise AccessViolation(f'{self.name}: {caller} is outside {scope!r}')

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        self._check(self.read)
        return instance.__dict__.get(self.storage_name, self.default)

    def __set__(self, instance, value):
        self._check(self.write)
        instance.__dict__[self.storage_name] = value

    def __repr__(self):
        return f'ProtectedField(name={self.name!r}, read={self.read!r}, write={self.write!r})'


def protected_property(*, read: Any = 'public', write: Any = 'module'):
    """Declare a property backed by ordinary Python getter/setter methods.

    Access policies are discoverable via ``access_info``. The descriptor
    intentionally does not wrap getters/setters or modify Python lookup.
    Static analysis can inspect the metadata; runtime enforcement is not
    implied by this declaration.
    """
    def decorate(getter):
        policy = AccessPolicy('protected', 'module', False, read, write)
        class ContractProperty(property):
            __access_policy__ = policy
            def getter(self, fget):
                return type(self)(fget, self.fset, self.fdel, self.__doc__)
            def setter(self, fset):
                return type(self)(self.fget, fset, self.fdel, self.__doc__)
            def deleter(self, fdel):
                return type(self)(self.fget, self.fset, fdel, self.__doc__)
        return ContractProperty(getter)
    return decorate
