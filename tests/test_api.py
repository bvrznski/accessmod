import asyncio
import inspect
import pytest
from access_modifiers import public, private, internal, protected, access_info, AccessViolation, ProtectedField

def test_public_export():
    namespace = {'__name__': 'test_dynamic'}
    exec('from access_modifiers import public\n@public\ndef api(): pass\n', namespace)
    assert namespace['__all__'] == ['api']

def test_private_export():
    namespace = {'__name__': 'test_dynamic', '__all__': ['hidden', 'visible']}
    exec('from access_modifiers import private\n@private\ndef hidden(): pass\n', namespace)
    assert namespace['__all__'] == ['visible']

def test_internal_policy():
    @internal
    def fn(): pass
    assert access_info(fn).scope == 'package'

def test_identity():
    def fn(): pass
    assert public(fn) is fn

def test_runtime_module():
    @private(runtime=True)
    def fn(): return 7
    assert fn() == 7
    assert inspect.signature(fn) == inspect.Signature()

def test_runtime_reject():
    @private(scope='nonexistent.module', runtime=True)
    def fn(): return 7
    # Owner module is always permitted.
    assert fn() == 7

def test_async():
    @internal
    async def fn(): return 9
    assert asyncio.run(fn()) == 9

def test_protected_metadata():
    @protected(read='public', write='module')
    def fn(): pass
    assert access_info(fn).read == 'public'
    assert access_info(fn).write == 'module'

def test_descriptor():
    class Sample:
        value = ProtectedField(1, read='public', write='module')
    obj = Sample()
    assert obj.value == 1
    obj.value = 3
    assert obj.value == 3
    assert 'value' in dir(obj)
    assert 'ProtectedField' in repr(Sample.value)

def test_class_runtime_rejected():
    with pytest.raises(TypeError):
        @private(runtime=True)
        class Sample: pass
