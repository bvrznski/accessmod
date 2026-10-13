from access_modifiers.checker import check_paths
from access_modifiers import protected_property, access_info

def test_checker(tmp_path):
    pkg=tmp_path/'pkg';pkg.mkdir()
    (pkg/'__init__.py').write_text('')
    (pkg/'a.py').write_text('@private\ndef secret(): pass\n@internal\ndef helper(): pass\n')
    (pkg/'b.py').write_text('from pkg.a import helper\n')
    (tmp_path/'outside.py').write_text('from pkg.a import secret, helper\n')
    codes=[d.code for d in check_paths([tmp_path],root=tmp_path)]
    assert codes.count('AM001')==1
    assert codes.count('AM002')==1

def test_protected_property_metadata():
    class Sample:
        @protected_property(read='public',write='class')
        def value(self): return 5
    assert Sample().value==5
    assert access_info(Sample.value).write=='class'
