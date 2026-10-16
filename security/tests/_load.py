"""Carrega os scripts implantados (alguns sem extensão .py) como módulos, para testar as funções puras.

Os scripts rodam em Linux; aqui no PC (Windows) os módulos só-Unix (grp) viram stubs: as funções
testadas não dependem deles.
"""
import importlib.machinery, importlib.util, os, sys, types

DEPLOY = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.modules.setdefault("grp", types.ModuleType("grp"))


def load(name, *rel):
    path = os.path.join(DEPLOY, *rel)
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod
