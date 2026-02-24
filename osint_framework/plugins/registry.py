import importlib
import inspect
import sys
from pathlib import Path
from typing import Dict, List, Type

from osint_framework.core.logger import logger
from osint_framework.plugins.base import BaseModule

class PluginRegistry:
    def __init__(self):
        self._modules: Dict[str, Type[BaseModule]] = {}

    def _resolve_plugins_dir(self, plugins_dir: str = None) -> Path:
        package_plugins_dir = Path(__file__).resolve().parent
        if not plugins_dir:
            return package_plugins_dir

        path = Path(plugins_dir)
        if path.is_absolute():
            return path
        if path.exists():
            return path.resolve()

        candidate = package_plugins_dir / plugins_dir
        if candidate.exists():
            return candidate.resolve()

        return path.resolve()

    def discover(self, plugins_dir: str = None):
        """Automatically discover and register all BaseModule subclasses in the plugins directory."""
        path = self._resolve_plugins_dir(plugins_dir)
        if not path.exists():
            logger.warning(f"Plugins directory {path} does not exist.")
            return

        # Add repo root to sys.path to allow imports like 'osint_framework.plugins.ip.module'
        package_root = Path(__file__).resolve().parents[1]  # .../osint_framework
        parent_dir = str(package_root.parent)
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)

        self._modules.clear()
        count = 0
        for py_file in path.rglob("*.py"):
            if any(part == "__pycache__" or part.startswith("._") for part in py_file.parts):
                continue
            if py_file.name.startswith("._") or py_file.name.startswith(".__"):
                continue
            if py_file.name == "__init__.py" or py_file.name == "base.py" or py_file.name == "registry.py":
                continue

            # Convert file path to module syntax: osint_framework.plugins.ip.my_module
            rel_path = py_file.relative_to(package_root.parent)
            module_name = ".".join(rel_path.with_suffix("").parts)

            try:
                mod = importlib.import_module(module_name)
                # Find all classes in the module that subclass BaseModule
                for name, obj in inspect.getmembers(mod, inspect.isclass):
                    if issubclass(obj, BaseModule) and obj is not BaseModule:
                        self.register(obj)
                        count += 1
            except Exception as e:
                logger.error(f"Failed to load plugin {module_name}: {e}")

        logger.info(f"Loaded {count} plugins from {path}")

    def register(self, module_class: Type[BaseModule]):
        """Register a module by its class name or 'name' attribute."""
        name = getattr(module_class, "name", module_class.__name__)
        self._modules[name] = module_class
        logger.debug(f"Registered module: {name} (Targets: {module_class.target_types})")

    def get_modules_for(self, target_type: str) -> List[Type[BaseModule]]:
        """Return all modules that support the given target type."""
        supported = []
        for name, mod_cls in self._modules.items():
            if target_type in mod_cls.target_types or "*" in mod_cls.target_types:
                supported.append(mod_cls)
        return supported

    def list_all(self) -> List[dict]:
        """List metadata of all registered modules."""
        info = []
        for name, mod_cls in self._modules.items():
            info.append({
                "name": name,
                "version": mod_cls.version,
                "description": mod_cls.description,
                "target_types": mod_cls.target_types,
                "author": mod_cls.author
            })
        return info

registry = PluginRegistry()
