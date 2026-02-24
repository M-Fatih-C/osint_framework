class OSINTError(Exception):
    """Base exception for all OSINT framework errors"""
    pass

class ValidationError(OSINTError):
    """Raised when target validation fails"""
    pass

class ModuleExecutionError(OSINTError):
    """Raised when a module fails to execute"""
    def __init__(self, module_name: str, message: str):
        self.module_name = module_name
        self.message = message
        super().__init__(f"[{module_name}] {message}")

class QueueError(OSINTError):
    """Raised when a job queue operation fails"""
    pass

class ConfigurationError(OSINTError):
    """Raised when configuration is invalid or missing"""
    pass
