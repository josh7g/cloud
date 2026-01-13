"""
Cloud Provider Registry - Factory pattern for managing cloud provider integrations
"""
import logging
from typing import Dict, Callable, Optional, Any
from abc import ABC

logger = logging.getLogger(__name__)


class CloudProviderRegistry:
    """
    Central registry for all cloud provider integrations.
    Uses factory pattern to register and retrieve provider-specific handlers.
    """
    
    _instance = None
    _providers: Dict[str, Dict[str, Any]] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CloudProviderRegistry, cls).__new__(cls)
        return cls._instance
    
    def register_provider(
        self,
        provider_name: str,
        scan_handler: Callable,
        validator: Optional[Callable] = None,
        scanner_class: Optional[type] = None,
        api_blueprint: Optional[Any] = None
    ):
        """
        Register a cloud provider with its handlers and classes.
        
        Args:
            provider_name: Name of the cloud provider (e.g., 'aws', 'azure', 'gcp')
            scan_handler: Async function to handle scan requests
            validator: Optional function to validate credentials
            scanner_class: Optional scanner class
            api_blueprint: Optional API blueprint
        """
        self._providers[provider_name] = {
            'scan_handler': scan_handler,
            'validator': validator,
            'scanner_class': scanner_class,
            'api_blueprint': api_blueprint
        }
        logger.info(f"Registered cloud provider: {provider_name}")
    
    def get_scan_handler(self, provider_name: str) -> Optional[Callable]:
        """Get the scan handler for a provider"""
        provider = self._providers.get(provider_name)
        return provider.get('scan_handler') if provider else None
    
    def get_validator(self, provider_name: str) -> Optional[Callable]:
        """Get the validator for a provider"""
        provider = self._providers.get(provider_name)
        return provider.get('validator') if provider else None
    
    def get_scanner_class(self, provider_name: str) -> Optional[type]:
        """Get the scanner class for a provider"""
        provider = self._providers.get(provider_name)
        return provider.get('scanner_class') if provider else None
    
    def get_api_blueprint(self, provider_name: str) -> Optional[Any]:
        """Get the API blueprint for a provider"""
        provider = self._providers.get(provider_name)
        return provider.get('api_blueprint') if provider else None
    
    def list_providers(self) -> list:
        """List all registered providers"""
        return list(self._providers.keys())
    
    def is_provider_registered(self, provider_name: str) -> bool:
        """Check if a provider is registered"""
        return provider_name in self._providers


def register_provider(
    provider_name: str,
    scan_handler: Callable,
    validator: Optional[Callable] = None,
    scanner_class: Optional[type] = None,
    api_blueprint: Optional[Any] = None
):
    """
    Convenience function to register a cloud provider.
    
    Usage:
        register_provider(
            'aws',
            scan_handler=scan_aws_account_handler,
            validator=validate_aws_credentials,
            scanner_class=AwsSecurityScanner,
            api_blueprint=aws_api_blueprint
        )
    """
    registry = CloudProviderRegistry()
    registry.register_provider(
        provider_name=provider_name,
        scan_handler=scan_handler,
        validator=validator,
        scanner_class=scanner_class,
        api_blueprint=api_blueprint
    )

