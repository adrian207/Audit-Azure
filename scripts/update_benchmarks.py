"""
Azure Security Benchmark Update Checker

Automatically checks for updates to Microsoft security baselines and frameworks.
Downloads and parses the latest versions from official Microsoft sources.
"""

import asyncio
import aiohttp  # type: ignore[import]
from typing import Dict, List, Optional
from datetime import datetime
import json
import os
import hashlib
from pathlib import Path


class BenchmarkUpdateChecker:
    """Check for updates to Azure Security Benchmark and related frameworks"""
    
    # Official Microsoft baseline URLs
    SOURCES = {
        'azure_security_benchmark': {
            'url': 'https://raw.githubusercontent.com/MicrosoftDocs/SecurityBenchmarks/master/Azure%20Security%20Benchmark/3.0/asb_v3.json',
            'description': 'Azure Security Benchmark v3.0',
            'type': 'json'
        },
        'cis_azure_foundations': {
            'url': 'https://www.cisecurity.org/benchmark/azure',
            'description': 'CIS Microsoft Azure Foundations Benchmark',
            'type': 'html'  # Requires manual download
        },
        'nist_csf': {
            'url': 'https://www.nist.gov/cyberframework',
            'description': 'NIST Cybersecurity Framework',
            'type': 'html'
        },
        'iso27001_controls': {
            'url': 'https://www.iso.org/standard/27001',
            'description': 'ISO/IEC 27001:2013',
            'type': 'reference'
        }
    }
    
    def __init__(self, cache_dir: str = './cache/benchmarks'):
        """
        Initialize update checker
        
        Args:
            cache_dir: Directory to cache downloaded benchmarks
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_cache_path(self, source_key: str) -> Path:
        """Get cache file path for source"""
        return self.cache_dir / f"{source_key}.json"
    
    def _get_hash(self, content: str) -> str:
        """Calculate content hash"""
        return hashlib.sha256(content.encode()).hexdigest()
    
    async def check_for_updates(self, source_key: str) -> Dict:
        """
        Check if benchmark source has updates
        
        Args:
            source_key: Source identifier from SOURCES
            
        Returns:
            Update status and details
        """
        if source_key not in self.SOURCES:
            return {'error': f'Unknown source: {source_key}'}
        
        source = self.SOURCES[source_key]
        cache_path = self._get_cache_path(source_key)
        
        # Load cached version
        cached_data = None
        cached_hash = None
        
        if cache_path.exists():
            with open(cache_path, 'r') as f:
                cached_data = json.load(f)
                cached_hash = cached_data.get('content_hash')
        
        # Fetch current version
        try:
            if source['type'] == 'json':
                current_content = await self._fetch_json(source['url'])
                current_hash = self._get_hash(json.dumps(current_content, sort_keys=True))
                
                has_update = cached_hash != current_hash
                
                if has_update:
                    # Save new version
                    new_data = {
                        'source': source_key,
                        'description': source['description'],
                        'content_hash': current_hash,
                        'last_updated': datetime.utcnow().isoformat(),
                        'content': current_content
                    }
                    
                    with open(cache_path, 'w') as f:
                        json.dump(new_data, f, indent=2)
                
                return {
                    'source': source_key,
                    'description': source['description'],
                    'has_update': has_update,
                    'cached_version': cached_data.get('last_updated') if cached_data else None,
                    'current_hash': current_hash,
                    'cached_hash': cached_hash
                }
            
            else:
                # For non-JSON sources, return manual check instructions
                return {
                    'source': source_key,
                    'description': source['description'],
                    'type': source['type'],
                    'url': source['url'],
                    'message': 'Manual check required - visit URL to download latest version'
                }
        
        except Exception as e:
            return {
                'source': source_key,
                'error': str(e),
                'message': 'Failed to check for updates'
            }
    
    async def _fetch_json(self, url: str) -> Dict:
        """Fetch JSON content from URL"""
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                response.raise_for_status()
                return await response.json()
    
    async def check_all_sources(self) -> List[Dict]:
        """Check all benchmark sources for updates"""
        tasks = [
            self.check_for_updates(source_key)
            for source_key in self.SOURCES.keys()
        ]
        
        return await asyncio.gather(*tasks)
    
    def get_cached_benchmark(self, source_key: str) -> Optional[Dict]:
        """Get cached benchmark content"""
        cache_path = self._get_cache_path(source_key)
        
        if not cache_path.exists():
            return None
        
        with open(cache_path, 'r') as f:
            return json.load(f)
    
    def parse_asb_benchmark(self, content: Dict) -> List[Dict]:
        """
        Parse Azure Security Benchmark JSON into control definitions
        
        Args:
            content: ASB JSON content
            
        Returns:
            List of control definitions
        """
        controls = []
        
        # Parse ASB structure (adjust based on actual format)
        if 'controls' in content:
            for control in content['controls']:
                controls.append({
                    'control_id': control.get('id'),
                    'domain': control.get('domain'),
                    'title': control.get('title'),
                    'description': control.get('description'),
                    'severity': control.get('severity'),
                    'azure_guidance': control.get('azureGuidance'),
                    'security_principle': control.get('securityPrinciple'),
                    'mappings': {
                        'cis': control.get('cisMapping', []),
                        'nist': control.get('nistMapping', []),
                        'pci_dss': control.get('pciMapping', []),
                        'iso_27001': control.get('isoMapping', [])
                    }
                })
        
        return controls
    
    async def update_local_controls(self) -> Dict:
        """
        Update local control definitions with latest benchmark
        
        Returns:
            Update summary
        """
        # Check for ASB updates
        asb_status = await self.check_for_updates('azure_security_benchmark')
        
        if asb_status.get('has_update'):
            # Get new benchmark
            benchmark = self.get_cached_benchmark('azure_security_benchmark')
            
            if benchmark:
                # Parse controls
                new_controls = self.parse_asb_benchmark(benchmark['content'])
                
                return {
                    'updated': True,
                    'controls_count': len(new_controls),
                    'version': benchmark.get('last_updated'),
                    'message': f'Updated {len(new_controls)} controls from ASB'
                }
        
        return {
            'updated': False,
            'message': 'No updates available'
        }


class ComplianceFrameworkUpdater:
    """Update compliance framework mappings"""
    
    FRAMEWORK_URLS = {
        'cis_v8': 'https://www.cisecurity.org/controls/v8',
        'nist_800_53': 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
        'pci_dss_4': 'https://www.pcisecuritystandards.org/document_library',
        'iso_27001': 'https://www.iso.org/standard/27001',
        'soc2': 'https://www.aicpa.org/soc',
        'hipaa': 'https://www.hhs.gov/hipaa/index.html',
        'gdpr': 'https://gdpr.eu/'
    }
    
    @staticmethod
    def get_framework_update_info() -> Dict:
        """Get information about framework updates"""
        return {
            'frameworks': [
                {
                    'name': 'CIS Controls v8',
                    'url': ComplianceFrameworkUpdater.FRAMEWORK_URLS['cis_v8'],
                    'check_frequency': 'Quarterly',
                    'last_update': '2023-05-01'
                },
                {
                    'name': 'NIST SP 800-53 Rev. 5',
                    'url': ComplianceFrameworkUpdater.FRAMEWORK_URLS['nist_800_53'],
                    'check_frequency': 'Annually',
                    'last_update': '2020-09-01'
                },
                {
                    'name': 'PCI-DSS v4.0',
                    'url': ComplianceFrameworkUpdater.FRAMEWORK_URLS['pci_dss_4'],
                    'check_frequency': 'Semi-annually',
                    'last_update': '2022-03-31'
                }
            ],
            'recommendation': 'Check for framework updates quarterly and update control mappings accordingly'
        }


async def check_for_benchmark_updates() -> Dict:
    """
    Convenience function to check for all benchmark updates
    
    Returns:
        Update status for all sources
    """
    checker = BenchmarkUpdateChecker()
    results = await checker.check_all_sources()
    
    return {
        'timestamp': datetime.utcnow().isoformat(),
        'results': results
    }
