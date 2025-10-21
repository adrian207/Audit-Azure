"""
CLI tool for benchmark update management
"""

import asyncio
import sys
from .update_benchmarks import (
    BenchmarkUpdateChecker,
    ComplianceFrameworkUpdater,
    check_for_benchmark_updates
)


def print_header(title: str):
    """Print formatted header"""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60 + "\n")


async def main():
    """Main CLI entry point"""
    
    # Parse command line arguments
    show_framework_info = '--show-framework-info' in sys.argv
    update_controls = '--update-controls' in sys.argv
    
    if show_framework_info:
        # Show framework update information
        print_header("Compliance Framework Update Information")
        
        info = ComplianceFrameworkUpdater.get_framework_update_info()
        
        for framework in info['frameworks']:
            print(f"Framework: {framework['name']}")
            print(f"  URL: {framework['url']}")
            print(f"  Check Frequency: {framework['check_frequency']}")
            print(f"  Last Update: {framework['last_update']}")
            print()
        
        print(f"Recommendation: {info['recommendation']}")
        return 0
    
    # Run update checks
    print_header("Azure Security Benchmark Update Check")
    
    results = await check_for_benchmark_updates()
    
    print(f"Check completed at: {results['timestamp']}\n")
    
    has_updates = False
    
    for result in results['results']:
        source = result.get('source', 'Unknown')
        description = result.get('description', '')
        
        print(f"Source: {source}")
        print(f"  Description: {description}")
        
        if 'error' in result:
            print(f"  ❌ Error: {result['error']}")
            print(f"  Message: {result.get('message', '')}")
        
        elif result.get('type') in ['html', 'reference']:
            print(f"  ℹ️  Type: {result['type']}")
            print(f"  URL: {result['url']}")
            print(f"  Message: {result['message']}")
        
        else:
            has_update = result.get('has_update', False)
            
            if has_update:
                print(f"  ✅ UPDATE AVAILABLE")
                has_updates = True
            else:
                print(f"  ✓ Up to date")
            
            if result.get('cached_version'):
                print(f"  Cached Version: {result['cached_version']}")
            
            print(f"  Current Hash: {result.get('current_hash', 'N/A')[:16]}...")
        
        print()
    
    # Optionally update local controls
    if update_controls and has_updates:
        print_header("Updating Local Control Definitions")
        
        checker = BenchmarkUpdateChecker()
        update_result = await checker.update_local_controls()
        
        if update_result['updated']:
            print(f"✅ {update_result['message']}")
            print(f"   Controls updated: {update_result['controls_count']}")
            print(f"   Version: {update_result['version']}")
        else:
            print(f"ℹ️  {update_result['message']}")
    
    elif has_updates:
        print("\n" + "=" * 60)
        print("💡 Updates are available!")
        print("   Run with --update-controls to apply updates")
        print("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
