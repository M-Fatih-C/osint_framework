import re
from typing import Dict, Any, List, Set

from osint_framework.core.logger import logger

class Correlator:
    """
    Intelligence Correlation Engine
    Finds relationships between different intelligence data points.
    """
    
    @staticmethod
    def analyze(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Merge results and find correlations like Email -> Domain -> IP
        """
        merged_data = {}
        extracted_emails = set()
        extracted_domains = set()
        extracted_ips = set()
        
        for result in results:
            mod_name = result.get("module")
            data = result.get("data", {})
            
            # Simple merge
            merged_data[mod_name] = data
            
            # Extract common indicators (naive regex extract for demonstration)
            text_repr = str(data)
            
            # Extract IPs
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text_repr)
            extracted_ips.update(ips)
            
            # Extract Emails
            emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text_repr)
            extracted_emails.update(emails)
            
            # Extract Domains (simplified)
            # A real implementation would use tldextract
            
        logger.debug(f"Correlator found {len(extracted_emails)} emails and {len(extracted_ips)} IPs.")
            
        return {
            "raw_results": merged_data,
            "correlations": {
                "emails_found": list(extracted_emails),
                "ips_found": list(extracted_ips),
                "domains_found": list(extracted_domains)
            }
        }
