"""
Web crawler module for scanning websites.
"""

import logging
import time
import urllib.parse
from typing import Dict, List, Any, Set
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class WebCrawler:
    """Web crawler for discovering pages and resources on a website."""
    
    def __init__(
        self,
        max_depth: int = 3,
        max_pages: int = 100,
        timeout: int = 10,
        user_agent: str = "AI-VulScan/1.0",
        threads: int = 5,
    ):
        """
        Initialize the crawler with configuration.
        
        Args:
            max_depth: Maximum depth to crawl
            max_pages: Maximum number of pages to crawl
            timeout: Request timeout in seconds
            user_agent: User agent string to use in requests
            threads: Number of threads to use for crawling
        """
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.user_agent = user_agent
        self.threads = threads
        self.visited_urls: Set[str] = set()
        self.pages: List[Dict[str, Any]] = []
        
    def crawl(self, base_url: str) -> List[Dict[str, Any]]:
        """
        Crawl the website starting from the base URL.
        
        Args:
            base_url: Starting URL for crawling
            
        Returns:
            List of discovered pages with their details
        """
        self.visited_urls = set()
        self.pages = []
        self.base_url = base_url
        
        # Normalize base URL
        parsed_url = urllib.parse.urlparse(base_url)
        self.domain = parsed_url.netloc
        
        # Start crawling from the base URL
        logger.info(f"Starting crawl on {base_url}")
        self._crawl_page(base_url, depth=0)
        
        logger.info(f"Crawl completed. Discovered {len(self.pages)} pages.")
        return self.pages
    
    def _crawl_page(self, url: str, depth: int) -> None:
        """
        Crawl a single page and extract links.
        
        Args:
            url: URL to crawl
            depth: Current depth level
        """
        # Check if we've reached the maximum depth or page count
        if depth > self.max_depth or len(self.pages) >= self.max_pages:
            return
        
        # Check if URL has already been visited
        if url in self.visited_urls:
            return
        
        # Mark URL as visited
        self.visited_urls.add(url)
        
        try:
            # Send GET request to the URL
            headers = {"User-Agent": self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            # Check if request was successful
            if response.status_code != 200:
                logger.warning(f"Failed to fetch {url}: HTTP {response.status_code}")
                return
            
            # Extract page info
            content_type = response.headers.get("Content-Type", "")
            
            # Only process HTML pages
            if "text/html" not in content_type:
                logger.debug(f"Skipping non-HTML content at {url}")
                return
            
            # Parse HTML content
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Extract page details
            title = soup.title.text.strip() if soup.title else ""
            
            # Create page information dictionary
            page_info = {
                "url": url,
                "title": title,
                "status_code": response.status_code,
                "content_type": content_type,
                "size": len(response.content),
                "depth": depth,
                "links": [],
                "forms": [],
                "inputs": []
            }
            
            # Extract links
            links = []
            for a_tag in soup.find_all("a", href=True):
                link_url = a_tag["href"]
                
                # Convert relative URLs to absolute
                if not link_url.startswith(("http://", "https://")):
                    link_url = urllib.parse.urljoin(url, link_url)
                
                # Only follow links to the same domain
                if urllib.parse.urlparse(link_url).netloc == self.domain:
                    links.append(link_url)
            
            page_info["links"] = links
            
            # Extract forms
            forms = []
            for form in soup.find_all("form"):
                form_info = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "get").upper(),
                    "inputs": []
                }
                
                # Extract form inputs
                for input_tag in form.find_all(["input", "textarea", "select"]):
                    input_info = {
                        "name": input_tag.get("name", ""),
                        "type": input_tag.get("type", "text"),
                        "value": input_tag.get("value", "")
                    }
                    form_info["inputs"].append(input_info)
                
                forms.append(form_info)
            
            page_info["forms"] = forms
            
            # Add page to discovered pages
            self.pages.append(page_info)
            logger.debug(f"Crawled {url} (depth {depth})")
            
            # Crawl linked pages in parallel
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                for link in links:
                    executor.submit(self._crawl_page, link, depth + 1)
                    
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error crawling {url}: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error crawling {url}: {str(e)}")
            
    def get_forms(self) -> List[Dict[str, Any]]:
        """
        Get all forms discovered during crawling.
        
        Returns:
            List of forms with page information
        """
        forms = []
        
        for page in self.pages:
            for form in page.get("forms", []):
                form_info = form.copy()
                form_info["page_url"] = page["url"]
                forms.append(form_info)
                
        return forms 