"""
Advanced response comparison engine for SQLi detection.
"""
import hashlib
import difflib
import re
from typing import Dict, Tuple, List, Optional, Set
import json
from dataclasses import dataclass
import numpy as np
from collections import Counter
import zlib

@dataclass
class ComparisonResult:
    """Result of response comparison"""
    similarity_score: float  # 0.0 to 1.0
    is_significantly_different: bool
    difference_type: str  # 'content', 'structure', 'status', 'headers', 'mixed'
    details: Dict[str, any]
    confidence: float

class ResponseComparator:
    """
    Advanced comparator for HTTP responses using multiple strategies.
    """
    
    def __init__(
        self,
        content_similarity_threshold: float = 0.85,
        structure_similarity_threshold: float = 0.90,
        min_content_length: int = 50,
        ignore_patterns: List[str] = None
    ):
        """
        Initialize the response comparator.
        
        Args:
            content_similarity_threshold: Threshold for content similarity
            structure_similarity_threshold: Threshold for structure similarity
            min_content_length: Minimum content length to analyze
            ignore_patterns: Regex patterns to ignore in comparison
        """
        self.content_threshold = content_similarity_threshold
        self.structure_threshold = structure_similarity_threshold
        self.min_content_length = min_content_length
        
        self.ignore_patterns = ignore_patterns or [
            r'\b\d{10,}\b',  # Long numbers (timestamps, etc.)
            r'csrf_token=[A-Za-z0-9+/=]+',  # CSRF tokens
            r'session_id=[A-Za-z0-9]+',
            r'timestamp=\d+',
            r'nonce=[A-Za-z0-9]+',
        ]
        
        # Compile ignore patterns
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.ignore_patterns]
    
    def normalize_content(self, content: str) -> str:
        """
        Normalize content by removing variable data.
        
        Args:
            content: Raw content string
            
        Returns:
            Normalized content
        """
        if not content:
            return ""
        
        normalized = content
        
        # Remove ignored patterns
        for pattern in self.compiled_patterns:
            normalized = pattern.sub('[REMOVED]', normalized)
        
        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', normalized)
        
        # Remove HTML comments
        normalized = re.sub(r'<!--.*?-->', '', normalized, flags=re.DOTALL)
        
        # Remove script and style tags content
        normalized = re.sub(r'<script[^>]*>.*?</script>', '<script>[REMOVED]</script>', 
                          normalized, flags=re.DOTALL | re.IGNORECASE)
        normalized = re.sub(r'<style[^>]*>.*?</style>', '<style>[REMOVED]</style>', 
                          normalized, flags=re.DOTALL | re.IGNORECASE)
        
        return normalized.strip()
    
    def calculate_content_fingerprint(self, content: str) -> Dict[str, any]:
        """
        Create a fingerprint of content for comparison.
        
        Args:
            content: Content string
            
        Returns:
            Fingerprint dictionary
        """
        normalized = self.normalize_content(content)
        
        return {
            'md5': hashlib.md5(normalized.encode()).hexdigest(),
            'sha256': hashlib.sha256(normalized.encode()).hexdigest(),
            'length': len(normalized),
            'line_count': len(normalized.split('\n')),
            'word_count': len(re.findall(r'\b\w+\b', normalized)),
            'char_distribution': self.get_char_distribution(normalized),
            'shingles': self.create_shingles(normalized),
        }
    
    def get_char_distribution(self, text: str, top_n: int = 10) -> Dict[str, float]:
        """
        Get character distribution of text.
        
        Args:
            text: Input text
            top_n: Number of top characters to return
            
        Returns:
            Dictionary of character frequencies
        """
        if not text:
            return {}
        
        # Count characters
        char_counts = Counter(text.lower())
        total_chars = sum(char_counts.values())
        
        # Calculate frequencies for top N characters
        top_chars = char_counts.most_common(top_n)
        distribution = {char: count/total_chars for char, count in top_chars}
        
        return distribution
    
    def create_shingles(self, text: str, k: int = 5) -> Set[str]:
        """
        Create k-shingles (n-grams) from text for similarity comparison.
        
        Args:
            text: Input text
            k: Shingle size
            
        Returns:
            Set of shingles
        """
        if len(text) < k:
            return {text}
        
        shingles = set()
        for i in range(len(text) - k + 1):
            shingle = text[i:i + k]
            shingles.add(shingle)
        
        return shingles
    
    def jaccard_similarity(self, set1: Set, set2: Set) -> float:
        """
        Calculate Jaccard similarity between two sets.
        
        Args:
            set1: First set
            set2: Second set
            
        Returns:
            Jaccard similarity (0.0 to 1.0)
        """
        if not set1 and not set2:
            return 1.0
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def compare_fingerprints(self, fp1: Dict, fp2: Dict) -> Dict[str, float]:
        """
        Compare two content fingerprints.
        
        Args:
            fp1: First fingerprint
            fp2: Second fingerprint
            
        Returns:
            Dictionary of similarity scores
        """
        similarities = {}
        
        # Hash similarity (exact match)
        similarities['hash_exact'] = 1.0 if fp1['md5'] == fp2['md5'] else 0.0
        
        # Length similarity
        if fp1['length'] == 0 or fp2['length'] == 0:
            similarities['length'] = 0.0
        else:
            diff = abs(fp1['length'] - fp2['length'])
            max_len = max(fp1['length'], fp2['length'])
            similarities['length'] = 1.0 - (diff / max_len)
        
        # Word count similarity
        if fp1['word_count'] == 0 or fp2['word_count'] == 0:
            similarities['word_count'] = 0.0
        else:
            diff = abs(fp1['word_count'] - fp2['word_count'])
            max_words = max(fp1['word_count'], fp2['word_count'])
            similarities['word_count'] = 1.0 - (diff / max_words)
        
        # Shingle similarity (Jaccard)
        shingle_sim = self.jaccard_similarity(fp1['shingles'], fp2['shingles'])
        similarities['shingle'] = shingle_sim
        
        # Character distribution similarity
        char_sim = self.compare_char_distributions(fp1['char_distribution'], fp2['char_distribution'])
        similarities['char_distribution'] = char_sim
        
        # Calculate weighted overall similarity
        weights = {
            'hash_exact': 0.3,
            'length': 0.2,
            'word_count': 0.1,
            'shingle': 0.3,
            'char_distribution': 0.1,
        }
        
        overall = sum(similarities[key] * weights[key] for key in weights)
        similarities['overall'] = overall
        
        return similarities
    
    def compare_char_distributions(self, dist1: Dict, dist2: Dict) -> float:
        """
        Compare character distributions using cosine similarity.
        
        Args:
            dist1: First character distribution
            dist2: Second character distribution
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        if not dist1 or not dist2:
            return 0.0
        
        # Get all unique characters
        all_chars = set(dist1.keys()).union(set(dist2.keys()))
        
        # Create vectors
        vec1 = [dist1.get(char, 0) for char in all_chars]
        vec2 = [dist2.get(char, 0) for char in all_chars]
        
        # Calculate cosine similarity
        dot_product = sum(v1 * v2 for v1, v2 in zip(vec1, vec2))
        norm1 = np.sqrt(sum(v * v for v in vec1))
        norm2 = np.sqrt(sum(v * v for v in vec2))
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)
    
    def analyze_html_structure(self, html: str) -> Dict[str, any]:
        """
        Analyze HTML structure for comparison.
        
        Args:
            html: HTML content
            
        Returns:
            Structure analysis dictionary
        """
        structure = {
            'tag_counts': {},
            'tag_nesting': 0,
            'form_count': 0,
            'input_count': 0,
            'link_count': 0,
            'depth': 0,
        }
        
        if not html or '<' not in html:
            return structure
        
        # Count tags
        tags = re.findall(r'</?(\w+)[^>]*>', html)
        tag_counter = Counter(tags)
        structure['tag_counts'] = dict(tag_counter)
        
        # Count specific elements
        structure['form_count'] = html.count('<form')
        structure['input_count'] = html.count('<input')
        structure['link_count'] = html.count('<a ')
        
        # Estimate nesting depth
        depth = 0
        max_depth = 0
        stack = []
        
        # Simple tag matching (for depth estimation)
        tag_pattern = re.compile(r'</?(\w+)[^>]*>')
        for match in tag_pattern.finditer(html):
            tag = match.group(0)
            if tag.startswith('</'):  # Closing tag
                if stack:
                    stack.pop()
                    depth -= 1
            elif not tag.endswith('/>'):  # Opening tag (not self-closing)
                stack.append(tag)
                depth += 1
                max_depth = max(max_depth, depth)
        
        structure['depth'] = max_depth
        structure['tag_nesting'] = len(stack)
        
        return structure
    
    def compare_structures(self, struct1: Dict, struct2: Dict) -> Dict[str, float]:
        """
        Compare HTML structures.
        
        Args:
            struct1: First structure analysis
            struct2: Second structure analysis
            
        Returns:
            Dictionary of similarity scores
        """
        similarities = {}
        
        # Compare tag counts
        all_tags = set(struct1['tag_counts'].keys()).union(set(struct2['tag_counts'].keys()))
        tag_vectors = []
        
        for tags in [struct1['tag_counts'], struct2['tag_counts']]:
            vec = [tags.get(tag, 0) for tag in all_tags]
            tag_vectors.append(vec)
        
        # Cosine similarity for tag vectors
        dot_product = sum(v1 * v2 for v1, v2 in zip(tag_vectors[0], tag_vectors[1]))
        norm1 = np.sqrt(sum(v * v for v in tag_vectors[0]))
        norm2 = np.sqrt(sum(v * v for v in tag_vectors[1]))
        
        if norm1 > 0 and norm2 > 0:
            similarities['tag_distribution'] = dot_product / (norm1 * norm2)
        else:
            similarities['tag_distribution'] = 0.0
        
        # Compare specific counts
        for key in ['form_count', 'input_count', 'link_count']:
            val1 = struct1.get(key, 0)
            val2 = struct2.get(key, 0)
            
            if val1 == 0 and val2 == 0:
                similarities[key] = 1.0
            else:
                max_val = max(val1, val2)
                similarities[key] = 1.0 - (abs(val1 - val2) / max_val)
        
        # Compare depth
        depth1 = struct1.get('depth', 0)
        depth2 = struct2.get('depth', 0)
        
        if depth1 == 0 and depth2 == 0:
            similarities['depth'] = 1.0
        else:
            max_depth = max(depth1, depth2)
            similarities['depth'] = 1.0 - (abs(depth1 - depth2) / max_depth)
        
        # Calculate overall structure similarity
        weights = {
            'tag_distribution': 0.4,
            'form_count': 0.2,
            'input_count': 0.2,
            'link_count': 0.1,
            'depth': 0.1,
        }
        
        overall = sum(similarities[key] * weights[key] for key in weights)
        similarities['overall'] = overall
        
        return similarities
    
    def detect_sql_indicators(self, content: str) -> Dict[str, any]:
        """
        Detect SQL-related indicators in response.
        
        Args:
            content: Response content
            
        Returns:
            Dictionary of detected indicators
        """
        indicators = {
            'sql_errors': [],
            'database_errors': [],
            'syntax_indicators': [],
            'boolean_indicators': [],
        }
        
        content_lower = content.lower()
        
        # SQL Error patterns
        sql_error_patterns = [
            (r"sql syntax.*error", "sql_syntax"),
            (r"mysql.*error", "mysql"),
            (r"postgresql.*error", "postgresql"),
            (r"microsoft.*sql.*server", "mssql"),
            (r"ora-\d+", "oracle"),
            (r"warning.*mysql", "mysql_warning"),
            (r"unclosed quotation mark", "quotation"),
            (r"division by zero", "division_zero"),
        ]
        
        for pattern, error_type in sql_error_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                if error_type.startswith('sql_'):
                    indicators['sql_errors'].append(error_type)
                else:
                    indicators['database_errors'].append(error_type)
        
        # Syntax indicators (changes in SQL structure)
        syntax_patterns = [
            r"order\s+by",
            r"group\s+by",
            r"union\s+select",
            r"select\s+.*from",
            r"insert\s+into",
            r"update\s+.*set",
            r"delete\s+from",
        ]
        
        for pattern in syntax_patterns:
            if re.search(pattern, content_lower):
                indicators['syntax_indicators'].append(pattern)
        
        # Boolean indicators (content differences)
        boolean_keywords = [
            "welcome", "login successful", "access granted",
            "error", "invalid", "access denied", "not found",
        ]
        
        for keyword in boolean_keywords:
            if keyword in content_lower:
                indicators['boolean_indicators'].append(keyword)
        
        return indicators
    
    def compare_responses(
        self,
        response1_text: str,
        response1_status: int,
        response2_text: str,
        response2_status: int
    ) -> ComparisonResult:
        """
        Compare two HTTP responses comprehensively.
        
        Args:
            response1_text: First response content
            response1_status: First response status code
            response2_text: Second response content
            response2_status: Second response status code
            
        Returns:
            ComparisonResult object
        """
        # Quick checks
        if response1_text == response2_text and response1_status == response2_status:
            return ComparisonResult(
                similarity_score=1.0,
                is_significantly_different=False,
                difference_type='identical',
                details={'reason': 'Responses are identical'},
                confidence=1.0
            )
        
        # Step 1: Basic comparison
        status_different = response1_status != response2_status
        
        # Step 2: Content fingerprinting and comparison
        fp1 = self.calculate_content_fingerprint(response1_text)
        fp2 = self.calculate_content_fingerprint(response2_text)
        content_similarity = self.compare_fingerprints(fp1, fp2)
        
        # Step 3: HTML structure analysis (if HTML)
        struct1 = self.analyze_html_structure(response1_text)
        struct2 = self.analyze_html_structure(response2_text)
        structure_similarity = self.compare_structures(struct1, struct2)
        
        # Step 4: Detect SQL indicators
        indicators1 = self.detect_sql_indicators(response1_text)
        indicators2 = self.detect_sql_indicators(response2_text)
        
        # Calculate overall similarity (weighted)
        content_weight = 0.6
        structure_weight = 0.3
        status_weight = 0.1
        
        overall_similarity = (
            content_similarity['overall'] * content_weight +
            structure_similarity['overall'] * structure_weight +
            (1.0 if not status_different else 0.0) * status_weight
        )
        
        # Determine if significantly different
        is_significantly_different = overall_similarity < self.content_threshold
        
        # Determine difference type
        difference_type = 'identical'
        if is_significantly_different:
            if content_similarity['overall'] < self.content_threshold:
                if structure_similarity['overall'] < self.structure_threshold:
                    difference_type = 'structure'
                else:
                    difference_type = 'content'
            elif status_different:
                difference_type = 'status'
            else:
                difference_type = 'mixed'
        
        # Calculate confidence
        confidence = 0.0
        if difference_type != 'identical':
            # Higher confidence for larger differences
            confidence = 1.0 - overall_similarity
            
            # Boost confidence if SQL indicators are present
            if indicators1['sql_errors'] or indicators2['sql_errors']:
                confidence = min(confidence + 0.2, 0.95)
            
            # Boost confidence for status code differences
            if status_different:
                confidence = min(confidence + 0.15, 0.95)
        
        # Prepare details
        details = {
            'status_different': status_different,
            'content_similarity': content_similarity['overall'],
            'structure_similarity': structure_similarity['overall'],
            'overall_similarity': overall_similarity,
            'indicators_response1': indicators1,
            'indicators_response2': indicators2,
            'content_lengths': {
                'response1': len(response1_text),
                'response2': len(response2_text),
            },
            'normalized_hashes': {
                'response1': fp1['md5'][:16],
                'response2': fp2['md5'][:16],
            }
        }
        
        return ComparisonResult(
            similarity_score=overall_similarity,
            is_significantly_different=is_significantly_different,
            difference_type=difference_type,
            details=details,
            confidence=confidence
        )

# Test function
def test_response_comparator():
    """Test the response comparator"""
    comparator = ResponseComparator()
    
    # Test cases
    test_cases = [
        {
            'name': 'Identical responses',
            'resp1': '<html><body>Hello World</body></html>',
            'resp2': '<html><body>Hello World</body></html>',
            'status1': 200,
            'status2': 200,
        },
        {
            'name': 'Different content',
            'resp1': '<html><body>Welcome User</body></html>',
            'resp2': '<html><body>Access Denied</body></html>',
            'status1': 200,
            'status2': 200,
        },
        {
            'name': 'Different status',
            'resp1': '<html><body>Page</body></html>',
            'resp2': '<html><body>Page</body></html>',
            'status1': 200,
            'status2': 404,
        },
        {
            'name': 'SQL error in response',
            'resp1': '<html><body>Welcome</body></html>',
            'resp2': '<html><body>SQL syntax error near SELECT</body></html>',
            'status1': 200,
            'status2': 200,
        },
    ]
    
    print("Testing Response Comparator:")
    print("=" * 80)
    
    for test in test_cases:
        result = comparator.compare_responses(
            test['resp1'], test['status1'],
            test['resp2'], test['status2']
        )
        
        print(f"\nTest: {test['name']}")
        print(f"  Similarity: {result.similarity_score:.3f}")
        print(f"  Different: {result.is_significantly_different}")
        print(f"  Type: {result.difference_type}")
        print(f"  Confidence: {result.confidence:.3f}")
        
        if result.details.get('indicators_response1', {}).get('sql_errors'):
            print(f"  SQL Errors in R1: {result.details['indicators_response1']['sql_errors']}")
        if result.details.get('indicators_response2', {}).get('sql_errors'):
            print(f"  SQL Errors in R2: {result.details['indicators_response2']['sql_errors']}")

if __name__ == "__main__":
    test_response_comparator()