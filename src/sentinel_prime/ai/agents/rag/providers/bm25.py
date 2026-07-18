import os
import re
import math
import pickle
from typing import List, Dict, Any, Optional, Set

# Stop words list for cleaning lexical queries (Step 3)
STOP_WORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "aren't", "as", "at",
    "be", "because", "been", "before", "being", "below", "between", "both", "but", "by", "can't", "cannot", "could",
    "couldn't", "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during", "each", "few", "for",
    "from", "further", "had", "hadn't", "has", "hasn't", "have", "haven't", "having", "he", "he'd", "he'll", "he's",
    "her", "here", "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i", "i'd", "i'll", "i'm",
    "i've", "if", "in", "into", "is", "isn't", "it", "it's", "its", "itself", "let's", "me", "more", "most", "mustn't",
    "my", "myself", "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our", "ours",
    "ourselves", "out", "over", "own", "same", "shan't", "she", "she'd", "she'll", "she's", "should", "shouldn't",
    "so", "some", "such", "than", "that", "that's", "the", "their", "theirs", "them", "themselves", "then", "there",
    "there's", "these", "they", "they'd", "they'll", "they're", "they've", "this", "those", "through", "to", "too",
    "under", "until", "up", "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've", "were", "weren't",
    "what", "what's", "when", "when's", "where", "where's", "which", "while", "who", "who's", "whom", "why",
    "why's", "with", "won't", "would", "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your", "yours",
    "yourself", "yourselves"
}

def tokenize(text: str) -> List[str]:
    """
    Query normalization tokenizer (Step 3).
    Normalizes query strings, handles lowercase/stop-words, splits tokens, performs basic stemming,
    and preserves critical identifiers like CVEs, technique IDs, domains, and IP addresses.
    """
    if not text:
        return []
        
    text_lower = text.lower()
    
    # regexes to extract and preserve exact identifiers (IOCs, CVEs, Technique IDs)
    patterns = [
        r'\bcve-\d{4}-\d{4,7}\b',              # CVEs (e.g. CVE-2023-38606)
        r'\bt\d{4}(?:\.\d{3})?\b',             # MITRE ATT&CK technique IDs (e.g. T1110, T1059.001)
        r'\bd3-[a-zA-Z0-9_-]+\b',               # MITRE D3FEND IDs (e.g. D3-DNST)
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', # IPv4 addresses
        r'\b[a-f0-9]{32}\b',                    # MD5 hashes
        r'\b[a-f0-9]{64}\b',                    # SHA256 hashes
        r'\b[a-zA-Z0-9._-]+\.[a-zA-Z]{2,6}\b',  # Domain names
        r'\binc-[\w-]+\b',                      # Incident IDs (e.g. INC-2024-089)
        r'\bpb-\d+\b',                          # Playbook IDs (e.g. PB-001)
        r'\bpol-\d+\b'                          # Policy IDs (e.g. POL-001)
    ]
    
    preserved_tokens = []
    cleaned_text = text_lower
    
    for pat in patterns:
        matches = re.findall(pat, cleaned_text)
        preserved_tokens.extend(matches)
        cleaned_text = re.sub(pat, ' ', cleaned_text)
        
    # Standard splitting on non-alphanumeric characters
    cleaned_text = re.sub(r'[^a-zA-Z0-9\s]', ' ', cleaned_text)
    words = cleaned_text.split()
    
    stemmed_tokens = []
    for w in words:
        if w in STOP_WORDS:
            continue
        # Basic suffix stemming
        if len(w) > 4:
            if w.endswith('ing'):
                w = w[:-3]
            elif w.endswith('edly'):
                w = w[:-4]
            elif w.endswith('ed'):
                w = w[:-2]
            elif w.endswith('es') and not w.endswith('aes') and not w.endswith('ees') and not w.endswith('oes'):
                w = w[:-2]
            elif w.endswith('s') and not w.endswith('ss') and not w.endswith('us') and not w.endswith('is'):
                w = w[:-1]
        stemmed_tokens.append(w)
        
    return list(set(preserved_tokens + stemmed_tokens))


class BM25Index:
    """
    Lexical BM25 index supporting document addition, deletion, updates,
    filtering, and serialization (Step 1 & 2).
    """
    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.doc_count = 0
        self.total_doc_len = 0
        self.doc_lengths: Dict[str, int] = {}       # doc_id -> length
        self.df: Dict[str, int] = {}                # term -> doc count containing term
        self.tf: Dict[str, Dict[str, int]] = {}      # doc_id -> {term -> count}
        self.docs: Dict[str, Dict[str, Any]] = {}    # doc_id -> raw document metadata dictionary
        
    def add_document(self, doc_id: str, text: str, doc_metadata: Dict[str, Any]):
        """Indexes or updates a document lexically (Step 2)."""
        if doc_id in self.docs:
            self.remove_document(doc_id)
            
        tokens = tokenize(text)
        if not tokens:
            return
            
        doc_len = len(tokens)
        self.doc_count += 1
        self.total_doc_len += doc_len
        self.doc_lengths[doc_id] = doc_len
        self.docs[doc_id] = doc_metadata
        
        self.tf[doc_id] = {}
        unique_terms = set(tokens)
        for term in tokens:
            self.tf[doc_id][term] = self.tf[doc_id].get(term, 0) + 1
            
        for term in unique_terms:
            self.df[term] = self.df.get(term, 0) + 1
            
    def remove_document(self, doc_id: str):
        """Removes a document from the lexical index (Step 2)."""
        if doc_id not in self.docs:
            return
            
        doc_len = self.doc_lengths.pop(doc_id, 0)
        self.doc_count = max(0, self.doc_count - 1)
        self.total_doc_len = max(0, self.total_doc_len - doc_len)
        self.docs.pop(doc_id, None)
        
        tf_dict = self.tf.pop(doc_id, {})
        for term in tf_dict.keys():
            if term in self.df:
                self.df[term] = max(0, self.df[term] - 1)
                if self.df[term] == 0:
                    self.df.pop(term, None)
                    
    def search(self, query: str, limit: int, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Performs lexical BM25 retrieval with optional metadata filters (Step 5)."""
        query_tokens = tokenize(query)
        if not query_tokens or self.doc_count == 0:
            return []
            
        scores = {}
        avgdl = self.total_doc_len / self.doc_count
        
        for doc_id, doc in self.docs.items():
            if filters and not self._matches_filters(doc, filters):
                continue
                
            score = 0.0
            doc_tf = self.tf.get(doc_id, {})
            doc_len = self.doc_lengths.get(doc_id, 0)
            
            for token in query_tokens:
                if token not in doc_tf:
                    continue
                    
                tf = doc_tf[token]
                df = self.df.get(token, 0)
                
                # Standard BM25 IDF
                idf = math.log((self.doc_count - df + 0.5) / (df + 0.5) + 1.0)
                
                # term frequency scaling
                numerator = tf * (self.k1 + 1.0)
                denominator = tf + self.k1 * (1.0 - self.b + self.b * (doc_len / avgdl))
                score += idf * (numerator / denominator)
                
            if score > 0.0:
                scores[doc_id] = score
                
        # Sort scores in descending order (highest score is best)
        sorted_docs = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:limit]
        
        results = []
        for doc_id, score in sorted_docs:
            res = self.docs[doc_id].copy()
            res["bm25_score"] = score
            results.append(res)
            
        return results
        
    def _matches_filters(self, doc: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        """Helper to match metadata attributes (tags, risk scores, containment status) (Step 2)."""
        for k, val in filters.items():
            doc_val = doc.get(k)
            if isinstance(val, list):
                if isinstance(doc_val, list):
                    if not any(item in doc_val for item in val):
                        return False
                else:
                    if doc_val not in val:
                        return False
            else:
                if isinstance(doc_val, list):
                    if val not in doc_val:
                        return False
                else:
                    if doc_val != val:
                        return False
        return True

    def save(self, filepath: str):
        """Saves the serialized BM25 index state."""
        dir_name = os.path.dirname(filepath)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)
        with open(filepath, "wb") as f:
            pickle.dump(self, f)

    @staticmethod
    def load(filepath: str) -> "BM25Index":
        """Loads a serialized BM25 index state."""
        with open(filepath, "rb") as f:
            return pickle.load(f)
