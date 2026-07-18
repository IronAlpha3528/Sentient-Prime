import os
from typing import Dict, Any, Optional
import sentinel_prime.ai.agents.rag.query as query
from sentinel_prime.ai.agents.rag.providers.attack import AttackProvider
from sentinel_prime.ai.agents.rag.providers.generic import GenericProvider
from sentinel_prime.ai.agents.rag.providers.historical_incident import HistoricalIncidentProvider

def _get_provider(provider_name: str):
    """Retrieves and initializes the target provider instance dynamically (Step 2 & 5)."""
    query.load_resources()
    
    if provider_name == "attack":
        if "attack" not in query._providers:
            query._providers["attack"] = AttackProvider(query.INDEX_DIR)
        return query._providers["attack"]
        
    elif provider_name == "historical_incident":
        if "historical_incident" not in query._providers:
            query._providers["historical_incident"] = HistoricalIncidentProvider(query.INDEX_DIR)
        return query._providers["historical_incident"]
        
    elif provider_name in ["d3fend", "sigma", "yara", "cve", "kev", "playbook", "policy", "threat_report"]:
        if provider_name not in query._providers:
            query._providers[provider_name] = GenericProvider(provider_name, query.INDEX_DIR)
        return query._providers[provider_name]
        
    else:
        raise ValueError(f"Unknown threat intelligence provider: {provider_name}")

def insert_cti_document(provider_name: str, doc: Dict[str, Any]) -> None:
    """Inserts a new threat intelligence document, syncing the index and flushing cache (Step 2)."""
    prov = _get_provider(provider_name)
    prov.insert_document(doc, sync_index=True)
    query._search_cache.clear()

def delete_cti_document(provider_name: str, doc_id: str) -> None:
    """Deletes an existing document by ID, syncing the index and flushing cache (Step 2)."""
    prov = _get_provider(provider_name)
    prov.delete_document(doc_id, sync_index=True)
    query._search_cache.clear()

def update_cti_document(provider_name: str, doc: Dict[str, Any]) -> None:
    """Updates an existing document by ID, syncing the index and flushing cache (Step 2)."""
    prov = _get_provider(provider_name)
    prov.update_document(doc, sync_index=True)
    query._search_cache.clear()

def upsert_cti_document(provider_name: str, doc: Dict[str, Any]) -> None:
    """Upserts a threat intelligence document, syncing the index and flushing cache (Step 2)."""
    prov = _get_provider(provider_name)
    prov.upsert_document(doc, sync_index=True)
    query._search_cache.clear()
