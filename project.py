import os
import json
import time
import requests
from pathlib import Path
from dotenv import load_dotenv

from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api._errors import NoTranscriptFound, TranscriptsDisabled

from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from langchain_google_genai import ChatGoogleGenerativeAI
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import SSLError, RequestException

# ------------------------------------------------------------------
# ENV
# ------------------------------------------------------------------

load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
if not GOOGLE_API_KEY:
    raise RuntimeError("GOOGLE_API_KEY not found in .env")

# ------------------------------------------------------------------
# CONSTANTS
# ------------------------------------------------------------------

# TRANSCRIPT_CACHE = Path("transcript_cache")
# TRANSCRIPT_CACHE.mkdir(exist_ok=True)


conceptual_videos = [
    {"id": "iihd7lo6Ui8", "title": "Path Traversal / Directory Traversal Explained", "advisories": ["GHSA-93m4-6634-74q7"]},
    {"id": "pJwj8d_gZoc", "title": "Path Traversal Explained", "advisories": ["GHSA-93m4-6634-74q7"]},
    {"id": "GeqVMOUugqY", "title": "SSRF (Server Side Request Forgery) Security", "advisories": ["GHSA-fr5h-rqp8-mj6g"]},
    {"id": "eVI0Ny5cZ2c", "title": "SSRF Explained The Cyber Mentor", "advisories": ["GHSA-fr5h-rqp8-mj6g"]},
    {"id": "4qZv_LACsAk", "title": "SSRF Deep Dive  The Cyber Mentor", "advisories": ["GHSA-fr5h-rqp8-mj6g"]},
    {"id": "XSgNXcJUr2Y", "title": "Command Injection Exploit Demonstration", "advisories": ["GHSA-5j98-mcp5-4vw2"]},
    {"id": "N_7-lA6UWHM", "title": "Command Injection Explained  TCM", "advisories": ["GHSA-5j98-mcp5-4vw2"]},
    {"id": "O94ESaJtHtM", "title": "ReDoS / Regex Performance Vulnerabilities", "advisories": ["GHSA-grv7-fg5c-xmjg", "GHSA-968p-4wvh-cqc8"]},
    {"id": "4Wl9Ap8cmqQ", "title": "Prototype Pollution in JavaScript", "advisories": ["GHSA-mh29-5h37-fv8m"]},
    {"id": "MzlZIJjqsVE", "title": "Prototype Pollution Explained (Deep Dive)", "advisories": ["GHSA-mh29-5h37-fv8m"]},
    {"id": "4h8mKzptMzQ", "title": "Client-Side Security Risks & Trust Boundaries", "advisories": ["GHSA-cpj6-fhp6-mr6j"]},
]
def fetch_github_advisory(ghsa_id):
    """Fetch GitHub Security Advisory data"""
    url = f"https://api.github.com/advisories/{ghsa_id}"
    
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract package info more carefully
            package_name = "N/A"
            affected_versions = "N/A"
            
            if data.get('vulnerabilities'):
                vuln = data['vulnerabilities'][0]
                if vuln.get('package'):
                    package_name = vuln['package'].get('name', 'N/A')
                affected_versions = vuln.get('vulnerable_version_range', 'N/A')
            
            # Create DETAILED content with ALL advisory info
            text = f"""GITHUB SECURITY ADVISORY: {ghsa_id}
Advisory ID: {ghsa_id}
GHSA Reference: {ghsa_id}
CVE ID: {data.get('cve_id', 'N/A')}
Package: {package_name}
Severity: {data.get('severity', 'N/A')}
=== VULNERABILITY SUMMARY ===
{data.get('summary', 'N/A')}

=== DETAILED DESCRIPTION ===
{data.get('description', 'N/A')}

=== AFFECTED VERSIONS ===
{affected_versions}

VULNERABILITY CLASS: {ghsa_id}

=== ADVISORY METADATA ===
This is the official GitHub Security Advisory {ghsa_id} for package {package_name}.
Advisory URL: https://github.com/advisories/{ghsa_id}
Published: {data.get('published_at', 'N/A')}
Updated: {data.get('updated_at', 'N/A')}

ADVISORY IDENTIFIER: {ghsa_id}
"""
            
            return Document(
                page_content=text,
                metadata={
                    'source': 'github_advisory',
                    'advisory_id': ghsa_id,
                    'cve_id': data.get('cve_id', 'N/A'),
                    'severity': data.get('severity', 'N/A'),
                    'package': package_name,
                    'url': f"https://github.com/advisories/{ghsa_id}",
                    'type': 'advisory',  # Important for filtering
                    'search_terms': f"{ghsa_id} {package_name} {data.get('summary', '')}"
                }
            )
        else:
            print(f"❌ Error fetching {ghsa_id}: HTTP {response.status_code}")
            return None
            
    except Exception as e:
        print(f"❌ Error with {ghsa_id}: {e}")
        return None

# ------------------------------------------------------------------
# Embeddings
# ------------------------------------------------------------------
print("🔧 Initializing embeddings model...")
embeddings = HuggingFaceEmbeddings(
    model_name="all-MiniLM-L6-v2",
    model_kwargs={"device": "cpu"},
    encode_kwargs={"normalize_embeddings": True}
)

# ------------------------------------------------------------------
# Your REAL vulnerabilities
# ------------------------------------------------------------------
MY_VULNERABILITIES = [
    "GHSA-fr5h-rqp8-mj6g",  # next – SSRF
    "GHSA-5j98-mcp5-4vw2",  # glob – command injection
    "GHSA-cpj6-fhp6-mr6j",  # react-router – data spoofing
    "GHSA-grv7-fg5c-xmjg",  # braces – ReDoS
    "GHSA-mh29-5h37-fv8m",  # js-yaml – prototype pollution
    "GHSA-968p-4wvh-cqc8",  # @babel/helpers – regex complexity
    "GHSA-93m4-6634-74q7"   # vite – path traversal bypass
]


# ------------------------------------------------------------------
# Build Knowledge Base
# ------------------------------------------------------------------
all_docs = []
advisory_count = 0

print("\n" + "="*60)
print("🔐 FETCHING GITHUB SECURITY ADVISORIES")
print("="*60)
for ghsa_id in MY_VULNERABILITIES:
    doc = fetch_github_advisory(ghsa_id)
    if doc:
        all_docs.append(doc)
        advisory_count += 1
        print(f"✓ {ghsa_id} - {doc.metadata.get('package', 'Unknown package')}")
    time.sleep(1)

print("\n" + "="*60)
print("🎥 LOADING YOUTUBE TRANSCRIPTS")
print("="*60)
for video in conceptual_videos:
    try:
        transcript_list = YouTubeTranscriptApi().list(video["id"])
        
        try:
            transcript = transcript_list.find_transcript(['en'])
            transcript_data = transcript.fetch(video["id"])
        except:
            transcript = transcript_list.find_generated_transcript(['en'])
            transcript_data = transcript.fetch(video["id"])
        
        buffer = []
        start_time = 0
        chunk_count = 0
        
        for i, entry in enumerate(transcript_data):
            buffer.append(entry.text)
            
            if (i > 0 and entry.start - start_time >= 60) or i == len(transcript_data) - 1:
                chunk_text = " ".join(buffer)
                
                # Add MUCH MORE context
                context = f"""VIDEO TUTORIAL: {video['title']}
Related Advisories: {', '.join(video['advisories'])}

EDUCATIONAL CONTENT (NOT OFFICIAL ADVISORY):
"""
                
                all_docs.append(
                    Document(
                        page_content=context + chunk_text,
                        metadata={
                            "source": "youtube",
                            "video_id": video["id"],
                            "title": video["title"],
                            "advisories": ", ".join(video["advisories"]),
                            "timestamp": int(start_time),
                            "url": f"https://youtube.com/watch?v={video['id']}&t={int(start_time)}",
                            "type": "tutorial"
                        }
                    )
                )
                
                buffer = []
                start_time = entry.start
                chunk_count += 1
        
        print(f"✓ {video['title']} ({chunk_count} chunks)")
        time.sleep(0.5)
        
    except Exception as e:
        print(f"⚠️ Skipped {video['title']}: {e}")

# ------------------------------------------------------------------
# Create Vector Database
# ------------------------------------------------------------------
print("\n" + "="*60)
print("📦 CREATING VECTOR DATABASE")
print("="*60)

# Count document types
advisory_count = len([d for d in all_docs if d.metadata.get('type') == 'advisory'])
tutorial_count = len([d for d in all_docs if d.metadata.get('type') == 'tutorial'])

print(f"Total documents to index: {len(all_docs)}")
print(f"  - Advisories: {advisory_count}")
print(f"  - Tutorial chunks: {tutorial_count}")

vectorstore = Chroma.from_documents(
    documents=all_docs,
    embedding=embeddings,
    persist_directory="./my_cve_db",
    collection_name="my_vulnerabilities"
)

print("\n✅ KNOWLEDGE BASE BUILT SUCCESSFULLY!")
print(f"✓ Indexed {advisory_count} GitHub advisories")
print(f"✓ Indexed {tutorial_count} tutorial chunks from {len(conceptual_videos)} videos")
print(f"✓ Total searchable documents: {len(all_docs)}")

print(f"\n🧪 TESTING RETRIEVAL...")
test_query = "GHSA-fr5h-rqp8-mj6g"
results = vectorstore.similarity_search(test_query, k=5)

advisory_results = [r for r in results if r.metadata.get('type') == 'advisory']
tutorial_results = [r for r in results if r.metadata.get('type') == 'tutorial']

print(f"   Query: {test_query}")
print(f"   • Advisories found: {len(advisory_results)}")
print(f"   • Tutorials found: {len(tutorial_results)}")

if len(advisory_results) == 0:
    print(f"\n⚠️  WARNING: No advisory found for {test_query}!")
    print(f"   This means embeddings aren't matching properly.")
else:
    print(f"\n✅ Advisory retrieval working correctly!")

print("\n" + "="*60)


# ------------------------------------------------------------------
# Load embeddings (MUST match builder)
# ------------------------------------------------------------------
embeddings = HuggingFaceEmbeddings(
    model_name="all-MiniLM-L6-v2",
    model_kwargs={"device": "cpu"},
    encode_kwargs={"normalize_embeddings": True}
)

# ------------------------------------------------------------------
# Load vector database
# ------------------------------------------------------------------
print("📂 Loading knowledge base...")
vectorstore = Chroma(
    persist_directory="./my_cve_db",
    embedding_function=embeddings,
    collection_name="my_vulnerabilities"
)

print(f"✓ Loaded {vectorstore._collection.count()} documents")

