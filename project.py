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

# ------------------------------------------------------------------
# Setup LLM
# ------------------------------------------------------------------
# llm = ChatGoogleGenerativeAI(
#     model="gemini-2.0-flash-exp",
#     temperature=0,
#     google_api_key='AIzaSyDPdK4j1RmCCFHCSdtKCKQfgxooPPAj7PQ'
# )

# ------------------------------------------------------------------
# IMPROVED Retrieval Strategy
# ------------------------------------------------------------------
# def hybrid_retrieve(query: str, k: int = 8):
#     """
#     Hybrid retrieval that ensures we get BOTH advisory and tutorial content
#     """
#     # Get initial results
#     all_results = vectorstore.similarity_search(query, k=k*2)
    
#     # Separate by type
#     advisories = [doc for doc in all_results if doc.metadata.get('type') == 'advisory']
#     tutorials = [doc for doc in all_results if doc.metadata.get('type') == 'tutorial']
    
#     # Ensure balanced mix: at least 2 advisories if they exist
#     final_docs = []
    
#     # Prioritize advisories for GHSA queries
#     if query.startswith('GHSA-'):
#         final_docs.extend(advisories[:3])  # Get top 3 advisories
#         final_docs.extend(tutorials[:5])   # Get top 5 tutorials
#     else:
#         final_docs.extend(advisories[:2])  # Get top 2 advisories
#         final_docs.extend(tutorials[:6])   # Get top 6 tutorials
    
#     return final_docs[:k]

# # ------------------------------------------------------------------
# # Improved RAG Chain
# # ------------------------------------------------------------------
# PROMPT = PromptTemplate(
#     template="""You are a security expert specializing in vulnerability analysis.

# You have been provided with context from TWO sources:
# 1. Official GitHub Security Advisories (GHSA documents)
# 2. Educational YouTube security tutorials

# Context:
# {context}

# Question: {question}

# IMPORTANT INSTRUCTIONS:
# - If GitHub advisory data is present in the context, USE IT as the PRIMARY source
# - The GitHub advisory contains the OFFICIAL vulnerability details, affected packages, and severity
# - Use the YouTube tutorials to SUPPLEMENT with conceptual explanations
# - Always cite which source you're using (GitHub Advisory vs YouTube Tutorial)

# Provide a comprehensive explanation covering:
# 1. **What this vulnerability is** (use GitHub advisory for technical details)
# 2. **Why it matters** (impact and risks from advisory)
# 3. **How to fix it** (remediation steps from advisory and tutorials)
# 4. **Additional learning** (conceptual understanding from tutorials)

# Structure your response clearly and cite your sources.
# """,
#     input_variables=["context", "question"],
# )

# def format_docs(docs):
#     """Format documents with clear source labels"""
#     formatted = []
    
#     for doc in docs:
#         source_type = doc.metadata.get('type', 'unknown')
        
#         if source_type == 'advisory':
#             header = f"📋 SOURCE: GitHub Security Advisory ({doc.metadata.get('advisory_id')})"
#         elif source_type == 'tutorial':
#             header = f"🎥 SOURCE: YouTube Tutorial - {doc.metadata.get('title')}"
#         else:
#             header = f"📄 SOURCE: {doc.metadata.get('source', 'Unknown')}"
        
#         formatted.append(f"{header}\n{'-'*60}\n{doc.page_content}\n")
    
#     return "\n".join(formatted)

# rag_chain = (
#     {"context": lambda x: format_docs(hybrid_retrieve(x)), "question": RunnablePassthrough()}
#     | PROMPT
#     | llm
#     | StrOutputParser()
# )

# ------------------------------------------------------------------
# Query Functions
# ------------------------------------------------------------------
# def explain_cve(cve_id: str) -> str:
#     """Explain a CVE/GHSA vulnerability"""
#     print(f"\n🔍 Searching for {cve_id}...")
    
#     docs = hybrid_retrieve(cve_id)
    
#     print(f"Found {len(docs)} relevant documents:")
#     for doc in docs:
#         source_type = doc.metadata.get('type', 'unknown')
#         if source_type == 'advisory':
#             print(f"  📋 Advisory: {doc.metadata.get('advisory_id')}")
#         else:
#             print(f"  🎥 Tutorial: {doc.metadata.get('title')}")
    
#     return rag_chain.invoke(cve_id)

# def query_security_topic(topic: str) -> str:
#     """Query about general security topics"""
#     print(f"\n🔍 Searching for: {topic}...")
    
#     docs = hybrid_retrieve(topic)
#     print(f"Found {len(docs)} relevant documents")
    
#     return rag_chain.invoke(f"Explain {topic} in cybersecurity context with practical examples.")

# # ------------------------------------------------------------------
# # Test Queries
# # ------------------------------------------------------------------
# if __name__ == "__main__":
#     print("\n" + "="*60)
#     print("TESTING RAG SYSTEM")
#     print("="*60)
    
#     # Test 1: GHSA query
#     print("\n📋 Test 1: GHSA-5j98-mcp5-4vw2")
#     result = explain_cve("GHSA-5j98-mcp5-4vw2")
#     print(result)
    
#     # Test 2: Concept query
#     print("\n" + "="*60)
#     print("\n📋 Test 2: SSRF")
#     result = query_security_topic("SSRF server side request forgery")
#     print(result)
    
#     # Test 3: Another GHSA
#     print("\n" + "="*60)
#     print("\n📋 Test 3: GHSA-fr5h-rqp8-mj6g")
#     result = explain_cve("GHSA-fr5h-rqp8-mj6g")
#     print(result)


# ------------------------------------------------------------------
# BUILD DOCUMENTS
# ------------------------------------------------------------------

# documents: list[Document] = []

# print("🔐 Fetching GitHub advisories...")
# for ghsa in MY_VULNERABILITIES:
#     doc = fetch_github_advisory(ghsa)
#     if doc:
#         documents.append(doc)
#         print(f"✓ {ghsa}")
#     time.sleep(1)

# print("\n🎥 Fetching & caching YouTube transcripts...")
# successful_videos = 0
# for video in conceptual_videos:
#     text = get_transcript(video["id"])
#     if not text:
#         print(f"⚠️ Skipped {video['title']}")
#         continue

#     documents.append(
#         Document(
#             page_content=text,
#             metadata={
#                 "source": "youtube",
#                 "title": video["title"],
#                 "video_id": video["id"],
#                 "advisories": ", ".join(video["advisories"]),
#                 "url": f"https://youtube.com/watch?v={video['id']}",
#             },
#         )
#     )
#     print(f"✓ {video['title']}")
#     successful_videos += 1

# print(f"\n📊 Retrieved {len(documents)} total documents ({len(MY_VULNERABILITIES)} advisories + {successful_videos} videos)")

# # ------------------------------------------------------------------
# # VECTOR STORE
# # ------------------------------------------------------------------

# if documents:
#     print("\n🧠 Creating vector store...")
#     vectorstore = Chroma.from_documents(
#         documents=documents,
#         embedding=embeddings,
#         persist_directory="./my_cve_db",
#         collection_name="my_vulnerabilities",
#     )
#     retriever = vectorstore.as_retriever(search_kwargs={"k": 3})
#     print("✅ Vector store created successfully!")
# else:
#     print("❌ No documents to create vector store!")
#     retriever = None


# def check_transcript_quality():
#     """Check cached transcript quality"""
#     print("\n🔍 CHECKING TRANSCRIPT QUALITY")
#     print("=" * 50)
    
#     successful_videos = []
#     for video in conceptual_videos:
#         cache_file = TRANSCRIPT_CACHE / f"{video['id']}.json"
#         if cache_file.exists():
#             try:
#                 text = json.loads(cache_file.read_text())
#                 lines = text.split('\n')
#                 word_count = len(text.split())
#                 print(f"\n📹 {video['title']} (ID: {video['id']})")
#                 print(f"   Words: {word_count}, Lines: {len(lines)}")
#                 print(f"   First 100 chars: {text[:100]}...")
#                 successful_videos.append(video['id'])
#             except Exception as e:
#                 print(f"❌ Error reading {video['id']}: {e}")
#         else:
#             print(f"📭 No cache for {video['title']}")
    
#     print(f"\n✅ Successfully cached: {len(successful_videos)}/{len(conceptual_videos)} videos")
#     return successful_videos

# # ------------------------------------------------------------------
# # LLM - CORRECTED MODEL NAME
# # ------------------------------------------------------------------

# llm = ChatGoogleGenerativeAI(
#     model="gemini-2.5-flash",  # Corrected from "gemini-1.5-flash-latest"
#     temperature=0,
#     google_api_key=GOOGLE_API_KEY
# )

# # ------------------------------------------------------------------
# # RAG CHAIN
# # ------------------------------------------------------------------

# if retriever:
#     PROMPT = PromptTemplate(
#         template="""
# You are a security expert specializing in vulnerability analysis.

# Context from GitHub advisories and YouTube security tutorials:
# {context}

# Question:
# {question}

# Provide a comprehensive explanation covering:
# 1. What this vulnerability is (technical definition)
# 2. Why it matters (potential impact and risks)
# 3. How to fix or prevent it (specific remediation steps)
# 4. Additional context from the video tutorials if available

# Answer in a clear, structured format suitable for security professionals.
# """,
#         input_variables=["context", "question"],
#     )

#     rag_chain = (
#         {"context": retriever, "question": RunnablePassthrough()}
#         | PROMPT
#         | llm
#         | StrOutputParser()
#     )

#     def explain_cve(cve_id: str) -> str:
#         """Explain a CVE/GHSA vulnerability using RAG"""
#         return rag_chain.invoke(f"Explain {cve_id} and how to fix it.")

#     def query_security_topic(topic: str) -> str:
#         """Query about general security topics"""
#         return rag_chain.invoke(f"Explain {topic} in cybersecurity context.")
# else:
#     def explain_cve(cve_id: str) -> str:
#         return f"Error: No documents available for RAG. Could not process {cve_id}"
    
#     def query_security_topic(topic: str) -> str:
#         return f"Error: No documents available for RAG. Could not process {topic}"

# # ------------------------------------------------------------------
# # TEST
# # ------------------------------------------------------------------

# if __name__ == "__main__":
#     print("\n" + "=" * 70)
#     print("SECURITY VULNERABILITY RAG SYSTEM - INITIALIZATION COMPLETE")
#     print("=" * 70)
    
#     if retriever:
#         print("\n🧪 Running tests...")
        
#         # Test 1: GHSA vulnerability
#         print("\n1. Testing GHSA advisory explanation:")
#         print("-" * 40)
#         try:
#             result = explain_cve("GHSA-fr5h-rqp8-mj6g")
#             print(result[:500] + "..." if len(result) > 500 else result)
#         except Exception as e:
#             print(f"❌ Test failed: {type(e).__name__}: {e}")
        
#         # Test 2: Another vulnerability
#         print("\n2. Testing another GHSA advisory:")
#         print("-" * 40)
#         try:
#             result = explain_cve("GHSA-5j98-mcp5-4vw2")
#             print(result[:300] + "..." if len(result) > 300 else result)
#         except Exception as e:
#             print(f"❌ Test failed: {type(e).__name__}: {e}")
        
#         # Test 3: General security topic
#         print("\n3. Testing general security topic:")
#         print("-" * 40)
#         try:
#             result = query_security_topic("SSRF attacks")
#             print(result[:300] + "..." if len(result) > 300 else result)
#         except Exception as e:
#             print(f"❌ Test failed: {type(e).__name__}: {e}")
        
#         print("\n" + "=" * 70)
#         print("✅ System ready! You can now use:")
#         print("   - explain_cve('GHSA-xxxx-xxxx') for specific advisories")
#         print("   - query_security_topic('topic') for general security questions")
#         print("=" * 70)
#     else:
#         print("\n❌ System initialization failed. No vector store created.")
#         print("Check if any transcripts were successfully fetched.")


# ------------------------------------------------------------------
# FETCH GITHUB ADVISORY
# ------------------------------------------------------------------

# def fetch_github_advisory(ghsa_id: str):
#     url = f"https://api.github.com/advisories/{ghsa_id}"

#     headers = {
#         "Accept": "application/vnd.github+json",
#         "X-GitHub-Api-Version": "2022-11-28",
#         "User-Agent": "cve-rag-bot"
#     }

#     session = requests.Session()
#     retries = Retry(
#         total=5,
#         backoff_factor=1,
#         status_forcelist=[429, 500, 502, 503, 504],
#         allowed_methods=["GET"],
#         raise_on_status=False,
#     )
#     adapter = HTTPAdapter(max_retries=retries)
#     session.mount("https://", adapter)

#     try:
#         r = session.get(url, headers=headers, timeout=10)
#         if r.status_code != 200:
#             print(f"⚠️ Skipped {ghsa_id} (HTTP {r.status_code})")
#             return None

#         data = r.json()

#         content = f"""
# Advisory ID: {ghsa_id}
# Summary: {data.get('summary')}
# Description: {data.get('description')}
# Severity: {data.get('severity')}
# Package: {data.get('package', {}).get('name')}
# Affected Versions: {data.get('vulnerable_version_range')}
# Patched Versions: {data.get('patched_versions')}
# """

#         return Document(
#             page_content=content.strip(),
#             metadata={
#                 "source": "github",
#                 "advisory_id": ghsa_id,
#                 "url": f"https://github.com/advisories/{ghsa_id}",
#             },
#         )

#     except SSLError as e:
#         print(f"⚠️ SSL error for {ghsa_id}, skipping safely")
#         return None

#     except RequestException as e:
#         print(f"⚠️ Network error for {ghsa_id}, skipping safely")
#         return None

# # ------------------------------------------------------------------
# # 🔴 UPDATED: CORRECT TRANSCRIPT FETCH USING CURRENT API
# # ------------------------------------------------------------------

# def get_transcript(video_id: str) -> str | None:
#     """Fetch transcript using the updated API format from PyPI docs"""
#     cache_file = TRANSCRIPT_CACHE / f"{video_id}.json"
    
#     # Return cached transcript if available
#     if cache_file.exists():
#         print(f"📁 Using cached transcript for {video_id}")
#         return json.loads(cache_file.read_text())

#     try:
#         # Initialize API client
#         ytt_api = YouTubeTranscriptApi()
        
#         # Method 1: Try direct fetch (preferred method from PyPI docs)
#         try:
#             fetched_transcript = ytt_api.fetch(video_id, languages=['en'])
#             text = "\n".join([snippet.text for snippet in fetched_transcript])
            
#         except (NoTranscriptFound, TranscriptsDisabled):
#             # Method 2: List available transcripts and find English
#             transcript_list = ytt_api.list(video_id)
            
#             try:
#                 # Try to find English transcript (manual or auto-generated)
#                 transcript = transcript_list.find_transcript(['en'])
#                 fetched_transcript = transcript.fetch()
#                 text = "\n".join([snippet.text for snippet in fetched_transcript])
                
#             except NoTranscriptFound:
#                 # Method 3: Try Hindi auto-generated and translate to English
#                 try:
#                     hindi_transcript = transcript_list.find_generated_transcript(['hi'])
#                     translated = hindi_transcript.translate('en')
#                     fetched_transcript = translated.fetch()
#                     text = "\n".join([snippet.text for snippet in fetched_transcript])
                    
#                 except Exception as e:
#                     print(f"⚠️ No English or Hindi transcript available for {video_id}")
#                     return None

#         # Cache the result
#         cache_file.write_text(json.dumps(text))
#         print(f"✅ Successfully fetched and cached transcript for {video_id}")
#         time.sleep(1)  # Respectful delay between requests
#         return text

#     except Exception as e:
#         print(f"❌ Error fetching transcript for {video_id}: {type(e).__name__}: {str(e)[:100]}...")
#         return None
