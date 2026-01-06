# backend/main.py - FastAPI Backend
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from dotenv import load_dotenv
load_dotenv()
import os


GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
# ------------------------------------------------------------------
# FastAPI App
# ------------------------------------------------------------------
app = FastAPI(title="Security RAG API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],  # React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------
class QueryRequest(BaseModel):
    query: str
    query_type: str = "advisory"  # "advisory" or "concept"

class SourceInfo(BaseModel):
    type: str
    title: str
    url: Optional[str] = None
    advisory_id: Optional[str] = None

class QueryResponse(BaseModel):
    answer: str
    sources: List[SourceInfo]
    advisory_count: int
    tutorial_count: int

# ------------------------------------------------------------------
# Initialize (on startup)
# ------------------------------------------------------------------
vectorstore = None
llm = None

@app.on_event("startup")
async def startup_event():
    global vectorstore, llm
    
    # Load embeddings
    embeddings = HuggingFaceEmbeddings(
        model_name="all-MiniLM-L6-v2",
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True}
    )
    
    # Load vectorstore
    vectorstore = Chroma(
        persist_directory="./my_cve_db",
        embedding_function=embeddings,
        collection_name="my_vulnerabilities"
    )
    
    # Load LLM
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        temperature=0,
        google_api_key=GOOGLE_API_KEY
    )
    
    print(f"✓ Loaded {vectorstore._collection.count()} documents")

# ------------------------------------------------------------------
# Retrieval Functions
# ------------------------------------------------------------------
def hybrid_retrieve(query: str, k: int = 8):
    """Hybrid retrieval ensuring balanced content"""
    all_results = vectorstore.similarity_search(query, k=k*2)
    
    advisories = [doc for doc in all_results if doc.metadata.get('type') == 'advisory']
    tutorials = [doc for doc in all_results if doc.metadata.get('type') == 'tutorial']
    
    final_docs = []
    
    if query.startswith('GHSA-'):
        final_docs.extend(advisories[:3])
        final_docs.extend(tutorials[:5])
    else:
        final_docs.extend(advisories[:2])
        final_docs.extend(tutorials[:6])
    
    return final_docs[:k]

def format_docs(docs):
    """Format documents for prompt"""
    formatted = []
    
    for doc in docs:
        source_type = doc.metadata.get('type', 'unknown')
        
        if source_type == 'advisory':
            header = f"📋 GitHub Advisory: {doc.metadata.get('advisory_id')}"
        elif source_type == 'tutorial':
            header = f"🎥 Tutorial: {doc.metadata.get('title')}"
        else:
            header = f"📄 {doc.metadata.get('source', 'Unknown')}"
        
        formatted.append(f"{header}\n{'-'*60}\n{doc.page_content}\n")
    
    return "\n".join(formatted)

# ------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------
@app.get("/")
async def root():
    return {
        "message": "Security RAG API",
        "documents": vectorstore._collection.count() if vectorstore else 0
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "vectorstore": vectorstore is not None,
        "llm": llm is not None
    }

@app.post("/query", response_model=QueryResponse)
async def query_vulnerability(request: QueryRequest):
    """Main query endpoint"""
    try:
        # Retrieve documents
        docs = hybrid_retrieve(request.query)
        
        # Count source types
        advisories = [d for d in docs if d.metadata.get('type') == 'advisory']
        tutorials = [d for d in docs if d.metadata.get('type') == 'tutorial']
        
        # Create prompt
        PROMPT = PromptTemplate(
            template="""You are a security expert specializing in vulnerability analysis.

Context from GitHub advisories and YouTube tutorials:
{context}

Question: {question}

IMPORTANT: If GitHub advisory data is present, use it as the PRIMARY source.
Supplement with tutorial content for conceptual understanding.

Provide:
1. What this vulnerability is (technical definition)
2. Why it matters (impact and risks)
3. How to fix it (remediation steps)
4. Additional learning (from tutorials)

Use markdown formatting for better readability.
""",
            input_variables=["context", "question"],
        )
        
        # Generate response
        rag_chain = PROMPT | llm | StrOutputParser()
        
        answer = rag_chain.invoke({
            "context": format_docs(docs),
            "question": request.query
        })
        
        # Format sources
        sources = []
        for doc in docs:
            source_type = doc.metadata.get('type', 'unknown')
            sources.append(SourceInfo(
                type=source_type,
                title=doc.metadata.get('title', doc.metadata.get('advisory_id', 'Unknown')),
                url=doc.metadata.get('url'),
                advisory_id=doc.metadata.get('advisory_id') if source_type == 'advisory' else None
            ))
        
        return QueryResponse(
            answer=answer,
            sources=sources,
            advisory_count=len(advisories),
            tutorial_count=len(tutorials)
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/advisories")
async def list_advisories():
    """List all indexed advisories"""
    results = vectorstore.similarity_search("GHSA", k=20)
    advisories = [
        {
            "id": doc.metadata.get('advisory_id'),
            "package": doc.metadata.get('package'),
            "severity": doc.metadata.get('severity'),
            "url": doc.metadata.get('url')
        }
        for doc in results if doc.metadata.get('type') == 'advisory'
    ]
    return {"advisories": advisories}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)