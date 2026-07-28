import React, { useState } from 'react';
import { Search, Shield, BookOpen, AlertTriangle, ExternalLink, Loader2 } from 'lucide-react';

export default function SecurityRAGApp() {
  const [query, setQuery] = useState('');
  const [queryType, setQueryType] = useState('advisory');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const quickQueries = [
    'GHSA-fr5h-rqp8-mj6g',
    'GHSA-5j98-mcp5-4vw2',
    'GHSA-grv7-fg5c-xmjg',
    'SSRF',
    'Command Injection',
    'Prototype Pollution'
  ];

  const handleSubmit = async () => {
    if (!query.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch(`${import.meta.env.VITE_API_URL}/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          query: query,
          query_type: queryType
        })
      });

      if (!response.ok) {
        throw new Error('Failed to fetch results');
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleQuickQuery = (q) => {
    setQuery(q);
    setQueryType(q.startsWith('GHSA-') ? 'advisory' : 'concept');
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 antialiased selection:bg-zinc-800 selection:text-white">
      <div className="container mx-auto px-4 py-10 max-w-5xl">
        {/* Header */}
        <div className="text-center mb-10">
          <div className="flex items-center justify-center gap-3 mb-3">
            <div className="p-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-zinc-100">
              <Shield className="w-8 h-8 text-zinc-100" />
            </div>
            <h1 className="text-4xl font-bold tracking-tight text-white">Security RAG</h1>
          </div>
          <p className="text-zinc-400 text-sm max-w-md mx-auto">
            Query GitHub Security Advisories & Educational Tutorials
          </p>
        </div>

        {/* Quick Queries */}
        <div className="mb-6">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-3 flex items-center gap-2">
            <BookOpen className="w-3.5 h-3.5 text-zinc-400" />
            Quick Searches
          </h3>
          <div className="flex flex-wrap gap-2">
            {quickQueries.map((q) => (
              <button
                key={q}
                onClick={() => handleQuickQuery(q)}
                className="px-3 py-1.5 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 hover:text-white rounded-lg transition-colors text-xs font-mono font-medium border border-zinc-800"
              >
                {q}
              </button>
            ))}
          </div>
        </div>

        {/* Search Panel */}
        <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 mb-8 shadow-sm">
          <div className="space-y-4">
            <div className="flex gap-6 text-xs font-medium tracking-wide">
              <label className="flex items-center gap-2 cursor-pointer text-zinc-300 hover:text-white transition-colors">
                <input
                  type="radio"
                  value="advisory"
                  checked={queryType === 'advisory'}
                  onChange={(e) => setQueryType(e.target.value)}
                  className="w-4 h-4 accent-white bg-zinc-950 border-zinc-800 focus:ring-0 focus:ring-offset-0"
                />
                <span>GHSA Advisory</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer text-zinc-300 hover:text-white transition-colors">
                <input
                  type="radio"
                  value="concept"
                  checked={queryType === 'concept'}
                  onChange={(e) => setQueryType(e.target.value)}
                  className="w-4 h-4 accent-white bg-zinc-950 border-zinc-800 focus:ring-0 focus:ring-offset-0"
                />
                <span>Security Concept</span>
              </label>
            </div>

            <div className="flex gap-3">
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder={queryType === 'advisory' ? 'e.g., GHSA-fr5h-rqp8-mj6g' : 'e.g., SSRF, command injection'}
                className="flex-1 px-4 py-2.5 bg-zinc-950 border border-zinc-800 rounded-lg text-zinc-100 placeholder-zinc-500 text-sm focus:outline-none focus:border-zinc-600 focus:ring-1 focus:ring-zinc-600 transition-all font-mono"
              />
              <button
                onClick={handleSubmit}
                disabled={loading || !query.trim()}
                className="px-5 py-2.5 bg-zinc-100 hover:bg-white disabled:bg-zinc-800 disabled:text-zinc-600 disabled:cursor-not-allowed text-zinc-950 rounded-lg font-semibold text-sm flex items-center gap-2 transition-all"
              >
                {loading ? (
                  <Loader2 className="w-4 h-4 animate-spin text-zinc-950" />
                ) : (
                  <Search className="w-4 h-4 text-zinc-950" />
                )}
                {loading ? 'Searching...' : 'Search'}
              </button>
            </div>
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div className="bg-red-950/30 border border-red-900/50 rounded-xl p-4 mb-8 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div className="text-sm">
              <h3 className="text-red-400 font-semibold">Error</h3>
              <p className="text-red-300/80">{error}</p>
            </div>
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="space-y-6">
            {/* Metrics */}
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <div className="text-zinc-400 text-xs font-medium uppercase tracking-wider mb-1">Advisories Found</div>
                <div className="text-3xl font-bold text-white font-mono">{result.advisory_count}</div>
              </div>
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                <div className="text-zinc-400 text-xs font-medium uppercase tracking-wider mb-1">Tutorials Found</div>
                <div className="text-3xl font-bold text-white font-mono">{result.tutorial_count}</div>
              </div>
            </div>

            {/* Answer */}
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
              <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2 border-b border-zinc-800 pb-3">
                <Shield className="w-4 h-4 text-zinc-400" />
                Analysis
              </h2>
              <div className="prose prose-invert max-w-none">
                <div className="text-zinc-300 whitespace-pre-wrap leading-relaxed text-sm">
                  {result.answer}
                </div>
              </div>
            </div>

            {/* Sources */}
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
              <h3 className="text-base font-semibold text-white mb-4 flex items-center gap-2 border-b border-zinc-800 pb-3">
                <BookOpen className="w-4 h-4 text-zinc-400" />
                Sources ({result.sources.length})
              </h3>
              <div className="space-y-2.5">
                {result.sources.map((source, idx) => (
                  <div
                    key={idx}
                    className="bg-zinc-950/60 border border-zinc-800/80 rounded-lg p-3.5 hover:border-zinc-700 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">
                            {source.type}
                          </span>
                          <h4 className="font-medium text-zinc-200 text-sm truncate">
                            {source.title}
                          </h4>
                        </div>
                        {source.advisory_id && (
                          <p className="text-zinc-400 font-mono text-xs mt-1">
                            {source.advisory_id}
                          </p>
                        )}
                      </div>
                      {source.url && (
                        <a
                          href={source.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="p-1 text-zinc-500 hover:text-white transition-colors"
                        >
                          <ExternalLink className="w-4 h-4" />
                        </a>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="text-center mt-12 text-zinc-500 text-xs font-mono">
          Powered by LangChain • Google Gemini • ChromaDB
        </div>
      </div>
    </div>
  );
}
