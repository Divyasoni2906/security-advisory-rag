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
      const response = await fetch('http://localhost:8000/query', {
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
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      <div className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="w-12 h-12 text-purple-400" />
            <h1 className="text-5xl font-bold text-white">Security RAG</h1>
          </div>
          <p className="text-purple-200 text-lg">
            Query GitHub Security Advisories & Educational Tutorials
          </p>
        </div>

        {/* Quick Queries */}
        <div className="mb-8">
          <h3 className="text-white text-sm font-semibold mb-3 flex items-center gap-2">
            <BookOpen className="w-4 h-4" />
            Quick Searches
          </h3>
          <div className="flex flex-wrap gap-2">
            {quickQueries.map((q) => (
              <button
                key={q}
                onClick={() => handleQuickQuery(q)}
                className="px-4 py-2 bg-purple-800/50 hover:bg-purple-700/50 text-purple-100 rounded-lg transition-colors text-sm font-medium border border-purple-600/30"
              >
                {q}
              </button>
            ))}
          </div>
        </div>

        {/* Search Panel */}
        <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-6 mb-8 border border-white/20">
          <div className="space-y-4">
            <div className="flex gap-4 mb-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  value="advisory"
                  checked={queryType === 'advisory'}
                  onChange={(e) => setQueryType(e.target.value)}
                  className="w-4 h-4"
                />
                <span className="text-white">🔍 GHSA Advisory</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  value="concept"
                  checked={queryType === 'concept'}
                  onChange={(e) => setQueryType(e.target.value)}
                  className="w-4 h-4"
                />
                <span className="text-white">💡 Security Concept</span>
              </label>
            </div>

            <div className="flex gap-3">
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder={queryType === 'advisory' ? 'e.g., GHSA-fr5h-rqp8-mj6g' : 'e.g., SSRF, command injection'}
                className="flex-1 px-4 py-3 bg-white/20 border border-white/30 rounded-xl text-white placeholder-purple-200 focus:outline-none focus:ring-2 focus:ring-purple-400"
              />
              <button
                onClick={handleSubmit}
                disabled={loading || !query.trim()}
                className="px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-xl font-semibold flex items-center gap-2 transition-colors"
              >
                {loading ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <Search className="w-5 h-5" />
                )}
                {loading ? 'Searching...' : 'Search'}
              </button>
            </div>
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div className="bg-red-500/20 border border-red-500/50 rounded-xl p-4 mb-8 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="text-red-400 font-semibold">Error</h3>
              <p className="text-red-200">{error}</p>
            </div>
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="space-y-6">
            {/* Metrics */}
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-blue-500/20 border border-blue-500/30 rounded-xl p-4">
                <div className="text-blue-200 text-sm mb-1">📋 Advisories Found</div>
                <div className="text-3xl font-bold text-white">{result.advisory_count}</div>
              </div>
              <div className="bg-green-500/20 border border-green-500/30 rounded-xl p-4">
                <div className="text-green-200 text-sm mb-1">🎥 Tutorials Found</div>
                <div className="text-3xl font-bold text-white">{result.tutorial_count}</div>
              </div>
            </div>

            {/* Answer */}
            <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-6 border border-white/20">
              <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                <Shield className="w-6 h-6 text-purple-400" />
                Analysis
              </h2>
              <div className="prose prose-invert max-w-none">
                <div className="text-purple-100 whitespace-pre-wrap leading-relaxed">
                  {result.answer}
                </div>
              </div>
            </div>

            {/* Sources */}
            <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-6 border border-white/20">
              <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <BookOpen className="w-5 h-5 text-purple-400" />
                Sources ({result.sources.length})
              </h3>
              <div className="space-y-3">
                {result.sources.map((source, idx) => (
                  <div
                    key={idx}
                    className="bg-white/5 border border-white/10 rounded-lg p-4 hover:bg-white/10 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          {source.type === 'advisory' ? (
                            <span className="text-blue-400">📋</span>
                          ) : (
                            <span className="text-green-400">🎥</span>
                          )}
                          <h4 className="font-semibold text-white">
                            {source.title}
                          </h4>
                        </div>
                        {source.advisory_id && (
                          <p className="text-purple-300 text-sm">
                            {source.advisory_id}
                          </p>
                        )}
                      </div>
                      {source.url && (
                        <a
                          href={source.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-purple-300 hover:text-purple-200 text-sm"
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
        <div className="text-center mt-12 text-purple-300 text-sm">
          🔐 Powered by LangChain + Google Gemini + ChromaDB
        </div>
      </div>
    </div>
  );
}