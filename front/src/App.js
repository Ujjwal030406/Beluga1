import React, { useState } from 'react';
import { Upload, AlertCircle, FileText, Check, AlertTriangle } from 'lucide-react';

const App = () => {
  const [file, setFile] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [dragActive, setDragActive] = useState(false);

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    handleFile(selectedFile);
  };

  const handleFile = (selectedFile) => {
    if (!selectedFile) return;

    if (selectedFile.size > 10 * 1024 * 1024) {
      setError('File size too large. Maximum size is 10MB.');
      return;
    }

    const validTypes = ['.exe', '.dll', '.sys','.bat'];
    const fileExtension = selectedFile.name.toLowerCase().substring(selectedFile.name.lastIndexOf('.'));
    if (!validTypes.includes(fileExtension)) {
      setError('Invalid file type. Please upload .exe, .dll, or .sys files only.');
      return;
    }

    setFile(selectedFile);
    setError(null);
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = async () => {
    if (!file) return;

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://localhost:8000/analyze', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(await response.text());
      }

      const data = await response.json();
      setAnalysis(data);
    } catch (err) {
      setError(err.message || 'An error occurred during analysis');
    } finally {
      setLoading(false);
    }
  };

  const formatFileSize = (size) => {
    if (size === null || size === undefined) return "N/A";
    const i = size === 0 ? 0 : Math.floor(Math.log(size) / Math.log(1024));
    return (
      (size / Math.pow(1024, i)).toFixed(2) * 1 +
      " " +
      ["B", "KB", "MB", "TB"][i]
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-blue-50 to-blue-100 py-12 px-4">
      <div className="max-w-4xl mx-auto">
        <div className="bg-white rounded-xl shadow-lg p-8">
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-blue-900 mb-2">Malware Analysis Tool</h1>
            <p className="text-blue-600">Secure file analysis for .exe, .dll, and .sys files</p>
          </div>

          <div 
            className={`border-2 border-dashed rounded-lg p-8 mb-6 text-center transition-colors
              ${dragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-blue-400'}`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <Upload className="w-12 h-12 text-blue-500 mx-auto mb-4" />
            <label className="block mb-4">
              <span className="text-blue-900 font-medium">Drop your file here or</span>
              <input
                type="file"
                className="hidden"
                onChange={handleFileChange}
                accept=".exe,.dll,.sys,.bat"
              />
              <span className="text-blue-500 font-semibold cursor-pointer hover:text-blue-600"> browse</span>
            </label>
            <p className="text-sm text-gray-500">Maximum file size: 10MB</p>
            {file && (
              <div className="mt-4 flex items-center justify-center gap-2 text-blue-700">
                <FileText className="w-4 h-4" />
                <span>{file.name}</span>
              </div>
            )}
          </div>

          <div className="text-center">
            <button
              className={`px-8 py-3 rounded-lg font-semibold transition-colors ${
                loading || !file
                  ? 'bg-gray-300 cursor-not-allowed text-gray-500'
                  : 'bg-blue-600 hover:bg-blue-700 text-white'
              }`}
              onClick={handleSubmit}
              disabled={!file || loading}
            >
              {loading ? 'Analyzing...' : 'Analyze File'}
            </button>
          </div>

          {error && (
            <div className="mt-6 p-4 bg-red-50 rounded-lg flex items-center gap-3 text-red-700">
              <AlertCircle className="w-5 h-5 flex-shrink-0" />
              <p>{error}</p>
            </div>
          )}

          {analysis && (
            <div className="mt-8 bg-blue-50 rounded-lg p-6">
              <h2 className="text-xl font-semibold text-blue-900 mb-4">Analysis Results</h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-white rounded-lg p-4 shadow-sm">
                  <h3 className="text-lg font-medium text-blue-800 mb-3">File Details</h3>
                  <div className="space-y-2">
                    <p className="text-gray-700">
                      <span className="font-medium">Hash: </span>
                      <span className="font-mono text-sm">{analysis.hash}</span>
                    </p>
                    <p className="text-gray-700">
                      <span className="font-medium">Size: </span>
                      {formatFileSize(analysis.file_size)}
                    </p>
                    <p className="text-gray-700">
                      <span className="font-medium">Analyzed: </span>
                      {new Date(analysis.timestamp).toLocaleString()}
                    </p>
                  </div>
                </div>

                <div className="bg-white rounded-lg p-4 shadow-sm">
                  <h3 className="text-lg font-medium text-blue-800 mb-3">Analysis Summary</h3>
                  <div className="space-y-2">
                    <p className="text-gray-700">
                      <span className="font-medium">Status: </span>
                      <span className={`inline-flex items-center gap-1 px-2 py-1 rounded ${
                        analysis.status === 'Clean' ? 'bg-green-100 text-green-700' :
                        analysis.status === 'Suspicious' ? 'bg-yellow-100 text-yellow-700' :
                        'bg-red-100 text-red-700'
                      }`}>
                        {analysis.status === 'Clean' ? <Check className="w-4 h-4" /> :
                         analysis.status === 'Suspicious' ? <AlertTriangle className="w-4 h-4" /> :
                         <AlertCircle className="w-4 h-4" />}
                        {analysis.status}
                      </span>
                    </p>
                    <p className="text-gray-700">
                      <span className="font-medium">Recommendations: </span>
                      {analysis.recommendations}
                    </p>
                  </div>
                </div>
              </div>

              {analysis.yara_matches && analysis.yara_matches.length > 0 && (
                <div className="mt-6 bg-white rounded-lg p-4 shadow-sm">
                  <h3 className="text-lg font-medium text-blue-800 mb-3">Matching Rules</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {analysis.yara_matches.map((match, index) => (
                      <div key={index} className="p-3 bg-blue-50 rounded-lg">
                        <p className="text-blue-900">
                          <span className="font-medium">Category: </span>
                          {match.category}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default App;