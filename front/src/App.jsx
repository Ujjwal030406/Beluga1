import React, { useState } from 'react';
import { Upload, AlertCircle, FileText, Check, AlertTriangle, Loader, Shield, Code, Lock } from 'lucide-react';
import './styles.css';

const App = () => {
  const [file, setFile] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [scannerPulse, setScannerPulse] = useState(false);

  const triggerScannerAnimation = () => {
    setScannerPulse(true);
    setTimeout(() => setScannerPulse(false), 2000);
  };

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(e.type === 'dragenter' || e.type === 'dragover');
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    triggerScannerAnimation();
    const formData = new FormData();
    formData.append('file', file);
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
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

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  };

  return (
    <div className="app-container">
      <div className="shadow-particles">
        {[...Array(20)].map((_, i) => (
          <div key={i} className="particle" style={{
            left: `${Math.random() * 100}%`,
            animationDelay: `${Math.random() * 5}s`
          }} />
        ))}
      </div>

      <div className="content">
        <div className="header">
          <Shield className="header-icon magical-rotate" />
          <h1 className="title magical-text">ShadowScan</h1>
          <p className="subtitle magical-fade-in">Arise from the Shadows - Secure Your System</p>
        </div>

        <div
          className={`upload-box ${dragActive ? 'drag-active' : ''} ${scannerPulse ? 'scanning' : ''}`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
        >
          <div className="magical-circle"></div>
          <Upload className="upload-icon hover-float" />
          <label className="upload-label">
            <span className="magical-text">Summon your file here </span>
            <input
              type="file"
              className="file-input"
              onChange={handleFileChange}
              accept=".exe,.dll,.sys,.bat"
            />
            <span className="browse-link hover-glow">Browse</span>
          </label>
          <p className="file-size-info">Maximum power level: 10MB</p>
          {file && (
            <div className="file-info hover-float">
              <FileText className="file-icon" />
              <span>{file.name}</span>
            </div>
          )}
        </div>

        <button
          className={`analyze-button magical-button ${loading || !file ? 'disabled' : ''}`}
          onClick={handleSubmit}
          disabled={!file || loading}
        >
          {loading ? (
            <div className="loading-container">
              <Loader className="loader-icon magical-spin" />
              <span className="loading-text">Analyzing...</span>
            </div>
          ) : (
            <span className="button-text">Analyze File</span>
          )}
        </button>

        {error && (
          <div className="error-message shadow-rise">
            <AlertCircle className="error-icon pulse" />
            <p>{error}</p>
          </div>
        )}

        {analysis && (
          <div className="analysis-results magical-fade-in">
            <h2 className="results-title magical-text">Analysis Results</h2>
            <div className="results-grid">
              <div className="result-card hover-rise">
                <h3><Code className="icon hover-float" /> File Details</h3>
                <p><strong>Hash:</strong> {analysis.hash}</p>
                <p><strong>Size:</strong> {formatFileSize(analysis.file_size)}</p>
                <p><strong>Analyzed:</strong> {new Date(analysis.timestamp).toLocaleString()}</p>
              </div>
              <div className="result-card hover-rise">
                <h3><Lock className="icon hover-float" /> Analysis Summary</h3>
                <p>
                  <strong>Status:</strong>
                  <span className={`status ${analysis.status.toLowerCase()} magical-pulse`}>
                    {analysis.status === 'Clean' ? <Check className="icon" /> :
                     analysis.status === 'Suspicious' ? <AlertTriangle className="icon" /> :
                     <AlertCircle className="icon" />}
                    {analysis.status}
                  </span>
                </p>
                <p><strong>Recommendations:</strong> {analysis.recommendations}</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
