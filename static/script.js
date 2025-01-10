class Login {
    constructor() {
        this.signInBtn = document.querySelector("#sign-in-btn");
        this.signUpBtn = document.querySelector("#sign-up-btn");
        this.container = document.querySelector(".container");

        this.addEventListeners();
    }

    addEventListeners() {
        this.signUpBtn.addEventListener("click", () => {
            this.container.classList.add("sign-up-mode");
        });

        this.signInBtn.addEventListener("click", () => {
            this.container.classList.remove("sign-up-mode");
        });
    }
}

// Inisialisasi kelas Login
document.addEventListener("DOMContentLoaded", () => {
    new Login();
});



class VulnerabilityScanner {
    constructor() {
        this.initializeElements();
        this.initializeEventListeners();
        this.currentFile = null;
    }
  
    initializeElements() {
        // Get DOM elements
        this.dragDropZone = document.getElementById('dragDropZone');
        this.fileInput = document.getElementById('fileInput');
        this.browseBtn = document.getElementById('browseBtn');
        this.fileInfo = document.getElementById('fileInfo');
        this.progressContainer = document.getElementById('progressContainer');
        this.scanProgress = document.getElementById('scanProgress');
        this.progressText = document.getElementById('progressText');
        this.resultsContainer = document.getElementById('resultsContainer');
        this.resultsList = document.getElementById('resultsList');
        this.resultsSummary = document.getElementById('resultsSummary');
    }
  
    initializeEventListeners() {
        // Drag and drop events
        this.dragDropZone.addEventListener('dragover', (e) => this.handleDragOver(e));
        this.dragDropZone.addEventListener('dragleave', (e) => this.handleDragLeave(e));
        this.dragDropZone.addEventListener('drop', (e) => this.handleDrop(e));
  
        // File input and browse button
        this.browseBtn.addEventListener('click', () => this.fileInput.click());
        this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
  
        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => this.filterResults(btn.dataset.severity));
        });
    }
  
    handleDragOver(e) {
        e.preventDefault();
        e.stopPropagation();
        this.dragDropZone.classList.add('drag-over');
    }
  
    handleDragLeave(e) {
        e.preventDefault();
        e.stopPropagation();
        this.dragDropZone.classList.remove('drag-over');
    }
  
    handleDrop(e) {
        e.preventDefault();
        e.stopPropagation();
        this.dragDropZone.classList.remove('drag-over');
  
        const files = e.dataTransfer.files;
        if (files.length) {
            this.validateAndProcessFile(files[0]);
        }
    }
  
    handleFileSelect(e) {
        const files = e.target.files;
        if (files.length) {
            this.validateAndProcessFile(files[0]);
        }
    }
  
    validateAndProcessFile(file) {
        // Validate file type
        if (!file.name.endsWith('.py')) {
            this.showError('Please select a Python (.py) file');
            return;
        }
  
        // Validate file size (16MB limit)
        if (file.size > 16 * 1024 * 1024) {
            this.showError('File size exceeds 16MB limit');
            return;
        }
  
        this.currentFile = file;
        this.fileInfo.textContent = `Selected: ${file.name}`;
        this.startScan();
    }
  
    async startScan() {
        if (!this.currentFile) return;

        this.showProgress();
        const formData = new FormData();
        formData.append('file', this.currentFile);

        try {
            // Start progress simulation
            this.startProgressSimulation();

            const response = await fetch('/scan', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error(`Scan failed: ${response.statusText}`);
            }

            const data = await response.json();
            
            // Clear progress simulation interval
            if (this.progressInterval) {
                clearInterval(this.progressInterval);
            }
            
            // Set progress to 100% immediately when scan completes
            this.updateProgress(100);
            
            // Display results after a short delay
            setTimeout(() => {
                this.hideProgress();
                this.displayResults(data);
            }, 500);

        } catch (error) {
            this.showError(`Error: ${error.message}`);
            this.hideProgress();
        }
    }
  
    startProgressSimulation() {
        let progress = 0;
        this.progressInterval = setInterval(() => {
            // Faster initial progress
            if (progress < 60) {
                progress += Math.random() * 20;
            } 
            // Slower middle progress
            else if (progress < 85) {
                progress += Math.random() * 10;
            }
            // Very slow final progress
            else if (progress < 95) {
                progress += Math.random() * 2;
            }
            
            // Cap progress at 95% until scan completes
            progress = Math.min(progress, 95);
            
            this.updateProgress(progress);
        }, 300);
    }
  
    showProgress() {
        this.progressContainer.classList.remove('hidden');
        this.updateProgress(0);
    }
  
    hideProgress() {
        this.progressContainer.classList.add('hidden');
        if (this.progressInterval) {
            clearInterval(this.progressInterval);
        }
    }
  
    updateProgress(percent) {
        this.scanProgress.style.width = `${Math.min(percent, 100)}%`;
        this.progressText.textContent = `${Math.round(percent)}%`;
    }
  
    displayResults(data) {
        // Ensure we're working with the correct data format
        let results;
        try {
            if (typeof data.results === 'string') {
                results = JSON.parse(data.results);
            } else if (data.results) {
                results = data.results;
            } else {
                results = { results: [] };
            }
        } catch (e) {
            console.error('Error parsing results:', e);
            results = { results: [] };
        }

        // Show results container
        this.resultsContainer.classList.remove('hidden');

        // Update summary
        const summary = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };

        if (Array.isArray(results.results)) {
            results.results.forEach(issue => {
                const severity = issue.issue_severity.toLowerCase();
                if (summary.hasOwnProperty(severity)) {
                    summary[severity]++;
                }
            });
        }

        this.updateSummary(summary);

        // Clear previous results
        this.resultsList.innerHTML = '';

        // Display results
        if (Array.isArray(results.results)) {
            results.results.forEach(issue => {
                const severity = issue.issue_severity.toLowerCase();
                this.resultsList.appendChild(this.createResultItem(issue, severity));
            });
        }
    }
  
    updateSummary(summary) {
        this.resultsSummary.innerHTML = `
            <div class="summary-card">
                <h4>Critical</h4>
                <div class="count">${summary.critical}</div>
            </div>
            <div class="summary-card">
                <h4>High</h4>
                <div class="count">${summary.high}</div>
            </div>
            <div class="summary-card">
                <h4>Medium</h4>
                <div class="count">${summary.medium}</div>
            </div>
            <div class="summary-card">
                <h4>Low</h4>
                <div class="count">${summary.low}</div>
            </div>
        `;
    }
  
    createResultItem(issue, severity) {
        const div = document.createElement('div');
        div.className = `result-item ${severity}`;
        div.innerHTML = `
            <div class="result-header">
                <span class="severity-badge ${severity}">${severity.toUpperCase()}</span>
                <h3>${issue.test_name}</h3>
            </div>
            <div class="result-details">
                <p class="issue-text">${issue.issue_text}</p>
                <div class="code-block">
                    <div class="code-header">
                        <span class="filename">${issue.filename}</span>
                        <span class="line-number">Line ${issue.line_number}</span>
                    </div>
                    <pre><code>${this.escapeHtml(issue.code)}</code></pre>
                </div>
                <div class="remediation">
                    <h4>Remediation Advice</h4>
                    <p>${issue.more_info}</p>
                </div>
            </div>
        `;
        return div;
    }
  
    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
  
    filterResults(severity) {
        // Update active filter button
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.severity === severity);
        });
  
        // Filter results
        document.querySelectorAll('.result-item').forEach(item => {
            if (severity === 'all' || item.classList.contains(severity)) {
                item.style.display = 'block';
            } else {
                item.style.display = 'none';
            }
        });
    }
  
    showError(message) {
        this.fileInfo.textContent = message;
        this.fileInfo.style.color = '#ff4444';
        setTimeout(() => {
            this.fileInfo.style.color = '';
            this.fileInfo.textContent = 'Supports .py files up to 16MB';
        }, 3000);
    }
}

// Initialize scanner and fade scroll functionality
document.addEventListener('DOMContentLoaded', () => {
    // Initialize the scanner
    window.scanner = new VulnerabilityScanner();

    // Initialize fade scroll functionality
    const fadeElements = document.querySelectorAll('.upload-section, .scan-options, .results-container, .about-section');
    
    const fadeScrollObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            } else {
                entry.target.classList.remove('visible');
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });

    fadeElements.forEach(element => {
        element.classList.add('fade-scroll');
        fadeScrollObserver.observe(element);
    });
});