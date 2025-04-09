/**
 * Wireshark MCP Web Interface - Main JavaScript
 */

// DOM elements
const darkModeToggle = document.getElementById('dark-mode-toggle');
const htmlElement = document.documentElement;
const fileDropZone = document.getElementById('file-drop-zone');
const fileInput = document.getElementById('file-input');
const copyButtons = document.querySelectorAll('.copy-btn');
const toastContainer = document.getElementById('toast-container');
const networkVisualization = document.getElementById('network-visualization');
const packetRows = document.querySelectorAll('.packet-row');
const protocolTabs = document.querySelectorAll('.protocol-tab');
const tabContents = document.querySelectorAll('.tab-content');

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    initDarkMode();
    initFileUpload();
    initCopyFunctionality();
    initPacketExpand();
    initTabs();
    initTooltips();
    initNetworkVisualization();
});

/**
 * Dark mode functionality
 */
function initDarkMode() {
    if (!darkModeToggle) return;
    
    // Check user preference from localStorage or OS preference
    const prefersDark = localStorage.getItem('darkMode') === 'true' || 
                      (!localStorage.getItem('darkMode') && 
                       window.matchMedia('(prefers-color-scheme: dark)').matches);
    
    // Set initial state
    if (prefersDark) {
        htmlElement.classList.add('dark');
        if (darkModeToggle.querySelector('.sun')) {
            darkModeToggle.querySelector('.sun').classList.remove('hidden');
            darkModeToggle.querySelector('.moon').classList.add('hidden');
        }
    } else {
        htmlElement.classList.remove('dark');
        if (darkModeToggle.querySelector('.moon')) {
            darkModeToggle.querySelector('.moon').classList.remove('hidden');
            darkModeToggle.querySelector('.sun').classList.add('hidden');
        }
    }
    
    // Toggle dark mode
    darkModeToggle.addEventListener('click', function() {
        htmlElement.classList.toggle('dark');
        const isDark = htmlElement.classList.contains('dark');
        localStorage.setItem('darkMode', isDark.toString());
        
        // Toggle icon if present
        if (darkModeToggle.querySelector('.sun') && darkModeToggle.querySelector('.moon')) {
            darkModeToggle.querySelector('.sun').classList.toggle('hidden', !isDark);
            darkModeToggle.querySelector('.moon').classList.toggle('hidden', isDark);
        }
        
        // Update network visualization if present
        if (window.networkChart) {
            updateNetworkVisualizationTheme();
        }
    });
}

/**
 * File upload with drag & drop
 */
function initFileUpload() {
    if (!fileDropZone) return;
    
    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        fileDropZone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });
    
    // Highlight drop zone when item is dragged over
    ['dragenter', 'dragover'].forEach(eventName => {
        fileDropZone.addEventListener(eventName, highlight, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        fileDropZone.addEventListener(eventName, unhighlight, false);
    });
    
    // Handle dropped files
    fileDropZone.addEventListener('drop', handleDrop, false);
    
    // Handle file selection via dialog
    fileDropZone.addEventListener('click', () => {
        fileInput.click();
    });
    
    if (fileInput) {
        fileInput.addEventListener('change', handleFileSelect, false);
    }
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    function highlight(e) {
        fileDropZone.classList.add('drag-active');
    }
    
    function unhighlight(e) {
        fileDropZone.classList.remove('drag-active');
    }
    
    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length) {
            fileInput.files = files;
            handleFileSelect();
        }
    }
    
    function handleFileSelect() {
        const files = fileInput.files;
        if (files.length) {
            // Show file name
            const fileName = document.getElementById('file-name');
            if (fileName) {
                fileName.textContent = files[0].name;
            }
            
            // Show upload button
            const uploadButton = document.getElementById('upload-button');
            if (uploadButton) {
                uploadButton.classList.remove('hidden');
            }
            
            // Add animation
            fileDropZone.classList.add('file-selected');
        }
    }
}

/**
 * Copy to clipboard functionality
 */
function initCopyFunctionality() {
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-copy-target');
            const targetEl = document.getElementById(targetId);
            
            if (!targetEl) return;
            
            // Copy text to clipboard
            const textToCopy = targetEl.textContent || targetEl.value;
            navigator.clipboard.writeText(textToCopy).then(() => {
                // Visual feedback
                button.classList.add('copied-animation');
                
                // Update button text/icon if needed
                const originalContent = button.innerHTML;
                button.innerHTML = '<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path d="M5 13l4 4L19 7"></path></svg> Copied!';
                
                // Show toast notification
                showToast('Copied to clipboard!', 'success');
                
                // Reset button after animation
                setTimeout(() => {
                    button.classList.remove('copied-animation');
                    button.innerHTML = originalContent;
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy text: ', err);
                showToast('Failed to copy to clipboard', 'error');
            });
        });
    });
}

/**
 * Toast notification system
 */
function showToast(message, type = 'success', duration = 3000) {
    if (!toastContainer) return;
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    // Add to container
    toastContainer.appendChild(toast);
    
    // Animate in
    setTimeout(() => {
        toast.classList.add('toast-enter-active');
    }, 10);
    
    // Remove after duration
    setTimeout(() => {
        toast.classList.add('toast-exit-active');
        setTimeout(() => {
            toastContainer.removeChild(toast);
        }, 300);
    }, duration);
}

/**
 * Expandable packet rows
 */
function initPacketExpand() {
    packetRows.forEach(row => {
        const header = row.querySelector('.packet-header');
        const content = row.querySelector('.packet-content');
        
        if (!header || !content) return;
        
        content.style.display = 'none'; // Initial state: collapsed
        
        header.addEventListener('click', () => {
            const isExpanded = content.style.display !== 'none';
            
            // Toggle content visibility
            content.style.display = isExpanded ? 'none' : 'block';
            
            // Toggle indicator icon if present
            const indicator = header.querySelector('.expand-indicator');
            if (indicator) {
                indicator.classList.toggle('rotate-180', !isExpanded);
            }
        });
    });
}

/**
 * Tab functionality
 */
function initTabs() {
    protocolTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.getAttribute('data-tab-target');
            
            // Deactivate all tabs
            protocolTabs.forEach(t => t.classList.remove('active'));
            
            // Hide all content
            tabContents.forEach(content => {
                content.style.display = 'none';
            });
            
            // Activate selected tab
            tab.classList.add('active');
            
            // Show selected content
            const targetContent = document.getElementById(target);
            if (targetContent) {
                targetContent.style.display = 'block';
            }
        });
    });
    
    // Activate first tab by default
    if (protocolTabs.length > 0) {
        protocolTabs[0].click();
    }
}

/**
 * Initialize tooltip functionality
 */
function initTooltips() {
    const tooltipElements = document.querySelectorAll('[data-tooltip]');
    
    tooltipElements.forEach(element => {
        element.addEventListener('mouseenter', showTooltip);
        element.addEventListener('mouseleave', hideTooltip);
    });
    
    function showTooltip(e) {
        const tooltipText = this.getAttribute('data-tooltip');
        
        // Create tooltip element
        const tooltip = document.createElement('div');
        tooltip.className = 'tooltip';
        tooltip.textContent = tooltipText;
        document.body.appendChild(tooltip);
        
        // Position tooltip
        const rect = this.getBoundingClientRect();
        tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
        tooltip.style.top = rect.top - tooltip.offsetHeight - 10 + 'px';
        
        // Store tooltip element
        this._tooltip = tooltip;
        
        // Show tooltip with animation
        setTimeout(() => {
            tooltip.classList.add('tooltip-visible');
        }, 10);
    }
    
    function hideTooltip() {
        if (this._tooltip) {
            this._tooltip.classList.remove('tooltip-visible');
            setTimeout(() => {
                if (this._tooltip.parentNode) {
                    document.body.removeChild(this._tooltip);
                }
                this._tooltip = null;
            }, 200);
        }
    }
}

/**
 * Network visualization using D3.js
 */
function initNetworkVisualization() {
    if (!networkVisualization || !window.d3) return;
    
    // Check if we have data to visualize
    const dataElement = document.getElementById('visualization-data');
    if (!dataElement) return;
    
    try {
        // Parse the data
        const data = JSON.parse(dataElement.textContent);
        if (!data || !data.nodes || !data.links) return;
        
        createNetworkGraph(data);
    } catch (e) {
        console.error('Failed to parse visualization data:', e);
    }
}

function createNetworkGraph(data) {
    // D3.js force-directed graph
    const width = networkVisualization.clientWidth;
    const height = 400;
    
    // Color scheme
    const isDark = htmlElement.classList.contains('dark');
    const colorScheme = isDark ? d3.schemeSet2 : d3.schemeCategory10;
    
    // Clear any existing SVG
    d3.select(networkVisualization).selectAll('svg').remove();
    
    // Create SVG container
    const svg = d3.select(networkVisualization)
        .append('svg')
        .attr('width', width)
        .attr('height', height);
    
    // Create the force simulation
    const simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.links).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('x', d3.forceX(width / 2).strength(0.1))
        .force('y', d3.forceY(height / 2).strength(0.1));
    
    // Define arrow marker for directed links
    svg.append('defs').selectAll('marker')
        .data(['end'])
        .enter().append('marker')
        .attr('id', d => d)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 15)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('fill', isDark ? '#9ca3af' : '#6b7280')
        .attr('d', 'M0,-5L10,0L0,5');
    
    // Create links
    const link = svg.append('g')
        .attr('class', 'links')
        .selectAll('line')
        .data(data.links)
        .enter().append('line')
        .attr('stroke', isDark ? '#4b5563' : '#9ca3af')
        .attr('stroke-width', d => Math.sqrt(d.value || 1))
        .attr('marker-end', 'url(#end)');
    
    // Create nodes
    const node = svg.append('g')
        .attr('class', 'nodes')
        .selectAll('circle')
        .data(data.nodes)
        .enter().append('circle')
        .attr('r', d => d.size || 5)
        .attr('fill', (d, i) => colorScheme[i % colorScheme.length])
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));
    
    // Add node labels
    const labels = svg.append('g')
        .attr('class', 'labels')
        .selectAll('text')
        .data(data.nodes)
        .enter().append('text')
        .attr('dx', 12)
        .attr('dy', '.35em')
        .text(d => d.name)
        .style('fill', isDark ? '#e5e7eb' : '#1f2937')
        .style('font-size', '10px');
    
    // Add tooltip on hover
    node.append('title')
        .text(d => d.name);
    
    // Update positions on each simulation tick
    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);
        
        node
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);
        
        labels
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    });
    
    // Store the chart reference for later updates
    window.networkChart = {
        svg: svg,
        simulation: simulation,
        data: data
    };
    
    // Drag functions
    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    
    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    
    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
}

/**
 * Update visualization theme for dark/light mode
 */
function updateNetworkVisualizationTheme() {
    if (!window.networkChart) return;
    
    const isDark = htmlElement.classList.contains('dark');
    const svg = window.networkChart.svg;
    
    // Update link colors
    svg.selectAll('.links line')
        .attr('stroke', isDark ? '#4b5563' : '#9ca3af');
    
    // Update arrow marker color
    svg.select('defs marker path')
        .attr('fill', isDark ? '#9ca3af' : '#6b7280');
    
    // Update label colors
    svg.selectAll('.labels text')
        .style('fill', isDark ? '#e5e7eb' : '#1f2937');
}

/**
 * Progress bar animation
 */
function animateProgress(elementId, targetValue, duration = 1000) {
    const progressBar = document.getElementById(elementId);
    if (!progressBar) return;
    
    const startValue = parseInt(progressBar.style.width) || 0;
    const startTime = performance.now();
    
    function updateProgress(currentTime) {
        const elapsedTime = currentTime - startTime;
        const progress = Math.min(elapsedTime / duration, 1);
        const currentValue = startValue + progress * (targetValue - startValue);
        
        progressBar.style.width = `${currentValue}%`;
        
        if (progress < 1) {
            requestAnimationFrame(updateProgress);
        }
    }
    
    requestAnimationFrame(updateProgress);
}

/**
 * Packet timeline visualization
 */
function initPacketTimeline(packetData) {
    const timelineContainer = document.getElementById('packet-timeline');
    if (!timelineContainer || !packetData || !packetData.length) return;
    
    // Clear existing content
    timelineContainer.innerHTML = '';
    
    // Get time range
    const firstPacketTime = new Date(packetData[0].timestamp).getTime();
    const lastPacketTime = new Date(packetData[packetData.length - 1].timestamp).getTime();
    const timeRange = lastPacketTime - firstPacketTime;
    
    // Create timeline elements
    packetData.forEach(packet => {
        const packetTime = new Date(packet.timestamp).getTime();
        const position = ((packetTime - firstPacketTime) / timeRange) * 100;
        
        const packetMarker = document.createElement('div');
        packetMarker.className = `packet-marker protocol-${packet.protocol.toLowerCase()}`;
        packetMarker.style.left = `${position}%`;
        packetMarker.setAttribute('data-tooltip', `${packet.protocol} - ${new Date(packet.timestamp).toLocaleTimeString()}`);
        
        packetMarker.addEventListener('click', () => {
            showPacketDetails(packet);
        });
        
        timelineContainer.appendChild(packetMarker);
    });
    
    // Initialize tooltips for the markers
    initTooltips();
}

/**
 * Show packet details in a modal
 */
function showPacketDetails(packet) {
    // Create modal element if it doesn't exist
    let modal = document.getElementById('packet-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'packet-modal';
        modal.className = 'packet-modal';
        document.body.appendChild(modal);
        
        // Close button
        const closeButton = document.createElement('button');
        closeButton.className = 'modal-close';
        closeButton.innerHTML = '&times;';
        closeButton.addEventListener('click', () => {
            modal.classList.remove('modal-visible');
        });
        
        modal.appendChild(closeButton);
    }
    
    // Content container
    const contentContainer = document.createElement('div');
    contentContainer.className = 'modal-content';
    
    // Packet header
    const header = document.createElement('div');
    header.className = 'modal-header';
    header.innerHTML = `<h3>${packet.protocol} Packet</h3>`;
    contentContainer.appendChild(header);
    
    // Packet details
    const details = document.createElement('div');
    details.className = 'modal-body';
    
    // Format details based on packet content
    let detailsHtml = `
        <div class="packet-detail"><strong>Time:</strong> ${new Date(packet.timestamp).toLocaleString()}</div>
        <div class="packet-detail"><strong>Source:</strong> ${packet.source}</div>
        <div class="packet-detail"><strong>Destination:</strong> ${packet.destination}</div>
        <div class="packet-detail"><strong>Protocol:</strong> ${packet.protocol}</div>
        <div class="packet-detail"><strong>Length:</strong> ${packet.length} bytes</div>
    `;
    
    // Add protocol-specific details
    if (packet.details) {
        detailsHtml += '<div class="packet-section">Details:</div>';
        
        Object.entries(packet.details).forEach(([key, value]) => {
            detailsHtml += `<div class="packet-detail"><strong>${key}:</strong> ${value}</div>`;
        });
    }
    
    details.innerHTML = detailsHtml;
    contentContainer.appendChild(details);
    
    // Clear previous content and add new content
    modal.innerHTML = '';
    modal.appendChild(closeButton);
    modal.appendChild(contentContainer);
    
    // Show modal with animation
    setTimeout(() => {
        modal.classList.add('modal-visible');
    }, 10);
}
