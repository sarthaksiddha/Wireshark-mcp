#!/usr/bin/env python3
"""
Web interface for Wireshark MCP

A simple Flask application that provides a web interface for using Wireshark MCP
to analyze network captures and generate AI-friendly contexts.
"""

import os
import tempfile
import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime

from flask import Flask, request, render_template, jsonify, redirect, url_for, flash
from werkzeug.utils import secure_filename

from wireshark_mcp import WiresharkMCP, Protocol, Filter
from wireshark_mcp.formatters import ClaudeFormatter

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-for-testing-only')

# Configure upload settings
UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), 'wireshark_mcp_uploads')
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename: str) -> bool:
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Render the home page."""
    protocols = [p.value for p in Protocol]
    return render_template('index.html', protocols=protocols)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and initial processing."""
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        file.save(filepath)
        logger.info(f"Saved uploaded file to {filepath}")
        
        # Redirect to analysis page
        return redirect(url_for('analyze', filename=unique_filename))
    
    flash('Invalid file type', 'error')
    return redirect(request.url)

@app.route('/analyze/<filename>')
def analyze(filename: str):
    """Analyze a packet capture file."""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    # Generate basic packet summary for display
    try:
        mcp = WiresharkMCP(filepath)
        context = mcp.generate_context(max_packets=100, include_statistics=True)
        
        # Extract summary data
        summary = context.get('summary', {})
        statistics = context.get('statistics', {})
        
        # Get available protocols in the capture
        available_protocols = []
        for proto, count in summary.get('protocols', {}).items():
            if count > 0:
                # Check if we have an analyzer for this protocol
                try:
                    p = next((p for p in Protocol if p.value.upper() == proto.upper()), None)
                    if p:
                        available_protocols.append({
                            'name': p.value,
                            'count': count,
                            'has_analyzer': p in [Protocol.HTTP, Protocol.DNS, Protocol.SMTP, Protocol.TLS]
                        })
                except:
                    # If protocol isn't in our enum, skip it
                    pass
        
        return render_template(
            'analyze.html', 
            filename=filename, 
            summary=summary,
            statistics=statistics,
            available_protocols=available_protocols
        )
    
    except Exception as e:
        logger.error(f"Error analyzing file: {e}", exc_info=True)
        flash(f"Error analyzing file: {str(e)}", 'error')
        return redirect(url_for('index'))

@app.route('/protocol/<filename>/<protocol>')
def analyze_protocol(filename: str, protocol: str):
    """Analyze a specific protocol in the packet capture."""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    try:
        # Get protocol enum
        proto = next((p for p in Protocol if p.value.upper() == protocol.upper()), None)
        
        if not proto:
            flash(f"Unknown protocol: {protocol}", 'error')
            return redirect(url_for('analyze', filename=filename))
        
        # Extract protocol data
        mcp = WiresharkMCP(filepath)
        proto_context = mcp.extract_protocol(
            protocol=proto,
            include_headers=True,
            include_body=False,
            max_conversations=10
        )
        
        # Extract insights if available
        try:
            proto_insights = mcp.protocol_insights(
                protocol=proto,
                extract_queries=True,
                analyze_response_codes=True,
                detect_tunneling=True
            )
        except:
            proto_insights = {}
        
        # Format for Claude
        formatter = ClaudeFormatter()
        claude_prompt = formatter.format_context(
            proto_context,
            query=f"Analyze this {protocol} traffic and identify any security concerns or unusual patterns."
        )
        
        return render_template(
            'protocol.html',
            filename=filename,
            protocol=protocol,
            context=proto_context,
            insights=proto_insights,
            claude_prompt=claude_prompt
        )
    
    except Exception as e:
        logger.error(f"Error analyzing protocol: {e}", exc_info=True)
        flash(f"Error analyzing protocol: {str(e)}", 'error')
        return redirect(url_for('analyze', filename=filename))

@app.route('/api/protocols/<filename>')
def api_get_protocols(filename: str):
    """API endpoint to get available protocols in a capture file."""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        mcp = WiresharkMCP(filepath)
        context = mcp.generate_context(max_packets=100)
        protocols = context.get('summary', {}).get('protocols', {})
        return jsonify({'protocols': protocols})
    
    except Exception as e:
        logger.error(f"API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/context/<filename>')
def api_get_context(filename: str):
    """API endpoint to get basic context for a capture file."""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        mcp = WiresharkMCP(filepath)
        context = mcp.generate_context(max_packets=100, include_statistics=True)
        return jsonify(context)
    
    except Exception as e:
        logger.error(f"API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/protocol/<filename>/<protocol>')
def api_get_protocol(filename: str, protocol: str):
    """API endpoint to get protocol-specific data."""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        # Get protocol enum
        proto = next((p for p in Protocol if p.value.upper() == protocol.upper()), None)
        
        if not proto:
            return jsonify({'error': f'Unknown protocol: {protocol}'}), 400
        
        # Extract protocol data
        mcp = WiresharkMCP(filepath)
        proto_context = mcp.extract_protocol(
            protocol=proto,
            include_headers=True,
            include_body=False,
            max_conversations=10
        )
        
        return jsonify(proto_context)
    
    except Exception as e:
        logger.error(f"API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/cleanup', methods=['POST'])
def cleanup():
    """Clean up temporary files to free disk space."""
    try:
        count = 0
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            # Remove files older than 1 day
            if os.path.isfile(filepath) and (datetime.now().timestamp() - os.path.getmtime(filepath)) > 86400:
                os.remove(filepath)
                count += 1
        
        flash(f"Removed {count} old files", 'success')
    except Exception as e:
        logger.error(f"Error cleaning up: {e}", exc_info=True)
        flash(f"Error cleaning up: {str(e)}", 'error')
    
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    return render_template('500.html'), 500

if __name__ == '__main__':
    # In production, use a proper WSGI server
    app.run(debug=True, host='0.0.0.0', port=5000)
