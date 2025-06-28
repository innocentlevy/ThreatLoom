from flask import Blueprint, request
import logging

test_bp = Blueprint('test', __name__)
logger = logging.getLogger('wireshark_siem')

@test_bp.route('/test/sql')
def test_sql():
    """Test endpoint for SQL injection detection"""
    query = request.args.get('query', '')
    logger.info(f'Received SQL test query: {query}')
    return {'status': 'received'}

@test_bp.route('/test/xss')
def test_xss():
    """Test endpoint for XSS detection"""
    input_data = request.args.get('input', '')
    logger.info(f'Received XSS test input: {input_data}')
    return {'status': 'received'}

@test_bp.route('/test/cmd')
def test_cmd():
    """Test endpoint for command injection detection"""
    cmd = request.args.get('cmd', '')
    logger.info(f'Received command test: {cmd}')
    return {'status': 'received'}
