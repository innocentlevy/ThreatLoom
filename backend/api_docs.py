from flask import jsonify, Blueprint

# API documentation configuration
SWAGGER_URL = '/api/docs'
API_URL = '/api/swagger.json'

# Create documentation blueprint
swagger_ui_blueprint = Blueprint('swagger_ui', __name__)

@swagger_ui_blueprint.route(SWAGGER_URL)
def swagger_ui():
    return jsonify({
        'message': 'API Documentation',
        'version': '1.0',
        'endpoints': get_api_spec()
    })

def get_api_spec():
    """Return the API specification in OpenAPI format"""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "ThreatLoom API",
            "description": "API documentation for ThreatLoom network security monitoring",
            "version": "1.0.0"
        },
        "servers": [
            {
                "url": "http://localhost:5000",
                "description": "Development server"
            }
        ],
        "paths": {
            "/api/auth/login": {
                "post": {
                    "tags": ["Authentication"],
                    "summary": "Login to get access token",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Successful login",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "access_token": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/capture/start": {
                "post": {
                    "tags": ["Packet Capture"],
                    "summary": "Start packet capture",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Capture started successfully"
                        }
                    }
                }
            },
            "/api/capture/stop": {
                "post": {
                    "tags": ["Packet Capture"],
                    "summary": "Stop packet capture",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Capture stopped successfully"
                        }
                    }
                }
            },
            "/api/stats": {
                "get": {
                    "tags": ["Statistics"],
                    "summary": "Get current statistics",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Current statistics",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "total_packets": {"type": "integer"},
                                            "packets_per_second": {"type": "number"},
                                            "protocol_distribution": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "name": {"type": "string"},
                                                        "value": {"type": "integer"}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/alerts": {
                "get": {
                    "tags": ["Alerts"],
                    "summary": "Get security alerts",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {
                            "name": "severity",
                            "in": "query",
                            "schema": {"type": "string", "enum": ["low", "medium", "high"]},
                            "required": False,
                            "description": "Filter alerts by severity"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "List of alerts",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "type": {"type": "string"},
                                                "severity": {"type": "string"},
                                                "message": {"type": "string"},
                                                "timestamp": {"type": "string", "format": "date-time"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
        }
    }
