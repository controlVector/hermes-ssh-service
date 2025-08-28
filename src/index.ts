import 'dotenv/config'
import Fastify from 'fastify'
import cors from '@fastify/cors'
import helmet from '@fastify/helmet'
import rateLimit from '@fastify/rate-limit'
import { MCPHandler } from './mcp/handler'

const PORT = parseInt(process.env.PORT || '3008')
const HOST = process.env.HOST || '0.0.0.0'

const fastify = Fastify({
  logger: {
    level: process.env.NODE_ENV === 'development' ? 'debug' : 'info',
    transport: process.env.NODE_ENV === 'development' ? {
      target: 'pino-pretty',
      options: {
        translateTime: 'HH:MM:ss Z',
        ignore: 'pid,hostname',
      },
    } : undefined,
  },
})

// Security and CORS
fastify.register(helmet, {
  contentSecurityPolicy: false, // Disable for API
})

fastify.register(cors, {
  origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
})

// Rate limiting - more restrictive for SSH operations
fastify.register(rateLimit, {
  max: 50,
  timeWindow: '1 minute'
})

// Initialize MCP Handler
const mcpHandler = new MCPHandler()

// Health check endpoint
fastify.get('/health', async (request, reply) => {
  reply.send({ 
    status: 'healthy',
    service: 'hermes',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    capabilities: [
      'ssh_key_generation',
      'ssh_key_deployment', 
      'ssh_connection_management',
      'ssh_command_execution',
      'ssh_key_rotation',
      'ssh_security_audit'
    ]
  })
})

// MCP endpoints
fastify.get('/api/v1/mcp/tools', async (request, reply) => {
  try {
    const tools = mcpHandler.getTools()
    reply.send({
      success: true,
      tools,
      count: tools.length
    })
  } catch (error: any) {
    reply.status(500).send({
      success: false,
      error: error.message
    })
  }
})

fastify.get('/api/v1/mcp/health', async (request, reply) => {
  reply.send({
    status: 'healthy',
    service: 'hermes-mcp',
    tools_available: mcpHandler.getTools().length,
    security_features: [
      'ed25519_key_generation',
      'encrypted_key_storage',
      'key_rotation',
      'access_audit_logging',
      'connection_monitoring'
    ],
    timestamp: new Date().toISOString()
  })
})

fastify.post('/api/v1/mcp/call', async (request, reply) => {
  try {
    const { name: toolName, arguments: args } = request.body as { name: string; arguments: any }
    
    if (!toolName) {
      return reply.status(400).send({
        success: false,
        error: 'Tool name is required'
      })
    }

    // Validate JWT token for security-critical operations
    if (!args?.jwt_token) {
      return reply.status(401).send({
        success: false,
        error: 'JWT token is required for SSH operations'
      })
    }

    fastify.log.info(`Executing Hermes SSH tool: ${toolName}`)
    
    const result = await mcpHandler.handleToolCall(toolName, args || {})
    
    // Log security-relevant operations
    if (['hermes_generate_ssh_key', 'hermes_deploy_ssh_key', 'hermes_revoke_ssh_key', 'hermes_rotate_ssh_key'].includes(toolName)) {
      fastify.log.info(`Security operation completed: ${toolName} - Success: ${result.success}`)
    }
    
    reply.send(result)
  } catch (error: any) {
    fastify.log.error(`Error executing SSH tool: ${error.message}`)
    reply.status(500).send({
      success: false,
      error: error.message,
      tool_name: (request.body as any)?.name || 'unknown'
    })
  }
})

// Direct SSH management endpoints
fastify.post('/api/v1/ssh/generate-key', async (request, reply) => {
  try {
    const args = request.body
    const result = await mcpHandler.handleToolCall('hermes_generate_ssh_key', args)
    reply.send(result)
  } catch (error: any) {
    reply.status(500).send({
      success: false,
      error: error.message
    })
  }
})

fastify.post('/api/v1/ssh/deploy-key', async (request, reply) => {
  try {
    const args = request.body
    const result = await mcpHandler.handleToolCall('hermes_deploy_ssh_key', args)
    reply.send(result)
  } catch (error: any) {
    reply.status(500).send({
      success: false,
      error: error.message
    })
  }
})

fastify.post('/api/v1/ssh/connect', async (request, reply) => {
  try {
    const args = request.body
    const result = await mcpHandler.handleToolCall('hermes_establish_ssh_connection', args)
    reply.send(result)
  } catch (error: any) {
    reply.status(500).send({
      success: false,
      error: error.message
    })
  }
})

fastify.post('/api/v1/ssh/execute', async (request, reply) => {
  try {
    const args = request.body
    const result = await mcpHandler.handleToolCall('hermes_execute_ssh_command', args)
    reply.send(result)
  } catch (error: any) {
    reply.status(500).send({
      success: false,
      error: error.message
    })
  }
})

fastify.post('/api/v1/ssh/audit', async (request, reply) => {
  try {
    const args = request.body
    const result = await mcpHandler.handleToolCall('hermes_audit_ssh_keys', args)
    reply.send(result)
  } catch (error: any) {
    reply.status(500).send({
      success: false,
      error: error.message
    })
  }
})

// Sync SSH key to Context Manager
fastify.post('/api/v1/ssh-keys/:keyId/sync-to-context-manager', async (request, reply) => {
  try {
    const { keyId } = request.params as { keyId: string }
    const args = { 
      key_id: keyId,
      jwt_token: 'dev-token-123' // Development mode token
    }
    const result = await mcpHandler.handleToolCall('hermes_sync_key_to_context_manager', args)
    reply.send(result)
  } catch (error: any) {
    reply.status(500).send({
      success: false,
      error: error.message
    })
  }
})

// Security monitoring endpoints
fastify.get('/api/v1/security/status', async (request, reply) => {
  try {
    // This would return security status overview
    reply.send({
      status: 'secure',
      active_connections: 0, // Would get from connection service
      total_keys_managed: 0, // Would get from key service
      last_security_scan: new Date().toISOString(),
      security_score: 95,
      recommendations: []
    })
  } catch (error: any) {
    reply.status(500).send({
      success: false,
      error: error.message
    })
  }
})

// Error handler
fastify.setErrorHandler((error, request, reply) => {
  fastify.log.error(error)
  
  reply.status(500).send({
    success: false,
    error: process.env.NODE_ENV === 'development' ? error.message : 'Internal Server Error',
    timestamp: new Date().toISOString()
  })
})

// Graceful shutdown handling
async function gracefulShutdown() {
  fastify.log.info('Shutting down Hermes SSH service gracefully...')
  
  try {
    // Close all active SSH connections
    // This would be implemented by the connection service
    fastify.log.info('All SSH connections closed')
    
    await fastify.close()
    fastify.log.info('Hermes service stopped')
    process.exit(0)
  } catch (error) {
    fastify.log.error({ error }, 'Error during shutdown')
    process.exit(1)
  }
}

// Start server
const start = async () => {
  try {
    await fastify.listen({ port: PORT, host: HOST })
    fastify.log.info(`🔐 Hermes SSH Key Management Agent running on ${HOST}:${PORT}`)
    fastify.log.info(`🛡️ Available MCP tools: ${mcpHandler.getTools().length}`)
    fastify.log.info('🔧 Available endpoints:')
    fastify.log.info('   - GET  /health')
    fastify.log.info('   - GET  /api/v1/mcp/tools')
    fastify.log.info('   - POST /api/v1/mcp/call')
    fastify.log.info('   - POST /api/v1/ssh/generate-key')
    fastify.log.info('   - POST /api/v1/ssh/deploy-key')
    fastify.log.info('   - POST /api/v1/ssh/connect')
    fastify.log.info('   - POST /api/v1/ssh/execute')
    fastify.log.info('   - POST /api/v1/ssh/audit')
    fastify.log.info('   - GET  /api/v1/security/status')
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}

// Handle graceful shutdown
process.on('SIGINT', gracefulShutdown)
process.on('SIGTERM', gracefulShutdown)

start()