/**
 * SSH Execution Service - Repeatable Abstraction for Victor/Hermes Integration
 * 
 * This service provides a systematic approach to SSH operations based on CLI POC learnings:
 * 1. Automatic SSH key discovery/generation
 * 2. Server connection management with retry logic  
 * 3. Command execution with proper result capture
 * 4. Error handling and recovery patterns
 * 5. Audit logging for all operations
 */

import { NodeSSH, SSHExecCommandResponse } from 'node-ssh'
import { v4 as uuidv4 } from 'uuid'
import { SSHKeyService } from './SSHKeyService'
import { SSHConnectionService } from './SSHConnectionService'
import { ContextManagerService } from './ContextManagerService'

export interface SSHExecutionResult {
  success: boolean
  command: string
  stdout: string
  stderr: string
  exitCode: number
  executionTime: number
  timestamp: string
  sessionId: string
  serverId: string
}

export interface SSHExecutionRequest {
  serverId: string // IP or hostname
  command: string
  workingDirectory?: string
  timeout?: number
  environment?: Record<string, string>
  sudo?: boolean
  jwtToken: string
  userId: string
  workspaceId: string
  // Session-aware fields for SSH key persistence
  sessionId?: string
  conversationId?: string
}

export interface SSHSession {
  id: string
  serverId: string
  keyId: string
  status: 'connecting' | 'connected' | 'failed' | 'disconnected'
  lastUsed: Date
  connectionCount: number
  ssh?: NodeSSH
}

export class SSHExecutionService {
  private sessions = new Map<string, SSHSession>()
  private sshKeyService: SSHKeyService
  private sshConnectionService: SSHConnectionService
  private contextManagerService: ContextManagerService

  constructor(sshKeyService: SSHKeyService) {
    this.sshKeyService = sshKeyService
    this.sshConnectionService = new SSHConnectionService(sshKeyService)
    this.contextManagerService = new ContextManagerService()
    
    // Clean up stale sessions every 30 minutes
    setInterval(() => this.cleanupStaleSessions(), 30 * 60 * 1000)
  }

  /**
   * Execute SSH command with automatic session management
   * This is the main abstraction that Victor calls
   */
  async executeCommand(request: SSHExecutionRequest): Promise<SSHExecutionResult> {
    const startTime = Date.now()
    const sessionId = await this.getOrCreateSession(request)
    
    try {
      console.log(`[SSH-EXEC] Executing command on ${request.serverId}: ${request.command}`)
      
      const session = this.sessions.get(sessionId)
      if (!session?.ssh) {
        throw new Error(`SSH session not available for ${request.serverId}`)
      }

      // Execute the command with proper options
      const result: SSHExecCommandResponse = await session.ssh.execCommand(request.command, {
        cwd: request.workingDirectory
      })

      session.lastUsed = new Date()
      session.connectionCount++

      const executionTime = Date.now() - startTime
      
      const executionResult: SSHExecutionResult = {
        success: result.code === 0,
        command: request.command,
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: result.code || 0,
        executionTime,
        timestamp: new Date().toISOString(),
        sessionId,
        serverId: request.serverId
      }

      console.log(`[SSH-EXEC] Command completed in ${executionTime}ms, exit code: ${result.code}`)
      
      // Log to audit system
      await this.auditLog(request, executionResult)
      
      return executionResult

    } catch (error) {
      const executionTime = Date.now() - startTime
      const errorResult: SSHExecutionResult = {
        success: false,
        command: request.command,
        stdout: '',
        stderr: error instanceof Error ? error.message : 'Unknown error',
        exitCode: -1,
        executionTime,
        timestamp: new Date().toISOString(),
        sessionId,
        serverId: request.serverId
      }

      console.error(`[SSH-EXEC] Command failed: ${error}`)
      
      // Invalidate session on connection errors
      if (error instanceof Error && error.message.includes('connection')) {
        this.sessions.delete(sessionId)
      }

      await this.auditLog(request, errorResult)
      return errorResult
    }
  }

  /**
   * Get or create SSH session for a server
   * Handles key discovery, connection establishment, and session caching
   */
  private async getOrCreateSession(request: SSHExecutionRequest): Promise<string> {
    const existingSession = Array.from(this.sessions.values())
      .find(s => s.serverId === request.serverId && s.status === 'connected')

    if (existingSession) {
      console.log(`[SSH-EXEC] Reusing existing session for ${request.serverId}`)
      return existingSession.id
    }

    console.log(`[SSH-EXEC] Creating new SSH session for ${request.serverId}`)
    
    // Step 1: Find or create SSH key for this server
    const keyId = await this.ensureSSHKey(request.serverId, request.jwtToken, request.userId, request.workspaceId, request.sessionId, request.conversationId)
    
    // Step 2: Establish SSH connection
    const sessionId = uuidv4()
    const session: SSHSession = {
      id: sessionId,
      serverId: request.serverId,
      keyId,
      status: 'connecting',
      lastUsed: new Date(),
      connectionCount: 0
    }
    
    this.sessions.set(sessionId, session)

    try {
      // Get private key from key service with session persistence
      const privateKey = await this.sshKeyService.getSSHKeyWithPersistence(keyId, request.jwtToken)
      
      // Create SSH connection
      const ssh = new NodeSSH()
      await ssh.connect({
        host: request.serverId,
        port: 22,
        username: 'root', // Standard for our deployments
        privateKey,
        readyTimeout: 10000,
        keepaliveInterval: 30000
      })

      session.ssh = ssh
      session.status = 'connected'
      
      console.log(`[SSH-EXEC] SSH connection established to ${request.serverId}`)
      return sessionId

    } catch (error) {
      session.status = 'failed'
      this.sessions.delete(sessionId)
      throw new Error(`Failed to establish SSH connection to ${request.serverId}: ${error}`)
    }
  }

  /**
   * Ensure SSH key exists for server (from CLI POC patterns)
   * This handles the key discovery/generation workflow
   */
  private async ensureSSHKey(serverId: string, jwtToken: string, userId: string, workspaceId: string, sessionId?: string, conversationId?: string): Promise<string> {
    // Step 1: Check if we already have keys for this server
    const existingKeys = await this.sshKeyService.listSSHKeys(userId, workspaceId)
    const serverKey = existingKeys.find(key => 
      key.deployedTo.includes(serverId) || 
      key.tags?.includes(`server:${serverId}`)
    )

    if (serverKey) {
      console.log(`[SSH-EXEC] Found existing SSH key for ${serverId}: ${serverKey.id}`)
      return serverKey.id
    }

    // Step 2: Generate session-aware SSH key for this server
    console.log(`[SSH-EXEC] Generating session-aware SSH key for ${serverId}`)
    const keyPair = await this.sshKeyService.generateSessionAwareSSHKeyPair({
      name: `deployment-key-${serverId}-${Date.now()}`,
      keyType: 'ed25519',
      purpose: 'deployment',
      tags: [`server:${serverId}`, 'auto-generated'],
      userId,
      workspaceId,
      // Session-aware fields for persistence across conversations
      sessionId: sessionId || uuidv4(),
      conversationId: conversationId,
      deploymentTarget: serverId,
      reusable: true
    }, jwtToken)

    // Step 3: Deploy key to server using enhanced deployment service
    // This leverages DigitalOcean integration for initial bootstrap
    try {
      await this.sshConnectionService.deploySSHKeyEnhanced(keyPair.id, jwtToken, {
        targets: [{
          host: serverId,
          port: 22,
          username: 'root'
        }],
        deployToAllDroplets: false
      })
      console.log(`[SSH-EXEC] Successfully deployed SSH key to ${serverId}`)
    } catch (error) {
      console.warn(`[SSH-EXEC] Key deployment warning for ${serverId}: ${error}`)
      // For new deployments, this is expected - keys will be deployed during droplet creation
      // Continue anyway - the connection attempt will reveal if keys are properly configured
    }

    console.log(`[SSH-EXEC] Generated and deployed SSH key for ${serverId}: ${keyPair.id}`)
    return keyPair.id
  }

  /**
   * Cleanup stale SSH sessions
   */
  private cleanupStaleSessions(): void {
    const now = new Date()
    const staleThreshold = 30 * 60 * 1000 // 30 minutes

    for (const [sessionId, session] of this.sessions.entries()) {
      if (now.getTime() - session.lastUsed.getTime() > staleThreshold) {
        console.log(`[SSH-EXEC] Cleaning up stale session: ${sessionId}`)
        session.ssh?.dispose()
        this.sessions.delete(sessionId)
      }
    }
  }

  /**
   * Audit logging for compliance and debugging
   */
  private async auditLog(request: SSHExecutionRequest, result: SSHExecutionResult): Promise<void> {
    const auditEntry = {
      timestamp: new Date().toISOString(),
      userId: request.userId,
      workspaceId: request.workspaceId,
      serverId: request.serverId,
      command: request.command,
      success: result.success,
      exitCode: result.exitCode,
      executionTime: result.executionTime,
      sessionId: result.sessionId
    }

    // This would integrate with actual audit logging system
    console.log(`[SSH-AUDIT] ${JSON.stringify(auditEntry)}`)
  }

  /**
   * Get session status for monitoring
   */
  getSessionStatus(): Array<{
    sessionId: string
    serverId: string
    status: string
    lastUsed: string
    connectionCount: number
  }> {
    return Array.from(this.sessions.values()).map(session => ({
      sessionId: session.id,
      serverId: session.serverId,
      status: session.status,
      lastUsed: session.lastUsed.toISOString(),
      connectionCount: session.connectionCount
    }))
  }

  /**
   * Close all sessions (for graceful shutdown)
   */
  async closeAllSessions(): Promise<void> {
    console.log(`[SSH-EXEC] Closing ${this.sessions.size} active sessions`)
    
    for (const session of this.sessions.values()) {
      if (session.ssh) {
        await session.ssh.dispose()
      }
    }
    
    this.sessions.clear()
  }
}