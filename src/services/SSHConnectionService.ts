import { NodeSSH, SSHExecCommandResponse } from 'node-ssh'
import * as fs from 'fs/promises'
import { v4 as uuidv4 } from 'uuid'
import { 
  SSHConnection, 
  SSHCommand, 
  SSHCommandResult, 
  ConnectionOptions,
  ServerInfo,
  KeyDeployment,
  SSHAuditLog
} from '../types/ssh'
import { SSHKeyService } from './SSHKeyService'
import { DigitalOceanService } from './DigitalOceanService'
import { ContextManagerService } from './ContextManagerService'

export class SSHConnectionService {
  private connections = new Map<string, NodeSSH>()
  private activeConnections = new Map<string, SSHConnection>()
  private sshKeyService: SSHKeyService
  private contextManagerService: ContextManagerService
  private digitalOceanServices = new Map<string, DigitalOceanService>()

  constructor(sshKeyService: SSHKeyService) {
    this.sshKeyService = sshKeyService
    this.contextManagerService = new ContextManagerService()
  }

  /**
   * Get or create DigitalOcean service instance with user credentials
   */
  private async getDigitalOceanService(jwtToken: string): Promise<DigitalOceanService> {
    const cacheKey = jwtToken.slice(-10) // Use last 10 chars as cache key
    
    if (this.digitalOceanServices.has(cacheKey)) {
      return this.digitalOceanServices.get(cacheKey)!
    }

    try {
      const apiToken = await this.contextManagerService.getProviderCredentials('digitalocean', jwtToken)
      const doService = new DigitalOceanService(apiToken)
      this.digitalOceanServices.set(cacheKey, doService)
      return doService
    } catch (error) {
      throw new Error(`Failed to initialize DigitalOcean service: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  async establishConnection(options: ConnectionOptions): Promise<SSHConnection> {
    const connectionId = uuidv4()
    
    try {
      const keyMetadata = await this.sshKeyService.getSSHKey(options.keyId)
      if (!keyMetadata) {
        throw new Error(`SSH key not found: ${options.keyId}`)
      }

      const privateKey = await this.sshKeyService.getPrivateKey(options.keyId)
      
      const ssh = new NodeSSH()
      
      await ssh.connect({
        host: options.host,
        port: options.port || 22,
        username: options.username,
        privateKey,
        readyTimeout: options.timeout || 10000,
        keepaliveInterval: options.keepAlive ? 30000 : undefined
      })

      // Get server information
      const serverInfo = await this.getServerInfo(ssh)

      const connection: SSHConnection = {
        id: connectionId,
        host: options.host,
        port: options.port || 22,
        username: options.username,
        keyId: options.keyId,
        status: 'connected',
        lastConnected: new Date(),
        metadata: {
          serverName: options.serverName,
          purpose: 'deployment'
        }
      }

      this.connections.set(connectionId, ssh)
      this.activeConnections.set(connectionId, connection)

      await this.auditLog({
        event: 'connection_established',
        keyId: options.keyId,
        details: {
          host: options.host,
          port: options.port,
          username: options.username,
          serverInfo
        },
        success: true
      })

      return {
        ...connection,
        metadata: {
          ...connection.metadata,
          ...serverInfo
        }
      }
    } catch (error: any) {
      await this.auditLog({
        event: 'connection_failed',
        keyId: options.keyId,
        details: {
          host: options.host,
          port: options.port,
          username: options.username
        },
        success: false,
        error: error.message
      })

      throw new Error(`Failed to establish SSH connection: ${error.message}`)
    }
  }

  async executeCommand(
    connectionId: string, 
    command: SSHCommand
  ): Promise<SSHCommandResult> {
    const ssh = this.connections.get(connectionId)
    const connection = this.activeConnections.get(connectionId)
    
    if (!ssh || !connection) {
      throw new Error(`SSH connection not found: ${connectionId}`)
    }

    const startTime = Date.now()
    const resultId = uuidv4()
    
    try {
      let fullCommand = command.command

      // Handle sudo commands
      if (command.sudo) {
        fullCommand = `sudo ${fullCommand}`
      }

      // Set working directory
      if (command.workingDirectory) {
        fullCommand = `cd "${command.workingDirectory}" && ${fullCommand}`
      }

      const execOptions: any = {
        execOptions: {
          pty: command.sudo // Use PTY for sudo commands
        }
      }

      // Set environment variables
      if (command.environment) {
        const envVars = Object.entries(command.environment)
          .map(([key, value]) => `${key}="${value}"`)
          .join(' ')
        fullCommand = `${envVars} ${fullCommand}`
      }

      const result: SSHExecCommandResponse = await ssh.execCommand(fullCommand, execOptions)
      
      const executionTime = Date.now() - startTime
      
      const commandResult: SSHCommandResult = {
        id: resultId,
        command: command.command,
        exitCode: result.code || 0,
        stdout: result.stdout,
        stderr: result.stderr,
        executionTime,
        timestamp: new Date(),
        success: (result.code || 0) === 0
      }

      await this.auditLog({
        event: 'command_executed',
        keyId: connection.keyId,
        details: {
          connectionId,
          command: command.command,
          exitCode: commandResult.exitCode,
          executionTime,
          host: connection.host
        },
        success: commandResult.success
      })

      return commandResult
    } catch (error: any) {
      const executionTime = Date.now() - startTime
      
      const commandResult: SSHCommandResult = {
        id: resultId,
        command: command.command,
        exitCode: -1,
        stdout: '',
        stderr: error.message,
        executionTime,
        timestamp: new Date(),
        success: false
      }

      await this.auditLog({
        event: 'command_executed',
        keyId: connection.keyId,
        details: {
          connectionId,
          command: command.command,
          executionTime,
          host: connection.host
        },
        success: false,
        error: error.message
      })

      return commandResult
    }
  }

  /**
   * Enhanced SSH key deployment with DigitalOcean integration
   */
  async deploySSHKeyEnhanced(
    keyId: string,
    jwtToken: string,
    options: {
      targets?: Array<{ host: string; port?: number; username: string; serverName?: string }>
      deployToAllDroplets?: boolean
      provider?: 'digitalocean'
      method?: 'authorized_keys' | 'cloud_init' | 'manual'
      addToProviderAccount?: boolean
    } = {}
  ): Promise<KeyDeployment[]> {
    const { 
      targets = [], 
      deployToAllDroplets = false, 
      provider = 'digitalocean',
      method = 'authorized_keys',
      addToProviderAccount = true
    } = options

    const keyMetadata = await this.sshKeyService.getSSHKey(keyId)
    if (!keyMetadata) {
      throw new Error(`SSH key not found: ${keyId}`)
    }

    const deployments: KeyDeployment[] = []
    let finalTargets = [...targets]

    // If deployToAllDroplets is enabled, discover droplets from provider
    if (deployToAllDroplets && provider === 'digitalocean') {
      try {
        const doService = await this.getDigitalOceanService(jwtToken)
        const droplets = await doService.listDroplets()
        
        console.log(`[Hermes] Found ${droplets.length} DigitalOcean droplets for key deployment`)
        
        for (const droplet of droplets) {
          if (droplet.status === 'active') {
            const connections = doService.getDropletConnectionDetails(droplet)
            finalTargets.push(...connections)
          }
        }

        // Add key to DigitalOcean account if requested
        if (addToProviderAccount) {
          try {
            const doKey = await doService.addSSHKeyToAccount(keyMetadata.name, keyMetadata.publicKey)
            console.log(`[Hermes] Added SSH key to DigitalOcean account: ${doKey.name}`)
            
            // Store the provider key ID for future reference
            await this.contextManagerService.storeSSHKeyInfo(keyId, {
              digitalocean_key_id: doKey.id,
              fingerprint: doKey.fingerprint
            }, jwtToken)
          } catch (error) {
            console.log(`[Hermes] Note: Could not add key to DigitalOcean account: ${error instanceof Error ? error.message : 'Unknown error'}`)
          }
        }
      } catch (error) {
        console.error(`[Hermes] Failed to discover droplets:`, error)
      }
    }

    // Deploy to all targets
    return this.deploySSHKey(keyId, finalTargets, method)
  }

  async deploySSHKey(
    keyId: string,
    targets: Array<{ host: string; port?: number; username: string; serverName?: string }>,
    method: 'authorized_keys' | 'cloud_init' | 'manual' = 'authorized_keys'
  ): Promise<KeyDeployment[]> {
    const keyMetadata = await this.sshKeyService.getSSHKey(keyId)
    if (!keyMetadata) {
      throw new Error(`SSH key not found: ${keyId}`)
    }

    const deployments: KeyDeployment[] = []

    for (const target of targets) {
      const deploymentId = uuidv4()
      
      try {
        if (method === 'authorized_keys') {
          await this.deployToAuthorizedKeys(keyMetadata.publicKey, target)
        } else if (method === 'cloud_init') {
          // Cloud-init deployment would be handled by the cloud provider
          throw new Error('Cloud-init deployment not yet implemented')
        } else {
          // Manual deployment requires human intervention
          throw new Error('Manual deployment requires human intervention')
        }

        const deployment: KeyDeployment = {
          id: deploymentId,
          keyId,
          serverId: `${target.host}:${target.port || 22}`,
          status: 'deployed',
          deployedAt: new Date(),
          method
        }

        deployments.push(deployment)

        await this.auditLog({
          event: 'key_deployed',
          keyId,
          details: {
            target: target.host,
            method,
            deploymentId
          },
          success: true
        })
      } catch (error: any) {
        const deployment: KeyDeployment = {
          id: deploymentId,
          keyId,
          serverId: `${target.host}:${target.port || 22}`,
          status: 'failed',
          method,
          error: error.message
        }

        deployments.push(deployment)

        await this.auditLog({
          event: 'key_deployed',
          keyId,
          details: {
            target: target.host,
            method,
            deploymentId
          },
          success: false,
          error: error.message
        })
      }
    }

    return deployments
  }

  private async deployToAuthorizedKeys(
    publicKey: string,
    target: { host: string; port?: number; username: string },
    jwtToken?: string
  ): Promise<void> {
    const ssh = new NodeSSH()
    
    try {
      console.log(`[Hermes SSH] Deploying SSH key to ${target.host}:${target.port || 22} as ${target.username}`)
      
      // Try multiple connection methods for bootstrap scenarios
      await this.establishBootstrapConnection(ssh, target, jwtToken)

      console.log(`[Hermes SSH] Connected to ${target.host}`)

      // Create .ssh directory if it doesn't exist
      await ssh.execCommand(`mkdir -p ~/.ssh && chmod 700 ~/.ssh`)
      
      // Backup existing authorized_keys file
      await ssh.execCommand(`cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.backup.$(date +%s) 2>/dev/null || true`)
      console.log(`[Hermes SSH] Backed up existing authorized_keys (if any)`)
      
      // Check if key already exists
      const checkResult = await ssh.execCommand(`grep -F "${publicKey}" ~/.ssh/authorized_keys 2>/dev/null`)
      
      if (checkResult.code === 0) {
        console.log(`[Hermes SSH] Key already exists in authorized_keys`)
        return
      }

      // Add the new public key to authorized_keys
      await ssh.execCommand(`echo "${publicKey}" >> ~/.ssh/authorized_keys`)
      
      // Set proper permissions
      await ssh.execCommand(`chmod 600 ~/.ssh/authorized_keys`)
      
      // Verify the key was added successfully
      const verifyResult = await ssh.execCommand(`grep -F "${publicKey}" ~/.ssh/authorized_keys`)
      
      if (verifyResult.code !== 0) {
        throw new Error('Failed to verify key deployment - key not found in authorized_keys')
      }

      console.log(`[Hermes SSH] Successfully deployed SSH key to ${target.host}`)
      
    } catch (error: any) {
      console.error(`[Hermes SSH] Failed to deploy key to ${target.host}:`, error.message)
      throw new Error(`SSH key deployment failed: ${error.message}`)
      
    } finally {
      ssh.dispose()
    }
  }

  /**
   * Bootstrap connection method that tries multiple authentication approaches
   * This solves the circular dependency of needing SSH access to deploy SSH keys
   */
  private async establishBootstrapConnection(
    ssh: NodeSSH,
    target: { host: string; port?: number; username: string },
    jwtToken?: string
  ): Promise<void> {
    const connectionMethods = []

    // Method 1: Try with stored credentials from Context Manager
    if (jwtToken) {
      try {
        const credentials = await this.contextManagerService.getSSHCredentials(target.host, jwtToken)
        if (credentials.password) {
          connectionMethods.push({
            name: 'stored_password',
            config: {
              host: target.host,
              port: target.port || 22,
              username: target.username,
              password: credentials.password,
              tryKeyboard: true,
              readyTimeout: 10000
            }
          })
        }
        if (credentials.privateKey) {
          connectionMethods.push({
            name: 'stored_private_key',
            config: {
              host: target.host,
              port: target.port || 22,
              username: target.username,
              privateKey: credentials.privateKey,
              readyTimeout: 10000
            }
          })
        }
      } catch (error) {
        console.log(`[Hermes SSH] Could not retrieve stored SSH credentials`)
      }
    }

    // Method 2: Try with SSH agent (for existing keys)
    connectionMethods.push({
      name: 'ssh_agent',
      config: {
        host: target.host,
        port: target.port || 22,
        username: target.username,
        tryKeyboard: true,
        readyTimeout: 10000
      }
    })

    // Method 3: For DigitalOcean droplets, try with default root access
    // This works for newly created droplets where SSH keys were deployed during creation
    if (target.username === 'root') {
      // Try to get existing SSH keys from our key service that might already be on the droplet
      try {
        const existingKeys = await this.sshKeyService.listSSHKeys('system', 'bootstrap')
        for (const key of existingKeys.slice(0, 3)) { // Try up to 3 most recent keys
          try {
            const privateKey = await this.sshKeyService.getPrivateKey(key.id)
            connectionMethods.push({
              name: `existing_key_${key.id.slice(0, 8)}`,
              config: {
                host: target.host,
                port: target.port || 22,
                username: target.username,
                privateKey,
                readyTimeout: 8000
              }
            })
          } catch (keyError) {
            // Skip if can't get private key
          }
        }
      } catch (error) {
        // Skip if can't list keys
      }
    }

    // Try each connection method
    let lastError: Error | null = null
    for (const method of connectionMethods) {
      try {
        console.log(`[Hermes SSH] Attempting connection to ${target.host} using ${method.name}`)
        await ssh.connect(method.config)
        console.log(`[Hermes SSH] Successfully connected using ${method.name}`)
        return
      } catch (error) {
        console.log(`[Hermes SSH] Connection failed with ${method.name}: ${error instanceof Error ? error.message : 'Unknown error'}`)
        lastError = error instanceof Error ? error : new Error('Unknown connection error')
        
        // Dispose connection attempt before trying next method
        try {
          ssh.dispose()
        } catch (disposeError) {
          // Ignore disposal errors
        }
      }
    }

    // If all methods failed, throw the last error
    throw new Error(`All SSH connection methods failed. Last error: ${lastError?.message || 'Unknown error'}. This is expected for new deployments where SSH keys need to be deployed during droplet creation.`)
  }

  async revokeSSHKey(
    keyId: string,
    targets: string[] = []
  ): Promise<boolean> {
    const keyMetadata = await this.sshKeyService.getSSHKey(keyId)
    if (!keyMetadata) {
      throw new Error(`SSH key not found: ${keyId}`)
    }

    try {
      // If no specific targets, revoke from all known deployments
      const revocationTargets = targets.length > 0 ? targets : keyMetadata.deployedTo

      for (const target of revocationTargets) {
        await this.removeFromAuthorizedKeys(keyMetadata.publicKey, target)
      }

      await this.auditLog({
        event: 'key_revoked',
        keyId,
        details: {
          targets: revocationTargets,
          keyName: keyMetadata.name
        },
        success: true
      })

      return true
    } catch (error: any) {
      await this.auditLog({
        event: 'key_revoked',
        keyId,
        details: {
          keyName: keyMetadata.name
        },
        success: false,
        error: error.message
      })

      return false
    }
  }

  private async removeFromAuthorizedKeys(publicKey: string, target: string): Promise<void> {
    const ssh = new NodeSSH()
    
    try {
      // Parse target string (format: host:port)
      const [host, portStr] = target.split(':')
      const port = parseInt(portStr) || 22
      
      console.log(`[Hermes SSH] Removing SSH key from ${host}:${port}`)
      
      // Connect to the target server
      await ssh.connect({
        host,
        port,
        username: 'root', // This should be configurable
        tryKeyboard: true,
        readyTimeout: 10000
      })

      console.log(`[Hermes SSH] Connected to ${host} for key removal`)

      // Backup existing authorized_keys file before modification
      await ssh.execCommand(`cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.backup.$(date +%s) 2>/dev/null || true`)
      
      // Remove the specific public key from authorized_keys
      // Use grep -v to exclude the line containing the public key
      const removeCommand = `grep -v -F "${publicKey}" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp && mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys || true`
      const result = await ssh.execCommand(removeCommand)
      
      // Verify the key was removed
      const verifyResult = await ssh.execCommand(`grep -F "${publicKey}" ~/.ssh/authorized_keys 2>/dev/null`)
      
      if (verifyResult.code === 0) {
        console.log(`[Hermes SSH] Warning: Key may still exist in authorized_keys`)
      } else {
        console.log(`[Hermes SSH] Successfully removed SSH key from ${host}`)
      }
      
    } catch (error: any) {
      console.error(`[Hermes SSH] Failed to remove key from ${target}:`, error.message)
      throw new Error(`SSH key removal failed: ${error.message}`)
      
    } finally {
      ssh.dispose()
    }
  }

  private async getServerInfo(ssh: NodeSSH): Promise<any> {
    try {
      const commands = [
        'uname -s', // OS
        'uname -r', // Kernel
        'uname -m', // Architecture  
        'free -h | head -2 | tail -1 | awk \'{print $2}\'', // Memory
        'nproc', // CPU cores
        'df -h / | tail -1 | awk \'{print $2}\'' // Disk
      ]

      const results = await Promise.all(
        commands.map(cmd => ssh.execCommand(cmd))
      )

      return {
        os: results[0].stdout.trim(),
        kernel: results[1].stdout.trim(),
        architecture: results[2].stdout.trim(),
        memory: results[3].stdout.trim(),
        cpu: `${results[4].stdout.trim()} cores`,
        disk: results[5].stdout.trim()
      }
    } catch (error) {
      return {
        os: 'unknown',
        kernel: 'unknown',
        architecture: 'unknown',
        memory: 'unknown',
        cpu: 'unknown',
        disk: 'unknown'
      }
    }
  }

  async getConnection(connectionId: string): Promise<SSHConnection | null> {
    return this.activeConnections.get(connectionId) || null
  }

  async listConnections(): Promise<SSHConnection[]> {
    return Array.from(this.activeConnections.values())
  }

  async closeConnection(connectionId: string): Promise<boolean> {
    const ssh = this.connections.get(connectionId)
    const connection = this.activeConnections.get(connectionId)
    
    if (ssh && connection) {
      try {
        ssh.dispose()
        this.connections.delete(connectionId)
        this.activeConnections.delete(connectionId)
        
        // Update connection status
        connection.status = 'disconnected'
        connection.connectionDuration = Date.now() - (connection.lastConnected?.getTime() || Date.now())
        
        return true
      } catch (error) {
        console.error('Error closing SSH connection:', error)
        return false
      }
    }
    
    return false
  }

  async closeAllConnections(): Promise<void> {
    const connectionIds = Array.from(this.connections.keys())
    
    await Promise.all(
      connectionIds.map(id => this.closeConnection(id))
    )
  }

  private async auditLog(log: Omit<SSHAuditLog, 'id' | 'timestamp' | 'userId' | 'workspaceId'>): Promise<void> {
    const auditLog: SSHAuditLog = {
      id: uuidv4(),
      timestamp: new Date(),
      userId: 'system', // Would be passed from context
      workspaceId: 'system', // Would be passed from context
      ...log
    }

    // In production, this would be stored in a database
    console.log('SSH Connection Audit Log:', auditLog)
  }
}