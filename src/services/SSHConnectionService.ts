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

export class SSHConnectionService {
  private connections = new Map<string, NodeSSH>()
  private activeConnections = new Map<string, SSHConnection>()
  private sshKeyService: SSHKeyService

  constructor(sshKeyService: SSHKeyService) {
    this.sshKeyService = sshKeyService
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
    target: { host: string; port?: number; username: string }
  ): Promise<void> {
    // This would typically use an existing SSH connection or root access
    // For now, we'll simulate the deployment
    
    // In a real implementation, this would:
    // 1. Connect to the target server with existing credentials
    // 2. Backup existing authorized_keys file
    // 3. Add the new public key to ~/.ssh/authorized_keys
    // 4. Set proper permissions (600 for authorized_keys, 700 for .ssh)
    // 5. Verify the key was added successfully

    console.log(`Simulating deployment of key to ${target.host}`)
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 1000))
    
    // For demo purposes, we'll assume success
    // In production, this would perform the actual deployment
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
    // This would connect to the target server and remove the public key
    // from the authorized_keys file
    console.log(`Simulating revocation of key from ${target}`)
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 500))
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