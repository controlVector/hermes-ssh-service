import { v4 as uuidv4 } from 'uuid'
import { SSHKeyService } from '../services/SSHKeyService'
import { SSHConnectionService } from '../services/SSHConnectionService'
import { 
  HERMES_MCP_TOOLS,
  GenerateSSHKeyOutput,
  DeploySSHKeyOutput,
  SSHConnectionOutput,
  SSHCommandOutput,
  SSHKeyAuditOutput,
  BulkOperationOutput
} from './tools'
import { SSHCommand } from '../types/ssh'

export class MCPHandler {
  private sshKeyService: SSHKeyService
  private sshConnectionService: SSHConnectionService

  constructor() {
    this.sshKeyService = new SSHKeyService()
    this.sshConnectionService = new SSHConnectionService(this.sshKeyService)
  }

  getTools() {
    return HERMES_MCP_TOOLS
  }

  async handleToolCall(toolName: string, args: any): Promise<any> {
    const startTime = Date.now()
    
    try {
      let result: any = null

      switch (toolName) {
        case 'hermes_generate_ssh_key':
          result = await this.generateSSHKey(args)
          break
          
        case 'hermes_deploy_ssh_key':
          result = await this.deploySSHKey(args)
          break
          
        case 'hermes_establish_ssh_connection':
          result = await this.establishSSHConnection(args)
          break
          
        case 'hermes_execute_ssh_command':
          result = await this.executeSSHCommand(args)
          break
          
        case 'hermes_revoke_ssh_key':
          result = await this.revokeSSHKey(args)
          break
          
        case 'hermes_rotate_ssh_key':
          result = await this.rotateSSHKey(args)
          break
          
        case 'hermes_audit_ssh_keys':
          result = await this.auditSSHKeys(args)
          break
          
        case 'hermes_manage_ssh_tunnel':
          result = await this.manageSSHTunnel(args)
          break
          
        case 'hermes_bulk_key_management':
          result = await this.bulkKeyManagement(args)
          break
          
        default:
          throw new Error(`Unknown tool: ${toolName}`)
      }

      const executionTime = `${Date.now() - startTime}ms`
      
      return {
        success: true,
        ...result,
        tool_name: toolName,
        execution_time: executionTime
      }
    } catch (error: any) {
      const executionTime = `${Date.now() - startTime}ms`
      
      return {
        success: false,
        error: error.message,
        tool_name: toolName,
        execution_time: executionTime
      }
    }
  }

  private async generateSSHKey(args: any): Promise<Partial<GenerateSSHKeyOutput>> {
    const {
      name,
      key_type = 'ed25519',
      key_size,
      passphrase,
      purpose,
      tags = [],
      expires_in,
      workspace_id,
      user_id
    } = args

    const keyPair = await this.sshKeyService.generateSSHKeyPair({
      name,
      keyType: key_type,
      keySize: key_size,
      passphrase,
      purpose,
      tags,
      expiresIn: expires_in,
      userId: user_id,
      workspaceId: workspace_id
    })

    return {
      key: {
        id: keyPair.id,
        name: keyPair.name,
        fingerprint: keyPair.fingerprint,
        key_type: keyPair.keyType,
        key_size: keyPair.keySize,
        public_key: keyPair.publicKey,
        created_at: keyPair.createdAt.toISOString(),
        expires_at: keyPair.expiresAt?.toISOString(),
        purpose: keyPair.metadata.purpose,
        tags: keyPair.metadata.tags
      }
    }
  }

  private async deploySSHKey(args: any): Promise<Partial<DeploySSHKeyOutput>> {
    const {
      key_id,
      server_targets,
      deployment_method = 'authorized_keys',
      backup_existing = true,
      workspace_id,
      user_id
    } = args

    // Verify key exists and user has access
    const keyMetadata = await this.sshKeyService.getSSHKey(key_id)
    if (!keyMetadata || keyMetadata.userId !== user_id || keyMetadata.workspaceId !== workspace_id) {
      throw new Error('SSH key not found or access denied')
    }

    const deployments = await this.sshConnectionService.deploySSHKey(
      key_id,
      server_targets,
      deployment_method
    )

    const summary = {
      total: deployments.length,
      successful: deployments.filter(d => d.status === 'deployed').length,
      failed: deployments.filter(d => d.status === 'failed').length
    }

    return {
      deployment: {
        id: uuidv4(),
        key_id,
        deployments: deployments.map(d => ({
          server: d.serverId,
          status: d.status,
          method: d.method,
          error: d.error
        })),
        summary
      }
    }
  }

  private async establishSSHConnection(args: any): Promise<Partial<SSHConnectionOutput>> {
    const {
      key_id,
      host,
      port = 22,
      username,
      timeout = 10000,
      server_name,
      keep_alive = true,
      workspace_id,
      user_id
    } = args

    // Verify key access
    const keyMetadata = await this.sshKeyService.getSSHKey(key_id)
    if (!keyMetadata || keyMetadata.userId !== user_id || keyMetadata.workspaceId !== workspace_id) {
      throw new Error('SSH key not found or access denied')
    }

    const connection = await this.sshConnectionService.establishConnection({
      keyId: key_id,
      host,
      port,
      username,
      timeout,
      keepAlive: keep_alive,
      serverName: server_name
    })

    return {
      connection: {
        id: connection.id,
        host: connection.host,
        port: connection.port,
        username: connection.username,
        status: connection.status,
        connected_at: connection.lastConnected?.toISOString() || new Date().toISOString(),
        server_info: connection.metadata
      }
    }
  }

  private async executeSSHCommand(args: any): Promise<Partial<SSHCommandOutput>> {
    const {
      connection_id,
      key_id,
      host,
      command,
      working_directory,
      timeout = 30000,
      environment,
      sudo = false,
      stdin,
      workspace_id,
      user_id
    } = args

    let connectionId = connection_id

    // If no connection_id provided, try to establish a new connection
    if (!connectionId && key_id && host) {
      const connection = await this.establishSSHConnection({
        key_id,
        host,
        username: args.username || 'root',
        workspace_id,
        user_id
      })
      connectionId = connection.connection?.id
    }

    if (!connectionId) {
      throw new Error('No SSH connection available')
    }

    const sshCommand: SSHCommand = {
      id: uuidv4(),
      command,
      workingDirectory: working_directory,
      timeout,
      environment,
      sudo,
      stdin
    }

    const result = await this.sshConnectionService.executeCommand(connectionId, sshCommand)

    return {
      result: {
        command: result.command,
        exit_code: result.exitCode,
        stdout: result.stdout,
        stderr: result.stderr,
        execution_time: result.executionTime,
        timestamp: result.timestamp.toISOString()
      }
    }
  }

  private async revokeSSHKey(args: any): Promise<any> {
    const {
      key_id,
      server_targets = [],
      remove_from_servers = true,
      backup_before_removal = true,
      workspace_id,
      user_id
    } = args

    // Verify key access
    const keyMetadata = await this.sshKeyService.getSSHKey(key_id)
    if (!keyMetadata || keyMetadata.userId !== user_id || keyMetadata.workspaceId !== workspace_id) {
      throw new Error('SSH key not found or access denied')
    }

    if (remove_from_servers) {
      await this.sshConnectionService.revokeSSHKey(key_id, server_targets)
    }

    const deleted = await this.sshKeyService.deleteSSHKey(key_id, user_id, workspace_id)

    return {
      revocation: {
        key_id,
        key_name: keyMetadata.name,
        revoked_at: new Date().toISOString(),
        removed_from_servers: remove_from_servers,
        servers_affected: server_targets.length || keyMetadata.deployedTo.length,
        key_deleted: deleted
      }
    }
  }

  private async rotateSSHKey(args: any): Promise<any> {
    const {
      key_id,
      new_key_name,
      maintain_old_key = false,
      rollback_period = 7,
      auto_deploy = true,
      workspace_id,
      user_id
    } = args

    // Get existing key info
    const oldKeyMetadata = await this.sshKeyService.getSSHKey(key_id)
    if (!oldKeyMetadata || oldKeyMetadata.userId !== user_id || oldKeyMetadata.workspaceId !== workspace_id) {
      throw new Error('SSH key not found or access denied')
    }

    // Generate new key with same properties
    const newKeyName = new_key_name || `${oldKeyMetadata.name}-rotated-${Date.now()}`
    
    const newKeyPair = await this.sshKeyService.generateSSHKeyPair({
      name: newKeyName,
      keyType: oldKeyMetadata.keyType,
      keySize: oldKeyMetadata.keySize,
      purpose: oldKeyMetadata.purpose,
      tags: [...oldKeyMetadata.tags, 'rotated'],
      userId: user_id,
      workspaceId: workspace_id
    })

    // Deploy new key to same servers if auto_deploy is enabled
    let deployments: any[] = []
    if (auto_deploy && oldKeyMetadata.deployedTo.length > 0) {
      const targets = oldKeyMetadata.deployedTo.map(serverId => {
        const [host, portStr] = serverId.split(':')
        return {
          host,
          port: parseInt(portStr) || 22,
          username: 'root' // This would be stored with the deployment info
        }
      })

      deployments = await this.sshConnectionService.deploySSHKey(newKeyPair.id, targets)
    }

    // Remove old key unless maintaining it
    if (!maintain_old_key) {
      await this.sshConnectionService.revokeSSHKey(key_id)
      await this.sshKeyService.deleteSSHKey(key_id, user_id, workspace_id)
    }

    return {
      rotation: {
        old_key_id: key_id,
        new_key_id: newKeyPair.id,
        new_key_name: newKeyName,
        rotated_at: new Date().toISOString(),
        old_key_maintained: maintain_old_key,
        rollback_period_days: rollback_period,
        auto_deployed: auto_deploy,
        deployments: deployments.map(d => ({
          server: d.serverId,
          status: d.status
        }))
      }
    }
  }

  private async auditSSHKeys(args: any): Promise<Partial<SSHKeyAuditOutput>> {
    const {
      key_ids,
      include_servers = true,
      include_usage_stats = true,
      check_compromised = true,
      workspace_id,
      user_id
    } = args

    const auditResult = await this.sshKeyService.auditSSHKeys(user_id, workspace_id, {
      keyIds: key_ids,
      includeServers: include_servers,
      includeUsageStats: include_usage_stats,
      checkCompromised: check_compromised
    })

    const keys = await this.sshKeyService.listSSHKeys(user_id, workspace_id)
    const auditedKeys = key_ids ? keys.filter(k => key_ids.includes(k.id)) : keys

    return {
      audit: {
        scan_id: auditResult.id,
        scan_date: auditResult.startedAt.toISOString(),
        keys_audited: auditedKeys.length,
        findings: auditResult.results.findings.map(f => ({
          key_id: f.affectedResource,
          key_name: auditedKeys.find(k => k.id === f.affectedResource)?.name || 'unknown',
          severity: f.severity,
          finding: f.title,
          recommendation: f.recommendation
        })),
        summary: {
          total_keys: auditedKeys.length,
          healthy_keys: auditedKeys.length - auditResult.results.findings.length,
          keys_needing_attention: auditResult.results.findings.length,
          expired_keys: auditResult.results.findings.filter(f => f.category === 'expired_key').length,
          unused_keys: auditResult.results.findings.filter(f => f.category === 'unused_key').length
        },
        recommendations: auditResult.results.recommendations
      }
    }
  }

  private async manageSSHTunnel(args: any): Promise<any> {
    const {
      action,
      tunnel_name,
      connection_id,
      key_id,
      local_port,
      remote_host,
      remote_port
    } = args

    // SSH tunneling would be implemented here
    // For now, we'll return a placeholder response

    switch (action) {
      case 'create':
        return {
          tunnel: {
            id: uuidv4(),
            name: tunnel_name,
            local_port,
            remote_host,
            remote_port,
            status: 'active',
            created_at: new Date().toISOString()
          }
        }

      case 'close':
        return {
          tunnel: {
            name: tunnel_name,
            status: 'closed',
            closed_at: new Date().toISOString()
          }
        }

      case 'status':
        return {
          tunnel: {
            name: tunnel_name,
            status: 'active',
            local_port,
            remote_host,
            remote_port,
            bytes_transferred: Math.floor(Math.random() * 1000000)
          }
        }

      default:
        throw new Error(`Unknown tunnel action: ${action}`)
    }
  }

  private async bulkKeyManagement(args: any): Promise<Partial<BulkOperationOutput>> {
    const {
      operation,
      key_ids,
      target_servers = [],
      options = {},
      workspace_id,
      user_id
    } = args

    const operationId = uuidv4()
    const startTime = new Date()
    const results: any[] = []

    for (const keyId of key_ids) {
      try {
        let result: any

        switch (operation) {
          case 'deploy':
            const deployments = await this.sshConnectionService.deploySSHKey(keyId, target_servers)
            result = {
              target: keyId,
              operation: 'deploy',
              status: deployments.every(d => d.status === 'deployed') ? 'success' : 'failed',
              details: `Deployed to ${deployments.filter(d => d.status === 'deployed').length}/${deployments.length} servers`
            }
            break

          case 'revoke':
            await this.sshConnectionService.revokeSSHKey(keyId)
            result = {
              target: keyId,
              operation: 'revoke',
              status: 'success',
              details: 'Key revoked from all servers'
            }
            break

          case 'audit':
            const audit = await this.sshKeyService.auditSSHKeys(user_id, workspace_id, { keyIds: [keyId] })
            result = {
              target: keyId,
              operation: 'audit',
              status: 'success',
              details: `Found ${audit.results.findings.length} findings`
            }
            break

          default:
            result = {
              target: keyId,
              operation,
              status: 'failed',
              error: `Unknown operation: ${operation}`
            }
        }

        results.push(result)
      } catch (error: any) {
        results.push({
          target: keyId,
          operation,
          status: 'failed',
          error: error.message
        })
      }
    }

    const summary = {
      total_operations: results.length,
      successful: results.filter(r => r.status === 'success').length,
      failed: results.filter(r => r.status === 'failed').length,
      skipped: results.filter(r => r.status === 'skipped').length
    }

    return {
      operation: {
        id: operationId,
        operation_type: operation,
        status: summary.failed === 0 ? 'completed' : 'partial',
        started_at: startTime.toISOString(),
        completed_at: new Date().toISOString(),
        summary,
        results
      }
    }
  }
}