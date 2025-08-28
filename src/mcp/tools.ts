import { z } from 'zod'

// Input schemas for Hermes MCP tools
export const GenerateSSHKeySchema = z.object({
  name: z.string().min(1, 'Key name is required'),
  key_type: z.enum(['rsa', 'ed25519', 'ecdsa']).default('ed25519'),
  key_size: z.number().min(1024).max(8192).optional(),
  passphrase: z.string().optional(),
  purpose: z.string().min(1, 'Purpose is required'),
  tags: z.array(z.string()).default([]),
  expires_in: z.number().min(1).max(3650).optional(), // days
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

export const DeploySSHKeySchema = z.object({
  key_id: z.string(),
  server_targets: z.array(z.object({
    host: z.string(),
    port: z.number().default(22),
    username: z.string(),
    server_name: z.string().optional(),
    provider: z.string().optional()
  })).default([]),
  deployment_method: z.enum(['authorized_keys', 'cloud_init', 'manual']).default('authorized_keys'),
  backup_existing: z.boolean().default(true),
  deploy_to_all_droplets: z.boolean().default(false),
  provider: z.enum(['digitalocean']).default('digitalocean'),
  add_to_provider_account: z.boolean().default(true),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

export const EstablishSSHConnectionSchema = z.object({
  key_id: z.string(),
  host: z.string(),
  port: z.number().default(22),
  username: z.string(),
  timeout: z.number().default(10000),
  server_name: z.string().optional(),
  keep_alive: z.boolean().default(true),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

export const ExecuteSSHCommandSchema = z.object({
  connection_id: z.string().optional(),
  key_id: z.string().optional(),
  host: z.string().optional(),
  command: z.string().min(1, 'Command is required'),
  working_directory: z.string().optional(),
  timeout: z.number().default(30000),
  environment: z.record(z.string()).optional(),
  sudo: z.boolean().default(false),
  stdin: z.string().optional(),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

export const RevokeSSHKeySchema = z.object({
  key_id: z.string(),
  server_targets: z.array(z.string()).optional(), // Server IDs, if not provided will revoke from all
  remove_from_servers: z.boolean().default(true),
  backup_before_removal: z.boolean().default(true),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

export const RotateSSHKeySchema = z.object({
  key_id: z.string(),
  new_key_name: z.string().optional(),
  maintain_old_key: z.boolean().default(false), // Keep old key for rollback period
  rollback_period: z.number().default(7), // days
  auto_deploy: z.boolean().default(true),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

export const AuditSSHKeysSchema = z.object({
  key_ids: z.array(z.string()).optional(), // If not provided, audit all keys
  include_servers: z.boolean().default(true),
  include_usage_stats: z.boolean().default(true),
  check_compromised: z.boolean().default(true),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

export const ManageSSHTunnelSchema = z.object({
  action: z.enum(['create', 'close', 'status']),
  tunnel_name: z.string(),
  connection_id: z.string().optional(),
  key_id: z.string().optional(),
  local_port: z.number().min(1024).max(65535),
  remote_host: z.string(),
  remote_port: z.number().min(1).max(65535),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

export const BulkKeyManagementSchema = z.object({
  operation: z.enum(['deploy', 'revoke', 'rotate', 'audit']),
  key_ids: z.array(z.string()),
  target_servers: z.array(z.object({
    host: z.string(),
    port: z.number().default(22),
    username: z.string(),
    server_name: z.string().optional()
  })).optional(),
  options: z.record(z.any()).optional(),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

// New systematic SSH execution schema
export const SystematicSSHExecutionSchema = z.object({
  serverId: z.string().min(1, 'Server ID/IP is required'),
  command: z.string().min(1, 'Command is required'),
  workingDirectory: z.string().optional(),
  timeout: z.number().default(30000),
  environment: z.record(z.string()).optional(),
  sudo: z.boolean().default(false),
  userId: z.string().min(1, 'User ID is required'),
  workspaceId: z.string().min(1, 'Workspace ID is required'),
  jwt_token: z.string().min(1, 'JWT token is required'),
  // Session-aware fields for cross-conversation SSH key persistence
  sessionId: z.string().optional(),
  conversationId: z.string().optional()
})

export const HERMES_MCP_TOOLS = [
  {
    name: 'hermes_execute_ssh_command_v2',
    description: 'Execute SSH command with automatic session management, key discovery, and proper error handling. This is the systematic abstraction for all SSH operations based on CLI POC learnings.',
    inputSchema: SystematicSSHExecutionSchema
  },
  {
    name: 'hermes_generate_ssh_key',
    description: 'Generate new SSH key pair with secure storage and metadata',
    inputSchema: GenerateSSHKeySchema
  },
  {
    name: 'hermes_deploy_ssh_key',
    description: 'Deploy SSH public key to target servers for secure access',
    inputSchema: DeploySSHKeySchema
  },
  {
    name: 'hermes_establish_ssh_connection',
    description: 'Establish secure SSH connection to server using managed keys',
    inputSchema: EstablishSSHConnectionSchema
  },
  {
    name: 'hermes_execute_ssh_command',
    description: 'Execute commands on remote servers through secure SSH connections',
    inputSchema: ExecuteSSHCommandSchema
  },
  {
    name: 'hermes_revoke_ssh_key',
    description: 'Revoke SSH key access from servers and remove from authorized_keys',
    inputSchema: RevokeSSHKeySchema
  },
  {
    name: 'hermes_rotate_ssh_key',
    description: 'Rotate SSH keys with automatic deployment and rollback support',
    inputSchema: RotateSSHKeySchema
  },
  {
    name: 'hermes_audit_ssh_keys',
    description: 'Audit SSH keys for security compliance and usage analysis',
    inputSchema: AuditSSHKeysSchema
  },
  {
    name: 'hermes_manage_ssh_tunnel',
    description: 'Create and manage SSH tunnels for secure service access',
    inputSchema: ManageSSHTunnelSchema
  },
  {
    name: 'hermes_bulk_key_management',
    description: 'Perform bulk operations on multiple SSH keys and servers',
    inputSchema: BulkKeyManagementSchema
  }
]

// Output types for MCP tools
export interface GenerateSSHKeyOutput {
  success: boolean
  key?: {
    id: string
    name: string
    fingerprint: string
    key_type: string
    key_size: number
    public_key: string
    created_at: string
    expires_at?: string
    purpose: string
    tags: string[]
  }
  error?: string
  tool_name: string
  execution_time?: string
}

export interface DeploySSHKeyOutput {
  success: boolean
  deployment?: {
    id: string
    key_id: string
    deployments: Array<{
      server: string
      status: 'deployed' | 'failed'
      method: string
      error?: string
    }>
    summary: {
      total: number
      successful: number
      failed: number
    }
  }
  error?: string
  tool_name: string
  execution_time?: string
}

export interface SSHConnectionOutput {
  success: boolean
  connection?: {
    id: string
    host: string
    port: number
    username: string
    status: 'connected' | 'error'
    connected_at: string
    server_info?: {
      os: string
      architecture: string
      uptime: string
    }
  }
  error?: string
  tool_name: string
  execution_time?: string
}

export interface SSHCommandOutput {
  success: boolean
  result?: {
    command: string
    exit_code: number
    stdout: string
    stderr: string
    execution_time: number
    timestamp: string
  }
  error?: string
  tool_name: string
  execution_time?: string
}

export interface SSHKeyAuditOutput {
  success: boolean
  audit?: {
    scan_id: string
    scan_date: string
    keys_audited: number
    findings: Array<{
      key_id: string
      key_name: string
      severity: 'critical' | 'high' | 'medium' | 'low'
      finding: string
      recommendation: string
    }>
    summary: {
      total_keys: number
      healthy_keys: number
      keys_needing_attention: number
      expired_keys: number
      unused_keys: number
    }
    recommendations: string[]
  }
  error?: string
  tool_name: string
  execution_time?: string
}

export interface BulkOperationOutput {
  success: boolean
  operation?: {
    id: string
    operation_type: string
    status: 'completed' | 'partial' | 'failed'
    started_at: string
    completed_at: string
    summary: {
      total_operations: number
      successful: number
      failed: number
      skipped: number
    }
    results: Array<{
      target: string
      operation: string
      status: 'success' | 'failed' | 'skipped'
      details?: string
      error?: string
    }>
  }
  error?: string
  tool_name: string
  execution_time?: string
}