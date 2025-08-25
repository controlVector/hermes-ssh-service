export interface SSHKeyPair {
  id: string
  name: string
  publicKey: string
  privateKey: string
  fingerprint: string
  keyType: 'rsa' | 'ed25519' | 'ecdsa'
  keySize: number
  createdAt: Date
  expiresAt?: Date
  passphrase?: string
  metadata: {
    userId: string
    workspaceId: string
    purpose: string
    tags: string[]
  }
}

export interface SSHKeyMetadata {
  id: string
  name: string
  fingerprint: string
  keyType: 'rsa' | 'ed25519' | 'ecdsa'
  keySize: number
  publicKey: string
  createdAt: Date
  expiresAt?: Date
  lastUsed?: Date
  deployedTo: string[] // List of server IDs
  purpose: string
  tags: string[]
  userId: string
  workspaceId: string
}

export interface SSHConnection {
  id: string
  host: string
  port: number
  username: string
  keyId: string
  status: 'connected' | 'disconnected' | 'error' | 'connecting'
  lastConnected?: Date
  connectionDuration?: number
  metadata: {
    serverName?: string
    provider?: string
    region?: string
    purpose?: string
  }
}

export interface SSHCommand {
  id: string
  command: string
  workingDirectory?: string
  timeout: number
  environment?: Record<string, string>
  sudo?: boolean
  stdin?: string
}

export interface SSHCommandResult {
  id: string
  command: string
  exitCode: number
  stdout: string
  stderr: string
  executionTime: number
  timestamp: Date
  success: boolean
}

export interface ServerInfo {
  id: string
  hostname: string
  ipAddress: string
  port: number
  username: string
  provider?: string
  region?: string
  tags?: string[]
  sshKeyIds: string[]
  status: 'active' | 'inactive' | 'unreachable'
  lastChecked?: Date
  systemInfo?: {
    os: string
    kernel: string
    architecture: string
    memory: string
    cpu: string
    disk: string
  }
}

export interface KeyDeployment {
  id: string
  keyId: string
  serverId: string
  status: 'pending' | 'deployed' | 'failed' | 'revoked'
  deployedAt?: Date
  revokedAt?: Date
  method: 'authorized_keys' | 'cloud_init' | 'manual'
  error?: string
}

export interface SSHTunnel {
  id: string
  name: string
  localPort: number
  remoteHost: string
  remotePort: number
  sshConnection: string
  status: 'active' | 'inactive' | 'error'
  createdAt: Date
  bytesTransferred: number
}

export interface KeyRotationPolicy {
  id: string
  name: string
  keyIds: string[]
  rotationInterval: number // days
  warningInterval: number // days before rotation
  autoRotate: boolean
  backupOldKeys: boolean
  notificationChannels: string[]
  lastRotation?: Date
  nextRotation: Date
}

export interface SSHAuditLog {
  id: string
  timestamp: Date
  event: 'key_generated' | 'key_deployed' | 'key_revoked' | 'connection_established' | 
         'connection_failed' | 'command_executed' | 'tunnel_created' | 'key_rotated'
  userId: string
  workspaceId: string
  keyId?: string
  serverId?: string
  details: Record<string, any>
  ipAddress?: string
  userAgent?: string
  success: boolean
  error?: string
}

export interface HermesConfig {
  keyStorage: {
    encryption: boolean
    backupEnabled: boolean
    backupInterval: number
    retention: number
  }
  keyGeneration: {
    defaultKeyType: 'rsa' | 'ed25519' | 'ecdsa'
    defaultKeySize: number
    allowWeakKeys: boolean
    requirePassphrase: boolean
  }
  security: {
    maxConcurrentConnections: number
    connectionTimeout: number
    commandTimeout: number
    auditLogging: boolean
    requireMFA: boolean
  }
  rotation: {
    defaultInterval: number
    warningThreshold: number
    autoRotateEnabled: boolean
  }
}

export interface KeyGenerationOptions {
  name: string
  keyType: 'rsa' | 'ed25519' | 'ecdsa'
  keySize?: number
  passphrase?: string
  purpose: string
  tags?: string[]
  expiresIn?: number // days
  userId: string
  workspaceId: string
}

export interface ConnectionOptions {
  host: string
  port?: number
  username: string
  keyId: string
  timeout?: number
  keepAlive?: boolean
  serverName?: string
}

export interface DeploymentTarget {
  id: string
  name: string
  host: string
  port: number
  username: string
  provider?: string
  region?: string
  tags?: string[]
  sshKeyIds?: string[]
}

export interface BulkKeyDeployment {
  id: string
  keyIds: string[]
  targetIds: string[]
  status: 'pending' | 'in_progress' | 'completed' | 'failed'
  startedAt?: Date
  completedAt?: Date
  deployments: KeyDeployment[]
  summary: {
    total: number
    successful: number
    failed: number
    pending: number
  }
}

export interface SecurityScan {
  id: string
  targetId: string
  scanType: 'key_audit' | 'connection_test' | 'security_check' | 'compliance_check'
  status: 'running' | 'completed' | 'failed'
  startedAt: Date
  completedAt?: Date
  results: {
    findings: SecurityFinding[]
    score: number
    recommendations: string[]
    critical: number
    high: number
    medium: number
    low: number
  }
}

export interface SecurityFinding {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  category: 'weak_key' | 'expired_key' | 'unused_key' | 'weak_auth' | 'config_issue'
  title: string
  description: string
  recommendation: string
  affectedResource: string
  remediation?: {
    automated: boolean
    steps: string[]
    estimatedTime: number
  }
}