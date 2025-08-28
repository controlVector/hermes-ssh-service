import { z } from 'zod'

// Deployment-specific SSH tools for application deployment automation

export const DeployApplicationSchema = z.object({
  serverId: z.string().min(1, 'Server ID/IP is required'),
  repository: z.object({
    url: z.string().url('Valid repository URL required'),
    branch: z.string().default('main'),
    path: z.string().default('/var/www')
  }),
  application: z.object({
    name: z.string().min(1, 'Application name required'),
    type: z.enum(['nodejs', 'python', 'go', 'static', 'docker']).default('nodejs'),
    port: z.number().default(3000),
    buildCommand: z.string().optional(),
    startCommand: z.string().optional(),
    environmentFile: z.string().optional()
  }),
  server: z.object({
    username: z.string().default('root'),
    port: z.number().default(22)
  }),
  deployment: z.object({
    strategy: z.enum(['pm2', 'systemd', 'docker', 'static']).default('pm2'),
    healthCheck: z.object({
      endpoint: z.string().default('/health'),
      timeout: z.number().default(30000)
    }).optional()
  }),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

export const ConfigureNginxSchema = z.object({
  serverId: z.string().min(1, 'Server ID/IP is required'),
  domain: z.string().min(1, 'Domain is required'),
  applicationPort: z.number().default(3000),
  sslEnabled: z.boolean().default(false),
  customConfig: z.string().optional(),
  server: z.object({
    username: z.string().default('root'),
    port: z.number().default(22)
  }),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

export const SetupSSLSchema = z.object({
  serverId: z.string().min(1, 'Server ID/IP is required'),
  domain: z.string().min(1, 'Domain is required'),
  email: z.string().email('Valid email required').default('admin@controlvector.io'),
  provider: z.enum(['letsencrypt', 'custom']).default('letsencrypt'),
  server: z.object({
    username: z.string().default('root'),
    port: z.number().default(22)
  }),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

export const ServerSetupSchema = z.object({
  serverId: z.string().min(1, 'Server ID/IP is required'),
  setup: z.object({
    updateSystem: z.boolean().default(true),
    installNodejs: z.boolean().default(true),
    nodeVersion: z.string().default('20'),
    installDocker: z.boolean().default(false),
    installNginx: z.boolean().default(true),
    setupFirewall: z.boolean().default(true),
    installPM2: z.boolean().default(true)
  }),
  server: z.object({
    username: z.string().default('root'),
    port: z.number().default(22)
  }),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

export const ApplicationHealthCheckSchema = z.object({
  serverId: z.string().min(1, 'Server ID/IP is required'),
  application: z.object({
    name: z.string().min(1, 'Application name required'),
    port: z.number().default(3000),
    healthEndpoint: z.string().default('/health'),
    expectedContent: z.string().optional()
  }),
  server: z.object({
    username: z.string().default('root'),
    port: z.number().default(22)
  }),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

export const DeploymentRecoverySchema = z.object({
  serverId: z.string().min(1, 'Server ID/IP is required'),
  recovery: z.object({
    action: z.enum(['restart_app', 'clear_locks', 'reinstall_deps', 'reset_nginx', 'full_reset']),
    applicationName: z.string().min(1, 'Application name required'),
    backupBeforeRecovery: z.boolean().default(true)
  }),
  server: z.object({
    username: z.string().default('root'),
    port: z.number().default(22)
  }),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

// Add to existing HERMES_MCP_TOOLS array
export const DEPLOYMENT_MCP_TOOLS = [
  {
    name: 'hermes_deploy_application',
    description: 'Deploy application from repository to server with full automation (clone, install, configure, start)',
    inputSchema: DeployApplicationSchema
  },
  {
    name: 'hermes_configure_nginx',
    description: 'Configure nginx reverse proxy for application with domain and SSL support',
    inputSchema: ConfigureNginxSchema
  },
  {
    name: 'hermes_setup_ssl',
    description: 'Setup SSL certificate using Let\'s Encrypt or custom certificates',
    inputSchema: SetupSSLSchema
  },
  {
    name: 'hermes_server_setup',
    description: 'Initial server setup with required software (Node.js, nginx, PM2, etc.)',
    inputSchema: ServerSetupSchema
  },
  {
    name: 'hermes_application_health_check',
    description: 'Check application health and verify deployment success',
    inputSchema: ApplicationHealthCheckSchema
  },
  {
    name: 'hermes_deployment_recovery',
    description: 'Recover from deployment failures with automated troubleshooting',
    inputSchema: DeploymentRecoverySchema
  }
]

// Output interfaces for deployment tools
export interface DeployApplicationOutput {
  success: boolean
  deployment?: {
    id: string
    applicationName: string
    status: 'deployed' | 'failed' | 'partial'
    steps: Array<{
      name: string
      status: 'completed' | 'failed' | 'skipped'
      output?: string
      error?: string
      duration: number
    }>
    endpoints: {
      application: string
      health?: string
    }
    processInfo?: {
      pid: number
      status: string
      memory: string
      uptime: string
    }
  }
  error?: string
  tool_name: string
  execution_time?: string
}

export interface ConfigureNginxOutput {
  success: boolean
  configuration?: {
    domain: string
    configPath: string
    status: 'active' | 'inactive' | 'error'
    sslEnabled: boolean
    upstreamPort: number
    testResult: {
      syntax: boolean
      canReload: boolean
    }
  }
  error?: string
  tool_name: string
  execution_time?: string
}

export interface SetupSSLOutput {
  success: boolean
  certificate?: {
    domain: string
    provider: string
    status: 'active' | 'pending' | 'failed'
    expiresAt?: string
    certificatePath?: string
    keyPath?: string
    validationMethod?: string
  }
  error?: string
  tool_name: string
  execution_time?: string
}

export interface ServerSetupOutput {
  success: boolean
  setup?: {
    serverId: string
    status: 'completed' | 'partial' | 'failed'
    installedComponents: string[]
    failedComponents: string[]
    systemInfo: {
      os: string
      architecture: string
      memory: string
      disk: string
    }
    services: Array<{
      name: string
      status: 'running' | 'stopped' | 'error'
      enabled: boolean
    }>
  }
  error?: string
  tool_name: string
  execution_time?: string
}

export interface ApplicationHealthCheckOutput {
  success: boolean
  healthCheck?: {
    applicationName: string
    status: 'healthy' | 'unhealthy' | 'unknown'
    checks: Array<{
      name: string
      status: 'pass' | 'fail'
      message: string
      responseTime?: number
    }>
    endpoints: {
      application: {
        url: string
        status: number
        responseTime: number
        content?: string
      }
      health?: {
        url: string
        status: number
        responseTime: number
        content?: string
      }
    }
    processInfo?: {
      running: boolean
      pid?: number
      memory?: string
      uptime?: string
    }
  }
  error?: string
  tool_name: string
  execution_time?: string
}

export interface DeploymentRecoveryOutput {
  success: boolean
  recovery?: {
    action: string
    status: 'completed' | 'failed' | 'partial'
    steps: Array<{
      name: string
      status: 'completed' | 'failed'
      output?: string
      error?: string
    }>
    finalState: {
      applicationRunning: boolean
      nginxRunning: boolean
      portsListening: number[]
      errors: string[]
    }
  }
  error?: string
  tool_name: string
  execution_time?: string
}