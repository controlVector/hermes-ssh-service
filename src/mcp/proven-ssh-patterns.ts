/**
 * Proven SSH Operation Patterns for Hermes
 * Based on successful test script patterns and deployment experience
 */

import { z } from 'zod'

// PROVEN PATTERN: SSH Key Management with DigitalOcean Integration
export const ProvenSSHKeyDeploymentSchema = z.object({
  // Target configuration
  droplet_id: z.string().optional(),
  server_ip: z.string().optional(),
  ssh_keys: z.array(z.string()).optional(), // If not provided, use all account keys
  
  // Deployment strategy (PROVEN: Multi-method approach)
  deployment_methods: z.array(z.enum(['digitalocean_api', 'cloud_init', 'direct_ssh'])).default(['digitalocean_api', 'cloud_init']),
  
  // Fallback configuration
  backup_existing_keys: z.boolean().default(true),
  create_recovery_user: z.boolean().default(false),
  
  // Auth context
  digitalocean_token: z.string().optional(),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

// PROVEN PATTERN: Application Deployment Commands
export const ProvenApplicationDeploymentSchema = z.object({
  server_ip: z.string().min(1, 'Server IP required'),
  application: z.object({
    name: z.string().min(1),
    repository_url: z.string().url(),
    branch: z.string().default('main'),
    type: z.enum(['nodejs', 'python', 'go', 'static']).default('nodejs'),
    port: z.number().default(3000),
    domain: z.string().optional(),
    build_command: z.string().optional(),
    start_command: z.string().default('npm start'),
    environment_file: z.string().optional()
  }),
  deployment_path: z.string().default('/var/www'),
  use_pm2: z.boolean().default(true),
  configure_nginx: z.boolean().default(true),
  setup_ssl: z.boolean().default(false),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

// PROVEN PATTERN: System Health Check Commands  
export const ProvenHealthCheckSchema = z.object({
  server_ip: z.string().min(1),
  application_name: z.string().min(1),
  application_port: z.number().default(3000),
  check_processes: z.boolean().default(true),
  check_nginx: z.boolean().default(true),
  check_logs: z.boolean().default(true),
  check_disk_space: z.boolean().default(true),
  check_memory: z.boolean().default(true),
  workspace_id: z.string(),
  user_id: z.string(),
  jwt_token: z.string()
})

/**
 * PROVEN SSH COMMAND PATTERNS
 * These are the exact command patterns that worked in our successful deployments
 */
export class ProvenSSHCommands {
  
  /**
   * System setup commands (PROVEN: Works on Ubuntu 24.04)
   */
  static getSystemSetupCommands(nodejsVersion: string = '20'): string[] {
    return [
      // Update system
      'apt-get update && apt-get upgrade -y',
      
      // Install Node.js (PROVEN: nodesource method)
      `curl -fsSL https://deb.nodesource.com/setup_${nodejsVersion}.x | sudo -E bash -`,
      'apt-get install -y nodejs',
      
      // Install essential packages
      'apt-get install -y git nginx ufw curl wget build-essential',
      
      // Install PM2 globally
      'npm install -g pm2',
      
      // Setup firewall (PROVEN: Essential ports)
      'ufw --force enable',
      'ufw allow ssh',
      'ufw allow http', 
      'ufw allow https'
    ]
  }

  /**
   * Application deployment commands (PROVEN: Works with Node.js apps)
   */
  static getApplicationDeploymentCommands(config: {
    appName: string
    repositoryUrl: string
    branch: string
    deploymentPath: string
    buildCommand?: string
    startCommand: string
    port: number
  }): string[] {
    const appDir = `${config.deploymentPath}/${config.appName.toLowerCase()}`
    
    return [
      // Create deployment directory
      `mkdir -p ${config.deploymentPath}`,
      `cd ${config.deploymentPath}`,
      
      // Clone repository (PROVEN: Remove existing, fresh clone)
      `rm -rf ${config.appName.toLowerCase()}`,
      `git clone ${config.repositoryUrl} -b ${config.branch} ${config.appName.toLowerCase()}`,
      
      // Install dependencies
      `cd ${appDir}`,
      'npm install',
      
      // Build if needed
      config.buildCommand ? `npm run ${config.buildCommand}` : 'echo "No build command specified"',
      
      // Stop existing PM2 process if running
      `pm2 delete ${config.appName.toLowerCase()} 2>/dev/null || echo "No existing process"`,
      
      // Start with PM2 (PROVEN: Named process with auto-restart)
      `pm2 start ${config.startCommand} --name "${config.appName.toLowerCase()}"`,
      'pm2 startup',
      'pm2 save'
    ]
  }

  /**
   * Nginx configuration commands (PROVEN: Reverse proxy pattern)
   */
  static getNginxConfigCommands(config: {
    appName: string
    domain?: string
    port: number
    enableSSL: boolean
  }): string[] {
    const siteName = config.appName.toLowerCase()
    const serverName = config.domain || '_'
    
    const nginxConfig = `server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    server_name ${serverName};
    
    location / {
        proxy_pass http://localhost:${config.port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \\$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \\$host;
        proxy_set_header X-Real-IP \\$remote_addr;
        proxy_set_header X-Forwarded-For \\$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \\$scheme;
        proxy_cache_bypass \\$http_upgrade;
        
        # Fallback for application downtime
        error_page 502 503 504 /50x.html;
    }
    
    location = /50x.html {
        root /usr/share/nginx/html;
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://localhost:${config.port}/health;
        access_log off;
    }
}`

    return [
      // Create nginx site configuration
      `cat > /etc/nginx/sites-available/${siteName} <<'EOF'
${nginxConfig}
EOF`,
      
      // Enable site (PROVEN: Remove default, enable custom)
      'rm -f /etc/nginx/sites-enabled/default',
      `ln -sf /etc/nginx/sites-available/${siteName} /etc/nginx/sites-enabled/`,
      
      // Test and reload nginx
      'nginx -t',
      'systemctl reload nginx',
      'systemctl enable nginx'
    ]
  }

  /**
   * Health check commands (PROVEN: Comprehensive system check)
   */
  static getHealthCheckCommands(config: {
    appName: string
    port: number
    checkLogs: boolean
  }): string[] {
    const commands = [
      // System status
      'echo "=== SYSTEM STATUS ==="',
      'date',
      'uptime',
      'df -h',
      'free -m',
      
      // Process status
      'echo "=== PROCESS STATUS ==="',
      `pm2 show ${config.appName.toLowerCase()} 2>/dev/null || echo "PM2 process not found"`,
      'pm2 list',
      
      // Network status
      'echo "=== NETWORK STATUS ==="',
      `ss -tlnp | grep -E ':(80|443|${config.port}|22)\\s' || echo "No services listening on expected ports"`,
      
      // Nginx status
      'echo "=== NGINX STATUS ==="',
      'systemctl status nginx --no-pager',
      
      // Application connectivity test
      'echo "=== APPLICATION TEST ==="',
      `curl -s -o /dev/null -w "HTTP Status: %{http_code}\\nResponse Time: %{time_total}s\\n" http://localhost:${config.port}/ || echo "Application not accessible"`,
      
      // Check for errors in logs
      'echo "=== ERROR CHECK ==="',
      'journalctl -u nginx --no-pager --lines=5 | grep -i error || echo "No recent nginx errors"'
    ]
    
    if (config.checkLogs) {
      commands.push(
        // Application logs
        'echo "=== APPLICATION LOGS (last 10 lines) ==="',
        `pm2 logs ${config.appName.toLowerCase()} --lines 10 --nostream || echo "No PM2 logs available"`
      )
    }
    
    return commands
  }

  /**
   * Recovery commands (PROVEN: Fix common deployment issues)
   */
  static getRecoveryCommands(action: 'restart_app' | 'restart_nginx' | 'clear_logs' | 'fix_permissions' | 'full_recovery', appName: string): string[] {
    const commands: Record<string, string[]> = {
      restart_app: [
        `pm2 restart ${appName.toLowerCase()}`,
        'pm2 save'
      ],
      
      restart_nginx: [
        'nginx -t',
        'systemctl restart nginx'
      ],
      
      clear_logs: [
        `pm2 flush ${appName.toLowerCase()}`,
        'journalctl --rotate',
        'journalctl --vacuum-time=1d'
      ],
      
      fix_permissions: [
        `chown -R www-data:www-data /var/www/${appName.toLowerCase()}`,
        `chmod -R 755 /var/www/${appName.toLowerCase()}`
      ],
      
      full_recovery: [
        // Stop services
        `pm2 delete ${appName.toLowerCase()} || echo "App not running"`,
        'systemctl stop nginx',
        
        // Clear caches
        'npm cache clean --force',
        `cd /var/www/${appName.toLowerCase()} && rm -rf node_modules`,
        
        // Reinstall and restart
        `cd /var/www/${appName.toLowerCase()} && npm install`,
        `cd /var/www/${appName.toLowerCase()} && pm2 start npm --name "${appName.toLowerCase()}" -- start`,
        'pm2 save',
        
        // Restart nginx
        'systemctl start nginx'
      ]
    }
    
    return commands[action] || []
  }
}

// Export the proven MCP tools
export const HERMES_PROVEN_TOOLS = [
  {
    name: 'hermes_deploy_ssh_keys_proven',
    description: 'Deploy SSH keys using proven multi-method approach with DigitalOcean integration',
    inputSchema: ProvenSSHKeyDeploymentSchema
  },
  {
    name: 'hermes_deploy_application_proven', 
    description: 'Deploy application using proven command patterns and best practices',
    inputSchema: ProvenApplicationDeploymentSchema
  },
  {
    name: 'hermes_health_check_proven',
    description: 'Comprehensive health check using proven diagnostic commands',
    inputSchema: ProvenHealthCheckSchema
  }
]