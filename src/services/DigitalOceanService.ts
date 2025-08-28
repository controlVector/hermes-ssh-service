/**
 * DigitalOcean Integration Service for Hermes
 * Manages SSH key deployment through DigitalOcean API and direct server connections
 */

import axios, { AxiosInstance } from 'axios'

export interface DropletInfo {
  id: number
  name: string
  memory: number
  vcpus: number
  disk: number
  locked: boolean
  status: 'new' | 'active' | 'off' | 'archive'
  kernel: any
  created_at: string
  features: string[]
  backup_ids: number[]
  snapshot_ids: number[]
  image: any
  volume_ids: string[]
  size: any
  size_slug: string
  networks: {
    v4: Array<{
      ip_address: string
      netmask: string
      gateway: string
      type: 'public' | 'private'
    }>
    v6: any[]
  }
  region: any
  tags: string[]
}

export interface SSHKeyInfo {
  id: number
  fingerprint: string
  public_key: string
  name: string
}

export class DigitalOceanService {
  private client: AxiosInstance

  constructor(private apiToken: string) {
    this.client = axios.create({
      baseURL: 'https://api.digitalocean.com/v2',
      headers: {
        'Authorization': `Bearer ${apiToken}`,
        'Content-Type': 'application/json'
      },
      timeout: 30000
    })
  }

  /**
   * List all droplets in the account
   */
  async listDroplets(): Promise<DropletInfo[]> {
    try {
      const response = await this.client.get('/droplets')
      return response.data.droplets || []
    } catch (error: any) {
      console.error('Failed to list DigitalOcean droplets:', error.response?.data || error.message)
      throw new Error(`Failed to list droplets: ${error.message}`)
    }
  }

  /**
   * Get droplet by ID
   */
  async getDroplet(dropletId: number): Promise<DropletInfo | null> {
    try {
      const response = await this.client.get(`/droplets/${dropletId}`)
      return response.data.droplet
    } catch (error: any) {
      if (error.response?.status === 404) {
        return null
      }
      throw new Error(`Failed to get droplet: ${error.message}`)
    }
  }

  /**
   * Add SSH key to DigitalOcean account
   */
  async addSSHKeyToAccount(name: string, publicKey: string): Promise<SSHKeyInfo> {
    try {
      const response = await this.client.post('/account/keys', {
        name,
        public_key: publicKey
      })
      return response.data.ssh_key
    } catch (error: any) {
      console.error('Failed to add SSH key to DigitalOcean:', error.response?.data || error.message)
      throw new Error(`Failed to add SSH key: ${error.message}`)
    }
  }

  /**
   * Remove SSH key from DigitalOcean account
   */
  async removeSSHKeyFromAccount(keyId: number): Promise<void> {
    try {
      await this.client.delete(`/account/keys/${keyId}`)
    } catch (error: any) {
      console.error('Failed to remove SSH key from DigitalOcean:', error.response?.data || error.message)
      throw new Error(`Failed to remove SSH key: ${error.message}`)
    }
  }

  /**
   * List SSH keys in DigitalOcean account
   */
  async listSSHKeys(): Promise<SSHKeyInfo[]> {
    try {
      const response = await this.client.get('/account/keys')
      return response.data.ssh_keys || []
    } catch (error: any) {
      console.error('Failed to list DigitalOcean SSH keys:', error.response?.data || error.message)
      throw new Error(`Failed to list SSH keys: ${error.message}`)
    }
  }

  /**
   * Get connection details for a droplet
   */
  getDropletConnectionDetails(droplet: DropletInfo): Array<{
    host: string
    port: number
    username: string
    serverName: string
  }> {
    const connections = []
    
    // Get public IPv4 addresses
    for (const network of droplet.networks.v4) {
      if (network.type === 'public') {
        connections.push({
          host: network.ip_address,
          port: 22,
          username: 'root', // Default for DigitalOcean droplets
          serverName: droplet.name
        })
      }
    }

    return connections
  }

  /**
   * Wait for droplet to be active
   */
  async waitForDropletActive(dropletId: number, maxWaitTime = 300000): Promise<DropletInfo> {
    const startTime = Date.now()
    
    while (Date.now() - startTime < maxWaitTime) {
      const droplet = await this.getDroplet(dropletId)
      
      if (!droplet) {
        throw new Error(`Droplet ${dropletId} not found`)
      }

      if (droplet.status === 'active') {
        return droplet
      }

      if (droplet.status === 'archive') {
        throw new Error(`Droplet ${dropletId} is archived`)
      }

      // Wait 5 seconds before checking again
      await new Promise(resolve => setTimeout(resolve, 5000))
    }

    throw new Error(`Droplet ${dropletId} did not become active within ${maxWaitTime}ms`)
  }

  /**
   * Deploy SSH key to specific droplets using DigitalOcean API
   * This is useful for new droplets during creation
   */
  async deployKeyToDroplets(
    sshKeyId: number, 
    dropletIds: number[]
  ): Promise<{ success: number[], failed: number[] }> {
    const success: number[] = []
    const failed: number[] = []

    for (const dropletId of dropletIds) {
      try {
        // Note: DigitalOcean doesn't have a direct API to add keys to existing droplets
        // This would need to be done during droplet creation or via SSH
        console.log(`[DigitalOcean] Key deployment to existing droplets requires SSH connection`)
        
        // For existing droplets, we'd need to use SSH deployment
        failed.push(dropletId)
      } catch (error) {
        failed.push(dropletId)
      }
    }

    return { success, failed }
  }

  /**
   * Check if SSH key exists in DigitalOcean account by fingerprint
   */
  async findSSHKeyByFingerprint(fingerprint: string): Promise<SSHKeyInfo | null> {
    try {
      const keys = await this.listSSHKeys()
      return keys.find(key => key.fingerprint === fingerprint) || null
    } catch (error) {
      console.error('Failed to search for SSH key by fingerprint:', error)
      return null
    }
  }
}