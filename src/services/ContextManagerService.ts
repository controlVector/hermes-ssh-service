/**
 * Context Manager Integration Service for Hermes
 * Retrieves cloud provider credentials and connection details
 */

import axios from 'axios'

export class ContextManagerService {
  private contextManagerUrl: string

  constructor(contextManagerUrl = 'http://localhost:3002') {
    this.contextManagerUrl = contextManagerUrl
  }

  /**
   * Get cloud provider credentials from Context Manager
   */
  async getProviderCredentials(provider: string, jwtToken: string): Promise<string> {
    try {
      console.log(`[Hermes Context] Retrieving ${provider} credentials from Context Manager`)
      
      const response = await axios.post(`${this.contextManagerUrl}/api/v1/context/secret/get`, {
        key: `${provider}_api_token`
      }, {
        headers: {
          'Authorization': `Bearer ${jwtToken}`,
          'Content-Type': 'application/json'
        }
      })

      if (!response.data.success || !response.data.value) {
        throw new Error(`No ${provider} API token found in Context Manager`)
      }

      console.log(`[Hermes Context] Successfully retrieved ${provider} credentials`)
      return response.data.value
    } catch (error: any) {
      console.error(`[Hermes Context] Failed to get ${provider} credentials:`, error.response?.data || error.message)
      throw new Error(
        `Failed to retrieve ${provider} credentials: ${error.response?.data?.message || error.message}`
      )
    }
  }

  /**
   * Get SSH connection credentials for a specific server
   */
  async getSSHCredentials(serverHost: string, jwtToken: string): Promise<{
    username?: string
    password?: string
    privateKey?: string
  }> {
    try {
      console.log(`[Hermes Context] Retrieving SSH credentials for ${serverHost}`)
      
      // Try to get server-specific credentials first
      const serverKey = `ssh_${serverHost.replace(/[^a-zA-Z0-9]/g, '_')}`
      
      try {
        const response = await axios.post(`${this.contextManagerUrl}/api/v1/context/secret/get`, {
          key: serverKey
        }, {
          headers: {
            'Authorization': `Bearer ${jwtToken}`,
            'Content-Type': 'application/json'
          }
        })

        if (response.data.success && response.data.value) {
          return JSON.parse(response.data.value)
        }
      } catch (error) {
        // Server-specific credentials not found, try default
      }

      // Try default SSH credentials
      const defaultResponse = await axios.post(`${this.contextManagerUrl}/api/v1/context/secret/get`, {
        key: 'default_ssh_credentials'
      }, {
        headers: {
          'Authorization': `Bearer ${jwtToken}`,
          'Content-Type': 'application/json'
        }
      })

      if (defaultResponse.data.success && defaultResponse.data.value) {
        return JSON.parse(defaultResponse.data.value)
      }

      return {} // No credentials found, rely on SSH agent or keys
    } catch (error: any) {
      console.error(`[Hermes Context] Failed to get SSH credentials:`, error.response?.data || error.message)
      return {} // Return empty object to try without explicit credentials
    }
  }

  /**
   * Store SSH key information in Context Manager
   */
  async storeSSHKeyInfo(keyId: string, keyInfo: any, jwtToken: string): Promise<void> {
    try {
      console.log(`[Hermes Context] Storing SSH key info for ${keyId}`)
      
      await axios.post(`${this.contextManagerUrl}/api/v1/context/secret/set`, {
        key: `ssh_key_${keyId}`,
        value: JSON.stringify(keyInfo)
      }, {
        headers: {
          'Authorization': `Bearer ${jwtToken}`,
          'Content-Type': 'application/json'
        }
      })

      console.log(`[Hermes Context] Successfully stored SSH key info`)
    } catch (error: any) {
      console.error(`[Hermes Context] Failed to store SSH key info:`, error.response?.data || error.message)
      // Don't throw error for storage failures
    }
  }

  /**
   * Get stored SSH key information
   */
  async getSSHKeyInfo(keyId: string, jwtToken: string): Promise<any> {
    try {
      const response = await axios.post(`${this.contextManagerUrl}/api/v1/context/secret/get`, {
        key: `ssh_key_${keyId}`
      }, {
        headers: {
          'Authorization': `Bearer ${jwtToken}`,
          'Content-Type': 'application/json'
        }
      })

      if (response.data.success && response.data.value) {
        return JSON.parse(response.data.value)
      }

      return null
    } catch (error) {
      console.error(`[Hermes Context] Failed to get SSH key info for ${keyId}`)
      return null
    }
  }

  /**
   * Store SSH key in Context Manager's encrypted storage
   */
  async storeSSHKey(keyName: string, keyData: {
    private_key: string,
    public_key: string,
    metadata: string
  }, jwtToken: string): Promise<void> {
    try {
      const response = await axios.post(`${this.contextManagerUrl}/api/v1/context/secret/set`, {
        key: keyName,
        value: JSON.stringify(keyData)
      }, {
        headers: {
          'Authorization': `Bearer ${jwtToken}`,
          'Content-Type': 'application/json'
        }
      })

      if (!response.data.success) {
        throw new Error(`Failed to store SSH key: ${response.data.message}`)
      }

      console.log(`[Hermes Context] Successfully stored SSH key: ${keyName}`)
    } catch (error: any) {
      console.error(`[Hermes Context] Failed to store SSH key ${keyName}:`, error.response?.data || error.message)
      throw new Error(`Failed to store SSH key: ${error.response?.data?.message || error.message}`)
    }
  }

  /**
   * Get SSH key from Context Manager's encrypted storage
   */
  async getSSHKey(keyName: string, jwtToken: string): Promise<{
    private_key: string,
    public_key: string,
    metadata: string
  } | null> {
    try {
      const response = await axios.post(`${this.contextManagerUrl}/api/v1/context/secret/get`, {
        key: keyName
      }, {
        headers: {
          'Authorization': `Bearer ${jwtToken}`,
          'Content-Type': 'application/json'
        }
      })

      if (!response.data.success || !response.data.value) {
        return null
      }

      return JSON.parse(response.data.value)
    } catch (error: any) {
      console.error(`[Hermes Context] Failed to get SSH key ${keyName}:`, error.response?.data || error.message)
      return null
    }
  }

  /**
   * List all secrets to find SSH keys
   */
  async listSecrets(jwtToken: string): Promise<{key: string, created_at: string}[]> {
    try {
      const response = await axios.get(`${this.contextManagerUrl}/api/v1/context/secret/list`, {
        headers: {
          'Authorization': `Bearer ${jwtToken}`,
          'Content-Type': 'application/json'
        }
      })

      if (!response.data.success) {
        throw new Error(`Failed to list secrets: ${response.data.message}`)
      }

      return response.data.secrets || []
    } catch (error: any) {
      console.error(`[Hermes Context] Failed to list secrets:`, error.response?.data || error.message)
      throw new Error(`Failed to list secrets: ${error.response?.data?.message || error.message}`)
    }
  }
}