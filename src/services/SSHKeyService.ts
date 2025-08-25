import * as forge from 'node-forge'
import * as crypto from 'crypto'
import * as fs from 'fs/promises'
import * as path from 'path'
import { v4 as uuidv4 } from 'uuid'
import { 
  SSHKeyPair, 
  SSHKeyMetadata, 
  KeyGenerationOptions, 
  KeyDeployment,
  SSHAuditLog,
  SecurityScan,
  SecurityFinding
} from '../types/ssh'

export class SSHKeyService {
  private readonly keyStoragePath: string
  private readonly encryptionKey: string

  constructor(keyStoragePath = './keys', encryptionKey?: string) {
    this.keyStoragePath = keyStoragePath
    this.encryptionKey = encryptionKey || process.env.HERMES_ENCRYPTION_KEY || this.generateEncryptionKey()
    this.ensureKeyDirectory()
  }

  private async ensureKeyDirectory(): Promise<void> {
    try {
      await fs.mkdir(this.keyStoragePath, { recursive: true })
      await fs.mkdir(path.join(this.keyStoragePath, 'private'), { recursive: true })
      await fs.mkdir(path.join(this.keyStoragePath, 'public'), { recursive: true })
      await fs.mkdir(path.join(this.keyStoragePath, 'metadata'), { recursive: true })
    } catch (error) {
      console.warn('Could not create key storage directories:', error)
    }
  }

  private generateEncryptionKey(): string {
    return crypto.randomBytes(32).toString('hex')
  }

  private encrypt(data: string): string {
    const iv = crypto.randomBytes(16)
    const key = crypto.scryptSync(this.encryptionKey, 'salt', 32)
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
    
    let encrypted = cipher.update(data, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    
    return iv.toString('hex') + ':' + encrypted
  }

  private decrypt(encryptedData: string): string {
    const parts = encryptedData.split(':')
    if (parts.length !== 2) {
      throw new Error('Invalid encrypted data format')
    }
    
    const iv = Buffer.from(parts[0], 'hex')
    const encrypted = parts[1]
    const key = crypto.scryptSync(this.encryptionKey, 'salt', 32)
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
    let decrypted = decipher.update(encrypted, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
  }

  async generateSSHKeyPair(options: KeyGenerationOptions): Promise<SSHKeyPair> {
    const keyId = uuidv4()
    
    try {
      let publicKey: string
      let privateKey: string
      let keySize: number
      let fingerprint: string

      switch (options.keyType) {
        case 'rsa':
          keySize = options.keySize || 4096
          const rsaKeyPair = this.generateRSAKeyPair(keySize)
          publicKey = rsaKeyPair.publicKey
          privateKey = rsaKeyPair.privateKey
          fingerprint = this.generateFingerprint(publicKey, 'rsa')
          break
          
        case 'ed25519':
          keySize = 256 // Ed25519 has fixed key size
          const ed25519KeyPair = this.generateEd25519KeyPair()
          publicKey = ed25519KeyPair.publicKey
          privateKey = ed25519KeyPair.privateKey
          fingerprint = this.generateFingerprint(publicKey, 'ed25519')
          break
          
        case 'ecdsa':
          keySize = options.keySize || 384
          const ecdsaKeyPair = this.generateECDSAKeyPair(keySize)
          publicKey = ecdsaKeyPair.publicKey
          privateKey = ecdsaKeyPair.privateKey
          fingerprint = this.generateFingerprint(publicKey, 'ecdsa')
          break
          
        default:
          throw new Error(`Unsupported key type: ${options.keyType}`)
      }

      // Apply passphrase encryption if provided
      if (options.passphrase) {
        privateKey = this.encryptPrivateKey(privateKey, options.passphrase)
      }

      const keyPair: SSHKeyPair = {
        id: keyId,
        name: options.name,
        publicKey,
        privateKey: this.encrypt(privateKey), // Always encrypt storage
        fingerprint,
        keyType: options.keyType,
        keySize,
        createdAt: new Date(),
        expiresAt: options.expiresIn ? new Date(Date.now() + options.expiresIn * 24 * 60 * 60 * 1000) : undefined,
        passphrase: options.passphrase,
        metadata: {
          userId: options.userId,
          workspaceId: options.workspaceId,
          purpose: options.purpose,
          tags: options.tags || []
        }
      }

      // Store key pair securely
      await this.storeKeyPair(keyPair)

      // Log key generation
      await this.auditLog({
        event: 'key_generated',
        keyId,
        userId: options.userId,
        workspaceId: options.workspaceId,
        details: {
          keyName: options.name,
          keyType: options.keyType,
          keySize,
          purpose: options.purpose
        },
        success: true
      })

      return keyPair
    } catch (error: any) {
      await this.auditLog({
        event: 'key_generated',
        userId: options.userId,
        workspaceId: options.workspaceId,
        details: { keyName: options.name, keyType: options.keyType },
        success: false,
        error: error.message
      })
      throw new Error(`Failed to generate SSH key pair: ${error.message}`)
    }
  }

  private generateRSAKeyPair(keySize: number): { publicKey: string; privateKey: string } {
    const keyPair = forge.pki.rsa.generateKeyPair({ bits: keySize })
    const privateKey = forge.ssh.privateKeyToOpenSSH(keyPair.privateKey)
    const publicKey = forge.ssh.publicKeyToOpenSSH(keyPair.publicKey, 'user@controlvector')
    
    return { publicKey, privateKey }
  }

  private generateEd25519KeyPair(): { publicKey: string; privateKey: string } {
    // Using Node.js crypto for Ed25519
    const keyPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    })

    // Convert to OpenSSH format
    const publicKey = this.convertToOpenSSHPublic(keyPair.publicKey, 'ed25519')
    const privateKey = this.convertToOpenSSHPrivate(keyPair.privateKey, 'ed25519')

    return { publicKey, privateKey }
  }

  private generateECDSAKeyPair(keySize: number): { publicKey: string; privateKey: string } {
    const curve = keySize === 256 ? 'prime256v1' : 
                  keySize === 384 ? 'secp384r1' : 
                  keySize === 521 ? 'secp521r1' : 'secp384r1'

    const keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: curve,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    })

    const publicKey = this.convertToOpenSSHPublic(keyPair.publicKey, 'ecdsa')
    const privateKey = this.convertToOpenSSHPrivate(keyPair.privateKey, 'ecdsa')

    return { publicKey, privateKey }
  }

  private convertToOpenSSHPublic(pemKey: string, keyType: string): string {
    // Simplified conversion - in production would use proper SSH key formatting
    const keyData = pemKey.replace(/-----BEGIN PUBLIC KEY-----|\r\n|-----END PUBLIC KEY-----|\n/g, '')
    return `ssh-${keyType} ${keyData} user@controlvector`
  }

  private convertToOpenSSHPrivate(pemKey: string, keyType: string): string {
    // Simplified conversion - in production would use proper OpenSSH private key format
    return `-----BEGIN OPENSSH PRIVATE KEY-----\n${pemKey}\n-----END OPENSSH PRIVATE KEY-----`
  }

  private generateFingerprint(publicKey: string, keyType: string): string {
    const keyContent = publicKey.split(' ')[1] || publicKey
    const hash = crypto.createHash('sha256').update(keyContent).digest('base64')
    return `SHA256:${hash}`
  }

  private encryptPrivateKey(privateKey: string, passphrase: string): string {
    const cipher = crypto.createCipher('aes-256-cbc', passphrase)
    let encrypted = cipher.update(privateKey, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    return encrypted
  }

  private async storeKeyPair(keyPair: SSHKeyPair): Promise<void> {
    const publicKeyPath = path.join(this.keyStoragePath, 'public', `${keyPair.id}.pub`)
    const privateKeyPath = path.join(this.keyStoragePath, 'private', `${keyPair.id}`)
    const metadataPath = path.join(this.keyStoragePath, 'metadata', `${keyPair.id}.json`)

    await Promise.all([
      fs.writeFile(publicKeyPath, keyPair.publicKey, 'utf8'),
      fs.writeFile(privateKeyPath, keyPair.privateKey, 'utf8'),
      fs.writeFile(metadataPath, JSON.stringify(this.keyPairToMetadata(keyPair), null, 2), 'utf8')
    ])
  }

  private keyPairToMetadata(keyPair: SSHKeyPair): SSHKeyMetadata {
    return {
      id: keyPair.id,
      name: keyPair.name,
      fingerprint: keyPair.fingerprint,
      keyType: keyPair.keyType,
      keySize: keyPair.keySize,
      publicKey: keyPair.publicKey,
      createdAt: keyPair.createdAt,
      expiresAt: keyPair.expiresAt,
      deployedTo: [],
      purpose: keyPair.metadata.purpose,
      tags: keyPair.metadata.tags,
      userId: keyPair.metadata.userId,
      workspaceId: keyPair.metadata.workspaceId
    }
  }

  async getSSHKey(keyId: string): Promise<SSHKeyMetadata | null> {
    try {
      const metadataPath = path.join(this.keyStoragePath, 'metadata', `${keyId}.json`)
      const metadataContent = await fs.readFile(metadataPath, 'utf8')
      return JSON.parse(metadataContent) as SSHKeyMetadata
    } catch (error) {
      return null
    }
  }

  async listSSHKeys(userId: string, workspaceId: string): Promise<SSHKeyMetadata[]> {
    try {
      const metadataDir = path.join(this.keyStoragePath, 'metadata')
      const files = await fs.readdir(metadataDir)
      const keys: SSHKeyMetadata[] = []

      for (const file of files) {
        if (file.endsWith('.json')) {
          const content = await fs.readFile(path.join(metadataDir, file), 'utf8')
          const metadata = JSON.parse(content) as SSHKeyMetadata
          
          if (metadata.userId === userId && metadata.workspaceId === workspaceId) {
            keys.push(metadata)
          }
        }
      }

      return keys.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
    } catch (error) {
      console.error('Error listing SSH keys:', error)
      return []
    }
  }

  async getPrivateKey(keyId: string, passphrase?: string): Promise<string> {
    try {
      const privateKeyPath = path.join(this.keyStoragePath, 'private', keyId)
      const encryptedPrivateKey = await fs.readFile(privateKeyPath, 'utf8')
      let privateKey = this.decrypt(encryptedPrivateKey)

      // If key has passphrase protection, decrypt it
      if (passphrase) {
        const decipher = crypto.createDecipher('aes-256-cbc', passphrase)
        let decrypted = decipher.update(privateKey, 'hex', 'utf8')
        decrypted += decipher.final('utf8')
        privateKey = decrypted
      }

      return privateKey
    } catch (error: any) {
      throw new Error(`Failed to retrieve private key: ${error.message}`)
    }
  }

  async deleteSSHKey(keyId: string, userId: string, workspaceId: string): Promise<boolean> {
    try {
      const metadata = await this.getSSHKey(keyId)
      if (!metadata || metadata.userId !== userId || metadata.workspaceId !== workspaceId) {
        throw new Error('Key not found or access denied')
      }

      const publicKeyPath = path.join(this.keyStoragePath, 'public', `${keyId}.pub`)
      const privateKeyPath = path.join(this.keyStoragePath, 'private', keyId)
      const metadataPath = path.join(this.keyStoragePath, 'metadata', `${keyId}.json`)

      await Promise.all([
        fs.unlink(publicKeyPath).catch(() => {}),
        fs.unlink(privateKeyPath).catch(() => {}),
        fs.unlink(metadataPath).catch(() => {})
      ])

      await this.auditLog({
        event: 'key_revoked',
        keyId,
        userId,
        workspaceId,
        details: { keyName: metadata.name },
        success: true
      })

      return true
    } catch (error: any) {
      await this.auditLog({
        event: 'key_revoked',
        keyId,
        userId,
        workspaceId,
        details: {},
        success: false,
        error: error.message
      })
      return false
    }
  }

  async auditSSHKeys(userId: string, workspaceId: string, options: any = {}): Promise<SecurityScan> {
    const scanId = uuidv4()
    const startTime = new Date()
    
    try {
      const keys = await this.listSSHKeys(userId, workspaceId)
      const findings: SecurityFinding[] = []

      for (const key of keys) {
        // Check for expired keys
        if (key.expiresAt && new Date() > key.expiresAt) {
          findings.push({
            id: uuidv4(),
            severity: 'high',
            category: 'expired_key',
            title: `SSH Key Expired: ${key.name}`,
            description: `SSH key "${key.name}" expired on ${key.expiresAt.toISOString()}`,
            recommendation: 'Rotate or remove expired SSH key',
            affectedResource: key.id
          })
        }

        // Check for keys expiring soon
        if (key.expiresAt && new Date() > new Date(key.expiresAt.getTime() - 7 * 24 * 60 * 60 * 1000)) {
          findings.push({
            id: uuidv4(),
            severity: 'medium',
            category: 'expired_key',
            title: `SSH Key Expiring Soon: ${key.name}`,
            description: `SSH key "${key.name}" will expire on ${key.expiresAt.toISOString()}`,
            recommendation: 'Plan key rotation before expiration',
            affectedResource: key.id
          })
        }

        // Check for unused keys
        const daysSinceLastUse = key.lastUsed ? 
          Math.floor((Date.now() - key.lastUsed.getTime()) / (1000 * 60 * 60 * 24)) : 
          Math.floor((Date.now() - key.createdAt.getTime()) / (1000 * 60 * 60 * 24))

        if (daysSinceLastUse > 90) {
          findings.push({
            id: uuidv4(),
            severity: 'low',
            category: 'unused_key',
            title: `Unused SSH Key: ${key.name}`,
            description: `SSH key "${key.name}" hasn't been used in ${daysSinceLastUse} days`,
            recommendation: 'Consider removing unused SSH key if no longer needed',
            affectedResource: key.id
          })
        }

        // Check for weak keys
        if (key.keyType === 'rsa' && key.keySize < 2048) {
          findings.push({
            id: uuidv4(),
            severity: 'critical',
            category: 'weak_key',
            title: `Weak RSA Key: ${key.name}`,
            description: `RSA key "${key.name}" uses ${key.keySize} bits, below recommended 2048`,
            recommendation: 'Replace with RSA 4096-bit or Ed25519 key',
            affectedResource: key.id
          })
        }
      }

      const severityCounts = findings.reduce((acc, finding) => {
        acc[finding.severity] = (acc[finding.severity] || 0) + 1
        return acc
      }, {} as Record<string, number>)

      const scan: SecurityScan = {
        id: scanId,
        targetId: `${workspaceId}:${userId}`,
        scanType: 'key_audit',
        status: 'completed',
        startedAt: startTime,
        completedAt: new Date(),
        results: {
          findings,
          score: this.calculateSecurityScore(keys, findings),
          recommendations: this.generateRecommendations(findings),
          critical: severityCounts.critical || 0,
          high: severityCounts.high || 0,
          medium: severityCounts.medium || 0,
          low: severityCounts.low || 0
        }
      }

      return scan
    } catch (error: any) {
      throw new Error(`SSH key audit failed: ${error.message}`)
    }
  }

  private calculateSecurityScore(keys: SSHKeyMetadata[], findings: SecurityFinding[]): number {
    if (keys.length === 0) return 100

    const totalKeys = keys.length
    const criticalFindings = findings.filter(f => f.severity === 'critical').length
    const highFindings = findings.filter(f => f.severity === 'high').length
    const mediumFindings = findings.filter(f => f.severity === 'medium').length

    // Start with 100 and subtract points for findings
    let score = 100
    score -= (criticalFindings * 30)
    score -= (highFindings * 20) 
    score -= (mediumFindings * 10)

    return Math.max(0, Math.min(100, score))
  }

  private generateRecommendations(findings: SecurityFinding[]): string[] {
    const recommendations = new Set<string>()

    for (const finding of findings) {
      recommendations.add(finding.recommendation)
    }

    // Add general recommendations
    if (findings.length > 0) {
      recommendations.add('Implement regular key rotation policy')
      recommendations.add('Monitor key usage and remove unused keys')
      recommendations.add('Use Ed25519 keys for new key generation')
    }

    return Array.from(recommendations)
  }

  private async auditLog(log: Omit<SSHAuditLog, 'id' | 'timestamp'>): Promise<void> {
    const auditLog: SSHAuditLog = {
      id: uuidv4(),
      timestamp: new Date(),
      ...log
    }

    // In production, this would be stored in a database
    console.log('SSH Audit Log:', auditLog)
  }
}