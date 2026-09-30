/**
 * Firewall Manager Service
 * Supports: pfSense, OPNsense
 * Integrates with SOC Agent for real-time rule deployment
 */

const axios = require('axios');
const System = require('../models/System.model');
const Alert = require('../models/Alert.model');

// Simple logger wrapper (console-based)
const logger = {
  info: (...args) => console.log('[FirewallManager]', ...args),
  error: (...args) => console.error('[FirewallManager]', ...args),
  warn: (...args) => console.warn('[FirewallManager]', ...args),
};

class FirewallManager {
  constructor(config = {}) {
    this.logMode = config.logMode || process.env.FIREWALL_LOG_MODE || false;
    
    // pfSense API config
    this.pfsenseUrl = process.env.PFSENSE_URL;
    this.pfsenseKey = process.env.PFSENSE_KEY;
    this.pfsenseSecret = process.env.PFSENSE_SECRET;
    
    // OPNsense API config
    this.opnsenseUrl = process.env.OPNSENSE_URL;
    this.opnsenseKey = process.env.OPNSENSE_KEY;
    this.opnsenseSecret = process.env.OPNSENSE_SECRET;
    
    logger.info(`[Firewall] Initialized with pfSense and OPNsense dual-firewall support`);
  }

  /**
   * Apply firewall rule to system(s)
   * @param {string} ruleId - Rule identifier
   * @param {object} rule - Rule configuration
   * @param {array} systemIds - Systems to apply to (empty = all with firewall enabled)
   * @returns {object} { success, applied, failed, details }
   */
  async applyRule(ruleId, rule, systemIds = []) {
    if (this.logMode) {
      logger.info(`[Firewall] LOG MODE: Would apply rule ${ruleId}:`, rule);
      return { success: true, applied: 0, logMode: true };
    }

    try {
      // Get target systems
      let systems;
      if (systemIds.length > 0) {
        systems = await System.find({ _id: { $in: systemIds }, isActive: true });
      } else {
        systems = await System.find({ isActive: true, 'config.firewallEnabled': true });
      }

      if (!systems.length) {
        return { success: false, applied: 0, message: 'No target systems found' };
      }

      // Apply to BOTH pfSense and OPNsense simultaneously
      let results = [];
      const pfsenseResults = await this._applyPfSenseRule(rule, systems);
      const opnsenseResults = await this._applyOPNsenseRule(rule, systems);
      results = [...pfsenseResults, ...opnsenseResults];

      const successful = results.filter(r => r.success).length;
      const failed = results.filter(r => !r.success).length;

      return {
        success: failed === 0,
        applied: successful,
        failed,
        details: results,
        ruleId,
        timestamp: new Date(),
      };
    } catch (err) {
      logger.error('[Firewall] applyRule error:', err.message);
      return { success: false, error: err.message };
    }
  }



  /**
   * pfSense - Apply rule via REST API
   */
  async _applyPfSenseRule(rule, systems) {
    if (!this.pfsenseUrl) {
      logger.warn('[Firewall] pfSense not configured, skipping...');
      return [];
    }

    const results = [];

    try {
      const ruleData = this._buildPfSenseRule(rule);
      
      const response = await axios.post(
        `${this.pfsenseUrl}/api/v1/firewall/rule`,
        ruleData,
        {
          headers: {
            'Authorization': `${this.pfsenseKey}:${this.pfsenseSecret}`,
            'Content-Type': 'application/json',
          },
          timeout: 10000,
        }
      );

      for (const system of systems) {
        results.push({
          systemId: system._id,
          systemName: system.name,
          success: response.status === 200 || response.status === 201,
          ruleId: response.data?.id || rule.id,
          method: 'pfsense_api',
        });
      }
    } catch (err) {
      logger.error('[Firewall] pfSense API error:', err.message);
      for (const system of systems) {
        results.push({
          systemId: system._id,
          systemName: system.name,
          success: false,
          error: err.message,
        });
      }
    }

    return results;
  }

  /**
   * OPNsense - Apply rule via REST API
   */
  async _applyOPNsenseRule(rule, systems) {
    if (!this.opnsenseUrl) {
      logger.warn('[Firewall] OPNsense not configured, skipping...');
      return [];
    }

    const results = [];

    try {
      const ruleData = this._buildOPNsenseRule(rule);
      
      const response = await axios.post(
        `${this.opnsenseUrl}/api/firewall/filter/add`,
        ruleData,
        {
          headers: {
            'X-API-Key': this.opnsenseKey,
            'X-API-Secret': this.opnsenseSecret,
            'Content-Type': 'application/json',
          },
          timeout: 10000,
        }
      );

      for (const system of systems) {
        results.push({
          systemId: system._id,
          systemName: system.name,
          success: response.status === 200,
          ruleId: response.data?.uuid || rule.id,
          method: 'opnsense_api',
        });
      }
    } catch (err) {
      logger.error('[Firewall] OPNsense API error:', err.message);
      for (const system of systems) {
        results.push({
          systemId: system._id,
          systemName: system.name,
          success: false,
          error: err.message,
        });
      }
    }

    return results;
  }



  /**
   * Build pfSense rule object
   */
  _buildPfSenseRule(rule) {
    const { action, protocol, fromIp, toPort, description } = rule;
    
    return {
      type: action === 'drop' ? 'reject' : 'pass',
      interface: rule.interface || 'wan',
      ipprotocol: 'inet',
      protocol: protocol || 'tcp',
      src: fromIp || 'any',
      srcport: rule.fromPort || 'any',
      dst: rule.toIp || 'any',
      dstport: toPort || 'any',
      direction: rule.direction || 'in',
      log: 1,
      description: description || `Rule created by SOC Agent`,
      enabled: 1,
    };
  }

  /**
   * Build OPNsense rule object
   */
  _buildOPNsenseRule(rule) {
    const { action, protocol, fromIp, toPort, description } = rule;
    
    return {
      filter: {
        action: action === 'drop' ? 'block' : 'pass',
        interface: rule.interface || 'wan',
        ipprotocol: 'inet',
        protocol: protocol || 'tcp',
        source: fromIp || 'any',
        destination: rule.toIp || 'any',
        destinationport: toPort ? toPort.toString() : 'any',
        log: '1',
        description: description || `Rule created by SOC Agent`,
        enabled: '1',
      },
    };
  }

  /**
   * Send command to agent via Socket.IO or webhook
   */
  async _sendCommandToAgent(systemId, command) {
    const system = await System.findById(systemId);
    if (!system) throw new Error('System not found');

    // Option 1: Via Socket.IO (real-time)
    const io = global.io; // Set during server initialization
    if (io) {
      io.to(`system:${systemId}`).emit('command:execute', command);
      return;
    }

    // Option 2: Via agent heartbeat (agent picks up on next check)
    // Store in pending commands
    await System.findByIdAndUpdate(systemId, {
      $push: { pendingCommands: command },
    });
  }

  /**
   * Get rule status for system
   */
  async getRuleStatus(systemId, ruleId) {
    const system = await System.findById(systemId);
    if (!system) throw new Error('System not found');

    // Check if rule is in applied rules
    const isApplied = system.appliedRules?.includes(ruleId);
    const appliedAt = system.ruleTimestamps?.[ruleId];

    return {
      systemId,
      systemName: system.name,
      ruleId,
      applied: isApplied || false,
      appliedAt,
      status: isApplied ? 'active' : 'pending',
    };
  }

  /**
   * Delete firewall rule
   */
  async deleteRule(ruleId, systemIds = []) {
    // Get systems
    let systems;
    if (systemIds.length > 0) {
      systems = await System.find({ _id: { $in: systemIds } });
    } else {
      systems = await System.find({ appliedRules: ruleId });
    }

    const results = [];

    for (const system of systems) {
      try {
        const command = this._buildRuleDeleteCommand(ruleId, this.firewallType);
        
        await this._sendCommandToAgent(system._id, {
          type: 'firewall_rule_delete',
          command,
          ruleId,
        });

        // Remove from applied rules
        await System.findByIdAndUpdate(system._id, {
          $pull: { appliedRules: ruleId },
          $unset: { [`ruleTimestamps.${ruleId}`]: 1 },
        });

        results.push({
          systemId: system._id,
          success: true,
          message: `Delete command sent for rule ${ruleId}`,
        });
      } catch (err) {
        results.push({
          systemId: system._id,
          success: false,
          error: err.message,
        });
      }
    }

    return results;
  }

  _buildRuleDeleteCommand(ruleId) {
    return `Delete rule ${ruleId} from both pfSense and OPNsense via their APIs`;
  }
}

module.exports = FirewallManager;
