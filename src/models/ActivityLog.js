const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const ActivityLog = sequelize.define('ActivityLog', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  user_id: {
    type: DataTypes.INTEGER,
    allowNull: true, // Can be null for anonymous activities
    references: {
      model: 'users',
      key: 'id'
    }
  },
  action: {
    type: DataTypes.STRING(100),
    allowNull: false
  },
  details: {
    type: DataTypes.JSONB,
    defaultValue: {}
  },
  ip_address: {
    type: DataTypes.STRING(45)
  },
  user_agent: {
    type: DataTypes.TEXT
  },
  severity: {
    type: DataTypes.ENUM('info', 'warning', 'error', 'critical'),
    defaultValue: 'info'
  },
  source: {
    type: DataTypes.STRING(50),
    defaultValue: 'api'
  }
}, {
  tableName: 'activity_logs',
  timestamps: true,
  underscored: true,
  indexes: [
    {
      fields: ['user_id']
    },
    {
      fields: ['action']
    },
    {
      fields: ['created_at']
    },
    {
      fields: ['severity']
    },
    {
      fields: ['ip_address']
    }
  ]
});

// Static methods
ActivityLog.createLog = async function(data) {
  return await this.create(data);
};

ActivityLog.logUserActivity = async function(userId, action, details = {}, ipAddress = null, userAgent = null) {
  return await this.create({
    user_id: userId,
    action: action,
    details: details,
    ip_address: ipAddress,
    user_agent: userAgent,
    created_at: new Date()
  });
};

ActivityLog.logAnonymousActivity = async function(action, details = {}, ipAddress = null, userAgent = null) {
  return await this.create({
    action: action,
    details: details,
    ip_address: ipAddress,
    user_agent: userAgent,
    severity: 'warning', // Anonymous activities are typically suspicious
    created_at: new Date()
  });
};

ActivityLog.getUserLogs = async function(userId, limit = 50, offset = 0) {
  return await this.findAll({
    where: { user_id: userId },
    order: [['created_at', 'DESC']],
    limit: limit,
    offset: offset
  });
};

ActivityLog.getRecentLogs = async function(limit = 100) {
  return await this.findAll({
    order: [['created_at', 'DESC']],
    limit: limit,
    include: [{
      association: 'user',
      attributes: ['id', 'email', 'username'],
      required: false
    }]
  });
};

ActivityLog.getLogsByAction = async function(action, limit = 100) {
  return await this.findAll({
    where: { action: action },
    order: [['created_at', 'DESC']],
    limit: limit,
    include: [{
      association: 'user',
      attributes: ['id', 'email', 'username'],
      required: false
    }]
  });
};

ActivityLog.getLogsBySeverity = async function(severity, limit = 100) {
  return await this.findAll({
    where: { severity: severity },
    order: [['created_at', 'DESC']],
    limit: limit,
    include: [{
      association: 'user',
      attributes: ['id', 'email', 'username'],
      required: false
    }]
  });
};

ActivityLog.getLogsByIP = async function(ipAddress, limit = 100) {
  return await this.findAll({
    where: { ip_address: ipAddress },
    order: [['created_at', 'DESC']],
    limit: limit,
    include: [{
      association: 'user',
      attributes: ['id', 'email', 'username'],
      required: false
    }]
  });
};

ActivityLog.getStats = async function(timeRange = '24h') {
  let whereClause = {};
  const now = new Date();
  
  // Set time range
  switch (timeRange) {
    case '1h':
      whereClause.created_at = { [sequelize.Op.gte]: new Date(now.getTime() - 60 * 60 * 1000) };
      break;
    case '24h':
      whereClause.created_at = { [sequelize.Op.gte]: new Date(now.getTime() - 24 * 60 * 60 * 1000) };
      break;
    case '7d':
      whereClause.created_at = { [sequelize.Op.gte]: new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000) };
      break;
    case '30d':
      whereClause.created_at = { [sequelize.Op.gte]: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000) };
      break;
  }
  
  // Get total logs
  const totalLogs = await this.count({ where: whereClause });
  
  // Get logs by severity
  const logsBySeverity = await this.findAll({
    attributes: [
      'severity',
      [sequelize.fn('COUNT', sequelize.col('severity')), 'count']
    ],
    where: whereClause,
    group: ['severity']
  });
  
  // Get top actions
  const topActions = await this.findAll({
    attributes: [
      'action',
      [sequelize.fn('COUNT', sequelize.col('action')), 'count']
    ],
    where: whereClause,
    group: ['action'],
    order: [[sequelize.literal('count'), 'DESC']],
    limit: 10
  });
  
  // Get unique IPs
  const uniqueIPs = await this.count({
    distinct: true,
    col: 'ip_address',
    where: whereClause
  });
  
  return {
    total_logs: totalLogs,
    logs_by_severity: logsBySeverity,
    top_actions: topActions,
    unique_ips: uniqueIPs,
    time_range: timeRange
  };
};

ActivityLog.cleanOldLogs = async function(daysToKeep = 90) {
  const cutoffDate = new Date(Date.now() - daysToKeep * 24 * 60 * 60 * 1000);
  return await this.destroy({
    where: {
      created_at: { [sequelize.Op.lt]: cutoffDate },
      severity: { [sequelize.Op.ne]: 'critical' } // Keep critical logs longer
    }
  });
};

// Instance methods
ActivityLog.prototype.toJSON = function() {
  const values = Object.assign({}, this.get());
  
  // Format dates
  if (values.created_at) {
    values.created_at = values.created_at.toISOString();
  }
  
  return values;
};

module.exports = ActivityLog;
