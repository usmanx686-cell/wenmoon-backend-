const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const IPAddress = sequelize.define('IPAddress', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  ip_address: {
    type: DataTypes.STRING(45), // IPv6 max length
    allowNull: false,
    unique: true
  },
  user_count: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    validate: {
      min: 0
    }
  },
  country_code: {
    type: DataTypes.STRING(10)
  },
  country_name: {
    type: DataTypes.STRING(100)
  },
  city: {
    type: DataTypes.STRING(100)
  },
  region: {
    type: DataTypes.STRING(100)
  },
  timezone: {
    type: DataTypes.STRING(50)
  },
  isp: {
    type: DataTypes.STRING(100)
  },
  is_blocked: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  block_reason: {
    type: DataTypes.STRING(255)
  },
  block_expires: {
    type: DataTypes.DATE
  },
  last_activity: {
    type: DataTypes.DATE
  },
  total_requests: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  failed_attempts: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  }
}, {
  tableName: 'ip_addresses',
  timestamps: true,
  underscored: true,
  indexes: [
    {
      fields: ['ip_address']
    },
    {
      fields: ['is_blocked']
    },
    {
      fields: ['country_code']
    },
    {
      fields: ['last_activity']
    }
  ]
});

// Static methods
IPAddress.findByIP = async function(ipAddress) {
  return await this.findOne({ where: { ip_address: ipAddress } });
};

IPAddress.createOrUpdate = async function(ipData) {
  const [ipRecord, created] = await this.findOrCreate({
    where: { ip_address: ipData.ip_address },
    defaults: ipData
  });
  
  if (!created) {
    await ipRecord.update(ipData);
  }
  
  return ipRecord;
};

IPAddress.incrementUserCount = async function(ipAddress) {
  const ipRecord = await this.findByIP(ipAddress);
  if (ipRecord) {
    await ipRecord.increment('user_count');
    await ipRecord.update({ last_activity: new Date() });
  }
  return ipRecord;
};

IPAddress.incrementRequests = async function(ipAddress) {
  const ipRecord = await this.findByIP(ipAddress);
  if (ipRecord) {
    await ipRecord.increment('total_requests');
    await ipRecord.update({ last_activity: new Date() });
  }
  return ipRecord;
};

IPAddress.incrementFailedAttempts = async function(ipAddress) {
  const ipRecord = await this.findByIP(ipAddress);
  if (ipRecord) {
    await ipRecord.increment('failed_attempts');
    await ipRecord.update({ last_activity: new Date() });
  }
  return ipRecord;
};

IPAddress.blockIP = async function(ipAddress, reason = 'Manual block', hours = 24) {
  const ipRecord = await this.findByIP(ipAddress);
  if (ipRecord) {
    const blockExpires = new Date(Date.now() + hours * 60 * 60 * 1000);
    await ipRecord.update({
      is_blocked: true,
      block_reason: reason,
      block_expires: blockExpires,
      last_activity: new Date()
    });
  }
  return ipRecord;
};

IPAddress.unblockIP = async function(ipAddress) {
  const ipRecord = await this.findByIP(ipAddress);
  if (ipRecord) {
    await ipRecord.update({
      is_blocked: false,
      block_reason: null,
      block_expires: null,
      last_activity: new Date()
    });
  }
  return ipRecord;
};

IPAddress.getBlockedIPs = async function() {
  return await this.findAll({ 
    where: { is_blocked: true },
    order: [['block_expires', 'DESC']]
  });
};

IPAddress.getTopIPsByUsers = async function(limit = 20) {
  return await this.findAll({
    where: {
      user_count: { [sequelize.Op.gt]: 1 }
    },
    order: [['user_count', 'DESC']],
    limit: limit
  });
};

IPAddress.getAnalytics = async function() {
  const totalIPs = await this.count();
  const blockedIPs = await this.count({ where: { is_blocked: true } });
  const suspiciousIPs = await this.count({ 
    where: { 
      user_count: { [sequelize.Op.gt]: 3 },
      is_blocked: false 
    }
  });
  
  const topCountries = await this.findAll({
    attributes: [
      'country_code',
      [sequelize.fn('COUNT', sequelize.col('country_code')), 'ip_count'],
      [sequelize.fn('SUM', sequelize.col('user_count')), 'total_users']
    ],
    where: {
      country_code: { [sequelize.Op.not]: null }
    },
    group: ['country_code'],
    order: [[sequelize.literal('ip_count'), 'DESC']],
    limit: 10
  });
  
  return {
    total_ips: totalIPs,
    blocked_ips: blockedIPs,
    suspicious_ips: suspiciousIPs,
    top_countries: topCountries
  };
};

// Instance methods
IPAddress.prototype.isBlockExpired = function() {
  if (!this.is_blocked || !this.block_expires) {
    return true;
  }
  return new Date() > this.block_expires;
};

IPAddress.prototype.toJSON = function() {
  const values = Object.assign({}, this.get());
  delete values.created_at;
  delete values.updated_at;
  return values;
};

module.exports = IPAddress;
