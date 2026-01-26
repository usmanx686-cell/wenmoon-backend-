const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true
    }
  },
  username: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: true
  },
  password_hash: {
    type: DataTypes.STRING,
    allowNull: false
  },
  wallet_address: {
    type: DataTypes.STRING,
    allowNull: true,
    validate: {
      isEthereumAddress(value) {
        if (value && !/^0x[a-fA-F0-9]{40}$/.test(value)) {
          throw new Error('Invalid Ethereum address');
        }
      }
    }
  },
  referral_code: {
    type: DataTypes.STRING(50),
    unique: true,
    allowNull: false
  },
  referred_by: {
    type: DataTypes.STRING(50),
    allowNull: true
  },
  moon_points: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    validate: {
      min: 0
    }
  },
  total_points_earned: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    validate: {
      min: 0
    }
  },
  email_verified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  telegram_id: {
    type: DataTypes.STRING,
    allowNull: true
  },
  google_id: {
    type: DataTypes.STRING,
    allowNull: true
  },
  ip_address: {
    type: DataTypes.STRING,
    allowNull: true
  },
  last_login: {
    type: DataTypes.DATE,
    allowNull: true
  },
  is_active: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  is_admin: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  }
}, {
  tableName: 'users',
  timestamps: true,
  underscored: true,
  hooks: {
    beforeCreate: async (user) => {
      // Hash password
      if (user.password_hash) {
        const salt = await bcrypt.genSalt(10);
        user.password_hash = await bcrypt.hash(user.password_hash, salt);
      }
      
      // Generate referral code if not provided
      if (!user.referral_code) {
        user.referral_code = crypto.randomBytes(4).toString('hex').toUpperCase();
      }
      
      // Generate username from email if not provided
      if (!user.username) {
        user.username = user.email.split('@')[0];
      }
    },
    beforeUpdate: async (user) => {
      // Hash password if changed
      if (user.changed('password_hash')) {
        const salt = await bcrypt.genSalt(10);
        user.password_hash = await bcrypt.hash(user.password_hash, salt);
      }
    }
  }
});

// Instance methods
User.prototype.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password_hash);
};

User.prototype.toJSON = function() {
  const values = Object.assign({}, this.get());
  
  // Remove sensitive data
  delete values.password_hash;
  delete values.created_at;
  delete values.updated_at;
  
  return values;
};

// Static methods
User.findByEmail = async function(email) {
  return await this.findOne({ where: { email } });
};

User.findByReferralCode = async function(referralCode) {
  return await this.findOne({ where: { referral_code: referralCode } });
};

User.incrementPoints = async function(userId, points) {
  return await this.increment({
    moon_points: points,
    total_points_earned: points
  }, { where: { id: userId } });
};

module.exports = User;
