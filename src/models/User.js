const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');
const bcrypt = require('bcryptjs');

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
    unique: true
  },
  password_hash: {
    type: DataTypes.STRING,
    allowNull: false
  },
  wallet_address: {
    type: DataTypes.STRING,
    validate: {
      isEthereumAddress(value) {
        if (value && !/^0x[a-fA-F0-9]{40}$/.test(value)) {
          throw new Error('Invalid Ethereum address');
        }
      }
    }
  },
  referral_code: {
    type: DataTypes.STRING,
    unique: true
  },
  referred_by: {
    type: DataTypes.STRING
  },
  moon_points: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  total_points_earned: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  email_verified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  telegram_id: {
    type: DataTypes.STRING
  },
  google_id: {
    type: DataTypes.STRING
  },
  ip_address: {
    type: DataTypes.STRING
  },
  last_login: {
    type: DataTypes.DATE
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
      if (user.password_hash) {
        const salt = await bcrypt.genSalt(10);
        user.password_hash = await bcrypt.hash(user.password_hash, salt);
      }
      // Generate referral code
      if (!user.referral_code) {
        user.referral_code = Math.random().toString(36).substring(2, 10).toUpperCase();
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
  delete values.password_hash;
  delete values.created_at;
  delete values.updated_at;
  return values;
};

module.exports = User;
