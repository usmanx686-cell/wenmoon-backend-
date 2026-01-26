const { sequelize, Op } = require('../config/database');
const logger = require('../utils/logger');

// Import models
const User = require('./User');
const Task = require('./Task');
const IPAddress = require('./IPAddress');
const Session = require('./Session');
const ActivityLog = require('./ActivityLog');
const UserTask = require('./UserTask');
const Referral = require('./Referral');
const WalletConnection = require('./WalletConnection');
const AdminLog = require('./AdminLog');

// Define associations
User.hasMany(Session, { foreignKey: 'user_id', as: 'sessions' });
User.hasMany(ActivityLog, { foreignKey: 'user_id', as: 'activities' });
User.hasMany(UserTask, { foreignKey: 'user_id', as: 'completedTasks' });
User.hasMany(WalletConnection, { foreignKey: 'user_id', as: 'wallets' });
User.hasMany(Referral, { foreignKey: 'referrer_id', as: 'referralsMade' });
User.hasMany(Referral, { foreignKey: 'referred_id', as: 'referralsReceived' });

Task.hasMany(UserTask, { foreignKey: 'task_id', sourceKey: 'task_id', as: 'completions' });

UserTask.belongsTo(User, { foreignKey: 'user_id', as: 'user' });
UserTask.belongsTo(Task, { foreignKey: 'task_id', targetKey: 'task_id', as: 'task' });

Session.belongsTo(User, { foreignKey: 'user_id', as: 'user' });
ActivityLog.belongsTo(User, { foreignKey: 'user_id', as: 'user' });
WalletConnection.belongsTo(User, { foreignKey: 'user_id', as: 'user' });

Referral.belongsTo(User, { foreignKey: 'referrer_id', as: 'referrer' });
Referral.belongsTo(User, { foreignKey: 'referred_id', as: 'referred' });

// Initialize models
const models = {
  User,
  Task,
  IPAddress,
  Session,
  ActivityLog,
  UserTask,
  Referral,
  WalletConnection,
  AdminLog,
  sequelize,
  Op
};

// Sync all models with database
const syncDatabase = async (force = false) => {
  try {
    if (force) {
      await sequelize.sync({ force: true });
      logger.warn('Database synced with force. All data was lost!');
    } else {
      await sequelize.sync({ alter: true });
      logger.info('Database synced successfully.');
    }
    return true;
  } catch (error) {
    logger.error('Database sync failed:', error);
    return false;
  }
};

module.exports = {
  ...models,
  syncDatabase
};
