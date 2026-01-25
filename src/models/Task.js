const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Task = sequelize.define('Task', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  task_id: {
    type: DataTypes.STRING(50),
    unique: true,
    allowNull: false
  },
  name: {
    type: DataTypes.STRING(255),
    allowNull: false
  },
  description: {
    type: DataTypes.TEXT
  },
  points: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 0,
    validate: {
      min: 0
    }
  },
  task_type: {
    type: DataTypes.STRING(50),
    allowNull: false,
    defaultValue: 'general'
  },
  is_active: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  max_completions: {
    type: DataTypes.INTEGER,
    defaultValue: 1,
    validate: {
      min: 1
    }
  },
  cooldown_hours: {
    type: DataTypes.INTEGER,
    defaultValue: 24,
    validate: {
      min: 0
    }
  },
  verification_required: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  verification_type: {
    type: DataTypes.STRING(50)
  },
  metadata: {
    type: DataTypes.JSONB,
    defaultValue: {}
  }
}, {
  tableName: 'tasks',
  timestamps: true,
  underscored: true
});

// Static methods
Task.findByTaskId = async function(taskId) {
  return await this.findOne({ where: { task_id: taskId } });
};

Task.getActiveTasks = async function() {
  return await this.findAll({ 
    where: { is_active: true },
    order: [['points', 'DESC']]
  });
};

Task.getTasksByType = async function(type) {
  return await this.findAll({ 
    where: { 
      is_active: true,
      task_type: type 
    }
  });
};

Task.getTotalTasks = async function() {
  return await this.count({ where: { is_active: true } });
};

// Instance methods
Task.prototype.canComplete = function(lastCompletion) {
  if (!lastCompletion) return true;
  
  const cooldownMs = this.cooldown_hours * 60 * 60 * 1000;
  const nextAvailable = new Date(lastCompletion.getTime() + cooldownMs);
  
  return new Date() >= nextAvailable;
};

Task.prototype.getNextAvailableTime = function(lastCompletion) {
  if (!lastCompletion) return new Date();
  
  const cooldownMs = this.cooldown_hours * 60 * 60 * 1000;
  return new Date(lastCompletion.getTime() + cooldownMs);
};

module.exports = Task;
