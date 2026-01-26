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
    type: DataTypes.STRING,
    allowNull: false
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: true
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
  return await this.findAll({ where: { is_active: true } });
};

Task.getByType = async function(taskType) {
  return await this.findAll({ where: { task_type: taskType, is_active: true } });
};

module.exports = Task;
