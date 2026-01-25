const { User, Task, UserTask, ActivityLog } = require('../models');
const logger = require('../utils/logger');

class TaskController {
  // Get all available tasks
  async getTasks(req, res) {
    try {
      const tasks = await Task.findAll({
        where: { is_active: true },
        attributes: ['id', 'task_id', 'name', 'description', 'points', 'task_type', 'max_completions', 'cooldown_hours']
      });

      // Get user's completed tasks
      const userTasks = await UserTask.findAll({
        where: { user_id: req.user.id },
        attributes: ['task_id', 'completed_at']
      });

      const completedTaskMap = new Map();
      userTasks.forEach(ut => {
        completedTaskMap.set(ut.task_id, ut.completed_at);
      });

      // Add completion status to tasks
      const tasksWithStatus = tasks.map(task => ({
        ...task.toJSON(),
        completed: completedTaskMap.has(task.task_id),
        completed_at: completedTaskMap.get(task.task_id) || null,
        can_complete: this.canCompleteTask(task, completedTaskMap.get(task.task_id))
      }));

      res.json({
        success: true,
        data: tasksWithStatus
      });
    } catch (error) {
      logger.error('Get tasks error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch tasks'
      });
    }
  }

  // Complete a task
  async completeTask(req, res) {
    try {
      const { taskId } = req.params;
      const userId = req.user.id;
      const ip = req.clientIp;

      // Get task
      const task = await Task.findOne({ where: { task_id: taskId, is_active: true } });
      if (!task) {
        return res.status(404).json({
          success: false,
          message: 'Task not found'
        });
      }

      // Check if already completed
      const existingCompletion = await UserTask.findOne({
        where: { user_id: userId, task_id: taskId }
      });

      if (existingCompletion) {
        // Check cooldown
        const lastCompletion = new Date(existingCompletion.completed_at);
        const cooldownHours = task.cooldown_hours || 24;
        const nextAvailable = new Date(lastCompletion.getTime() + cooldownHours * 60 * 60 * 1000);

        if (new Date() < nextAvailable && task.max_completions <= 1) {
          return res.status(400).json({
            success: false,
            message: `Task on cooldown. Available again at ${nextAvailable.toLocaleString()}`,
            next_available: nextAvailable
          });
        }

        // Check max completions
        const completionsCount = await UserTask.count({
          where: { user_id: userId, task_id: taskId }
        });

        if (completionsCount >= task.max_completions) {
          return res.status(400).json({
            success: false,
            message: 'Maximum completions reached for this task'
          });
        }
      }

      // Special handling for different task types
      let verificationRequired = false;
      let metadata = {};

      switch (taskId) {
        case 'twitter_follow':
          // In production, verify Twitter follow via API
          verificationRequired = true;
          metadata = { verified_via: 'manual' };
          break;
          
        case 'telegram_join':
          // Verify Telegram membership
          verificationRequired = true;
          metadata = { verified_via: 'bot' };
          break;
          
        case 'watch_ad':
          // Track ad view
          metadata = { 
            ad_id: `ad_${Date.now()}`,
            duration: 30,
            viewed_at: new Date().toISOString()
          };
          break;
          
        case 'wallet_connect':
          // Verify wallet connection
          const user = await User.findByPk(userId);
          if (!user.wallet_address) {
            return res.status(400).json({
              success: false,
              message: 'Please connect your wallet first'
            });
          }
          metadata = { wallet_address: user.wallet_address };
          break;
      }

      // Create completion record
      await UserTask.create({
        user_id: userId,
        task_id: taskId,
        points_awarded: task.points,
        metadata
      });

      // Update user points
      const user = await User.findByPk(userId);
      await user.update({
        moon_points: user.moon_points + task.points,
        total_points_earned: user.total_points_earned + task.points
      });

      // Log activity
      await ActivityLog.create({
        user_id: userId,
        action: 'task_completed',
        details: {
          task_id: taskId,
          task_name: task.name,
          points: task.points,
          ip,
          metadata
        },
        ip_address: ip
      });

      res.json({
        success: true,
        message: `Task completed! You earned ${task.points} Moon Points`,
        data: {
          task: task.name,
          points_earned: task.points,
          total_points: user.moon_points + task.points,
          next_available: task.cooldown_hours > 0 
            ? new Date(Date.now() + task.cooldown_hours * 60 * 60 * 1000)
            : null
        }
      });

    } catch (error) {
      logger.error('Complete task error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to complete task'
      });
    }
  }

  // Get user's task progress
  async getUserProgress(req, res) {
    try {
      const userId = req.user.id;

      const completedTasks = await UserTask.findAll({
        where: { user_id: userId },
        include: [{
          model: Task,
          attributes: ['name', 'task_type', 'points']
        }],
        order: [['completed_at', 'DESC']]
      });

      const totalPoints = completedTasks.reduce((sum, task) => sum + task.points_awarded, 0);
      const tasksByType = {};

      completedTasks.forEach(task => {
        const type = task.Task.task_type;
        if (!tasksByType[type]) {
          tasksByType[type] = {
            count: 0,
            points: 0,
            tasks: []
          };
        }
        tasksByType[type].count++;
        tasksByType[type].points += task.points_awarded;
        tasksByType[type].tasks.push({
          name: task.Task.name,
          completed_at: task.completed_at,
          points: task.points_awarded
        });
      });

      res.json({
        success: true,
        data: {
          total_tasks_completed: completedTasks.length,
          total_points_earned: totalPoints,
          tasks_by_type: tasksByType,
          recent_completions: completedTasks.slice(0, 10).map(t => ({
            task: t.Task.name,
            completed_at: t.completed_at,
            points: t.points_awarded
          }))
        }
      });

    } catch (error) {
      logger.error('Get user progress error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch progress'
      });
    }
  }

  // Helper method
  canCompleteTask(task, lastCompletion) {
    if (!lastCompletion) return true;
    
    const cooldownHours = task.cooldown_hours || 24;
    const nextAvailable = new Date(lastCompletion.getTime() + cooldownHours * 60 * 60 * 1000);
    
    return new Date() >= nextAvailable;
  }
}

module.exports = new TaskController();
