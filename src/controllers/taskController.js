const Task = require('../models/Task');
const User = require('../models/User');
const IPLog = require('../models/IPLog');
const SecurityLog = require('../models/SecurityLog');
const logger = require('../utils/logger');
const fraudDetection = require('../services/fraudDetection');

// Get all available tasks
const getTasks = async (req, res) => {
    try {
        const { category, status = 'active' } = req.query;
        
        const query = { status };
        if (category) query.category = category;
        
        const tasks = await Task.find(query)
            .sort({ points: -1, createdAt: -1 })
            .lean();
        
        // Get user's completed tasks
        const user = await User.findById(req.userId);
        const completedTaskIds = user?.completedTasks.map(t => t.taskId.toString()) || [];
        
        // Mark tasks as completed for user
        const tasksWithCompletion = tasks.map(task => ({
            ...task,
            isCompleted: completedTaskIds.includes(task._id.toString()),
            canComplete: task.dailyLimit > 0
        }));
        
        res.status(200).json({
            status: 'success',
            data: {
                tasks: tasksWithCompletion,
                stats: {
                    totalTasks: tasks.length,
                    completedTasks: completedTaskIds.length,
                    availableTasks: tasks.length - completedTaskIds.length
                }
            }
        });
    } catch (error) {
        logger.error('Get tasks error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Get task by ID
const getTaskById = async (req, res) => {
    try {
        const { id } = req.params;
        
        const task = await Task.findById(id);
        if (!task) {
            return res.status(404).json({
                status: 'error',
                message: 'Task not found'
            });
        }
        
        // Check if user completed this task
        const user = await User.findById(req.userId);
        const isCompleted = user?.completedTasks.some(
            t => t.taskId.toString() === id
        ) || false;
        
        res.status(200).json({
            status: 'success',
            data: {
                task,
                isCompleted,
                canComplete: !isCompleted && task.dailyLimit > 0
            }
        });
    } catch (error) {
        logger.error('Get task by ID error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Complete a task
const completeTask = async (req, res) => {
    try {
        const { id } = req.params;
        const { proof } = req.body; // Proof of completion (URL, hash, etc.)
        
        // Find task
        const task = await Task.findById(id);
        if (!task || task.status !== 'active') {
            return res.status(404).json({
                status: 'error',
                message: 'Task not found or inactive'
            });
        }
        
        // Find user
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }
        
        // Check if task already completed
        const alreadyCompleted = user.completedTasks.some(
            t => t.taskId.toString() === id
        );
        
        if (alreadyCompleted) {
            return res.status(400).json({
                status: 'error',
                message: 'Task already completed'
            });
        }
        
        // Check daily task limit
        if (user.tasksCompletedToday >= user.dailyTaskLimit) {
            return res.status(429).json({
                status: 'error',
                message: 'Daily task limit reached',
                limit: user.dailyTaskLimit,
                completedToday: user.tasksCompletedToday
            });
        }
        
        // Check task-specific requirements
        if (task.requiresWallet && !user.walletAddress) {
            return res.status(400).json({
                status: 'error',
                message: 'Wallet connection required for this task'
            });
        }
        
        // Validate proof if required
        if (task.requiresProof && !proof) {
            return res.status(400).json({
                status: 'error',
                message: 'Proof of completion required'
            });
        }
        
        // Check for rapid task completion (fraud detection)
        const recentTasks = user.completedTasks
            .filter(t => {
                const taskTime = new Date(t.completedAt);
                const now = new Date();
                return (now - taskTime) < 60 * 1000; // Last minute
            })
            .length;
        
        if (recentTasks > 2) {
            // Flag for manual review
            await fraudDetection.monitorUserActivity(
                user._id,
                'rapid_task_completion',
                { taskId: id, recentTasks }
            );
            
            return res.status(429).json({
                status: 'error',
                message: 'Task completion rate too high. Please slow down.'
            });
        }
        
        // Complete the task
        await user.completeTask(task._id, task.points);
        
        // Log task completion
        await IPLog.create({
            ipAddress: req.clientIP,
            userId: user._id,
            action: 'task_completion',
            userAgent: req.useragent?.source,
            endpoint: `/tasks/${id}/complete`,
            riskScore: user.riskScore,
            details: {
                taskId: task._id,
                taskTitle: task.title,
                points: task.points,
                proof: task.requiresProof ? proof : null
            }
        });
        
        // Log security event
        await SecurityLog.create({
            userId: user._id,
            type: 'task_completed',
            severity: 'info',
            details: {
                taskId: task._id,
                taskTitle: task.title,
                points: task.points,
                proof: task.requiresProof ? 'provided' : 'not_required'
            }
        });
        
        res.status(200).json({
            status: 'success',
            data: {
                task: {
                    id: task._id,
                    title: task.title,
                    points: task.points
                },
                user: {
                    moonPoints: user.moonPoints,
                    tasksCompletedToday: user.tasksCompletedToday,
                    dailyLimit: user.dailyTaskLimit
                },
                completion: {
                    timestamp: new Date(),
                    pointsEarned: task.points
                }
            }
        });
    } catch (error) {
        logger.error('Complete task error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Get user's completed tasks
const getCompletedTasks = async (req, res) => {
    try {
        const user = await User.findById(req.userId)
            .populate('completedTasks.taskId', 'title points category icon');
        
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }
        
        const completedTasks = user.completedTasks.map(ct => ({
            task: ct.taskId,
            completedAt: ct.completedAt,
            pointsEarned: ct.pointsEarned,
            status: ct.status
        }));
        
        // Calculate statistics
        const stats = {
            totalCompleted: completedTasks.length,
            totalPoints: completedTasks.reduce((sum, ct) => sum + ct.pointsEarned, 0),
            completedToday: user.tasksCompletedToday,
            dailyLimit: user.dailyTaskLimit
        };
        
        // Group by category
        const byCategory = {};
        completedTasks.forEach(ct => {
            const category = ct.task?.category || 'uncategorized';
            if (!byCategory[category]) {
                byCategory[category] = {
                    count: 0,
                    points: 0,
                    tasks: []
                };
            }
            byCategory[category].count++;
            byCategory[category].points += ct.pointsEarned;
            byCategory[category].tasks.push(ct);
        });
        
        res.status(200).json({
            status: 'success',
            data: {
                tasks: completedTasks,
                stats,
                byCategory
            }
        });
    } catch (error) {
        logger.error('Get completed tasks error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Get task statistics
const getTaskStats = async (req, res) => {
    try {
        // Global task statistics
        const taskStats = await Task.aggregate([
            {
                $group: {
                    _id: '$status',
                    count: { $sum: 1 },
                    totalPoints: { $sum: '$points' },
                    avgPoints: { $avg: '$points' }
                }
            }
        ]);
        
        // User task statistics
        const user = await User.findById(req.userId);
        const userStats = {
            completedTasks: user?.completedTasks.length || 0,
            totalPointsEarned: user?.totalPointsEarned || 0,
            tasksCompletedToday: user?.tasksCompletedToday || 0,
            dailyLimit: user?.dailyTaskLimit || 10
        };
        
        // Category distribution
        const categoryStats = await Task.aggregate([
            {
                $group: {
                    _id: '$category',
                    count: { $sum: 1 },
                    totalPoints: { $sum: '$points' }
                }
            },
            {
                $sort: { count: -1 }
            }
        ]);
        
        res.status(200).json({
            status: 'success',
            data: {
                global: {
                    totalTasks: taskStats.reduce((sum, stat) => sum + stat.count, 0),
                    activeTasks: taskStats.find(stat => stat._id === 'active')?.count || 0,
                    totalPointsAvailable: taskStats.reduce((sum, stat) => sum + stat.totalPoints, 0)
                },
                user: userStats,
                categories: categoryStats.map(cat => ({
                    category: cat._id,
                    taskCount: cat.count,
                    totalPoints: cat.totalPoints
                }))
            }
        });
    } catch (error) {
        logger.error('Get task stats error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

module.exports = {
    getTasks,
    getTaskById,
    completeTask,
    getCompletedTasks,
    getTaskStats
};
