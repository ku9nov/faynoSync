package tasks

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// GetTask retrieves task status from Redis
func GetTask(c *gin.Context, redisClient *redis.Client) {
	taskID := c.Query("task_id")
	if taskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "task_id query parameter is required",
		})
		return
	}

	if redisClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Redis client is not available",
		})
		return
	}

	ctx := context.Background()
	taskKey := "task:" + taskID

	// Get task status from Redis
	taskData, err := redisClient.Get(ctx, taskKey).Result()
	if err == redis.Nil {
		// Task not found - return PENDING state
		c.JSON(http.StatusOK, Response{
			Data: TasksData{
				TaskID: taskID,
				State:  TaskStatePending,
				Result: nil,
			},
			Message: "Task state.",
		})
		return
	} else if err != nil {
		logrus.Errorf("Failed to get task from Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve task status",
		})
		return
	}

	// Parse task status from JSON
	var taskStatus TaskStatus
	if err := json.Unmarshal([]byte(taskData), &taskStatus); err != nil {
		logrus.Errorf("Failed to unmarshal task status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to parse task status",
		})
		return
	}

	// Handle special case: if state is SUCCESS but status is false, change to ERRORED
	if taskStatus.State == TaskStateSuccess && taskStatus.Result != nil && taskStatus.Result.Status != nil && !*taskStatus.Result.Status {
		taskStatus.State = TaskStateErrored
	}

	// Handle case where result is an exception/error string
	if taskStatus.Result != nil && taskStatus.Result.Error != nil && *taskStatus.Result.Error != "" {
		// Error is already in the result structure
	}

	c.JSON(http.StatusOK, Response{
		Data: TasksData{
			TaskID: taskID,
			State:  taskStatus.State,
			Result: taskStatus.Result,
		},
		Message: "Task state.",
	})
}

// SaveTaskStatus saves or updates task status in Redis
func SaveTaskStatus(redisClient *redis.Client, taskID string, state TaskState, result *TaskResult) error {
	if redisClient == nil {
		return nil // Silently skip if Redis is not available
	}

	ctx := context.Background()
	taskKey := "task:" + taskID

	taskStatus := TaskStatus{
		State:  state,
		Result: result,
	}

	// If result is nil but state is not PENDING, create empty result
	if taskStatus.Result == nil && state != TaskStatePending {
		taskStatus.Result = &TaskResult{}
	}

	// Set LastUpdate if result exists
	if taskStatus.Result != nil {
		now := time.Now()
		taskStatus.Result.LastUpdate = &now
	}

	taskJSON, err := json.Marshal(taskStatus)
	if err != nil {
		logrus.Errorf("Failed to marshal task status: %v", err)
		return err
	}

	err = redisClient.Set(ctx, taskKey, taskJSON, 0).Err()
	if err != nil {
		logrus.Errorf("Failed to save task status to Redis: %v", err)
		return err
	}

	logrus.Debugf("Saved task status: task_id=%s, state=%s", taskID, state)
	return nil
}

// UpdateTaskState updates only the state of a task
func UpdateTaskState(redisClient *redis.Client, taskID string, state TaskState) error {
	if redisClient == nil {
		return nil
	}

	ctx := context.Background()
	taskKey := "task:" + taskID

	// Get existing task status
	taskData, err := redisClient.Get(ctx, taskKey).Result()
	var taskStatus TaskStatus

	if err == redis.Nil {
		// Task doesn't exist, create new
		taskStatus = TaskStatus{
			State:  state,
			Result: &TaskResult{},
		}
	} else if err != nil {
		logrus.Errorf("Failed to get task from Redis: %v", err)
		return err
	} else {
		// Parse existing task status
		if err := json.Unmarshal([]byte(taskData), &taskStatus); err != nil {
			logrus.Errorf("Failed to unmarshal task status: %v", err)
			return err
		}
		// Update state
		taskStatus.State = state
	}

	// Update LastUpdate
	if taskStatus.Result == nil {
		taskStatus.Result = &TaskResult{}
	}
	now := time.Now()
	taskStatus.Result.LastUpdate = &now

	// Save back to Redis
	taskJSON, err := json.Marshal(taskStatus)
	if err != nil {
		logrus.Errorf("Failed to marshal task status: %v", err)
		return err
	}

	err = redisClient.Set(ctx, taskKey, taskJSON, 0).Err()
	if err != nil {
		logrus.Errorf("Failed to update task state in Redis: %v", err)
		return err
	}

	logrus.Debugf("Updated task state: task_id=%s, state=%s", taskID, state)
	return nil
}

// UpdateTaskResult updates the result of a task
func UpdateTaskResult(redisClient *redis.Client, taskID string, result *TaskResult) error {
	if redisClient == nil {
		return nil
	}

	ctx := context.Background()
	taskKey := "task:" + taskID

	// Get existing task status
	taskData, err := redisClient.Get(ctx, taskKey).Result()
	var taskStatus TaskStatus

	if err == redis.Nil {
		// Task doesn't exist, create new with PENDING state
		taskStatus = TaskStatus{
			State:  TaskStatePending,
			Result: result,
		}
	} else if err != nil {
		logrus.Errorf("Failed to get task from Redis: %v", err)
		return err
	} else {
		// Parse existing task status
		if err := json.Unmarshal([]byte(taskData), &taskStatus); err != nil {
			logrus.Errorf("Failed to unmarshal task status: %v", err)
			return err
		}
		// Update result
		taskStatus.Result = result
	}

	// Set LastUpdate
	if taskStatus.Result != nil {
		now := time.Now()
		taskStatus.Result.LastUpdate = &now
	}

	// Save back to Redis
	taskJSON, err := json.Marshal(taskStatus)
	if err != nil {
		logrus.Errorf("Failed to marshal task status: %v", err)
		return err
	}

	err = redisClient.Set(ctx, taskKey, taskJSON, 0).Err()
	if err != nil {
		logrus.Errorf("Failed to update task result in Redis: %v", err)
		return err
	}

	logrus.Debugf("Updated task result: task_id=%s", taskID)
	return nil
}
