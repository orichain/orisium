#ifndef KALMAN_H
#define KALMAN_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    float process_noise;
    float measurement_noise;
    float estimated_error;
    float state_estimate;
    bool is_initialized;
} kalman_t;

typedef struct {
    double process_noise;
    double measurement_noise;
    double estimated_error;
    double state_estimate;
    bool is_initialized;
} kalman_double_t;

typedef struct {
    long double process_noise;
    long double measurement_noise;
    long double estimated_error;
    long double state_estimate;
    bool is_initialized;
} kalman_long_double_t;

static inline void kalman_init(
    kalman_t *filter,
    float initial_process_noise,
    float initial_measurement_noise,
    float initial_estimated_error,
    float initial_value
) {
    filter->process_noise      = initial_process_noise;
    filter->measurement_noise  = initial_measurement_noise;
    filter->estimated_error    = initial_estimated_error;
    filter->state_estimate     = initial_value;
    filter->is_initialized     = false;
}

static inline void kalman_double_init(
    kalman_double_t *filter,
    double initial_process_noise,
    double initial_measurement_noise,
    double initial_estimated_error,
    double initial_value
) {
    filter->process_noise      = initial_process_noise;
    filter->measurement_noise  = initial_measurement_noise;
    filter->estimated_error    = initial_estimated_error;
    filter->state_estimate     = initial_value;
    filter->is_initialized     = false;
}

static inline void kalman_long_double_init(
    kalman_long_double_t *filter,
    long double initial_process_noise,
    long double initial_measurement_noise,
    long double initial_estimated_error,
    long double initial_value
) {
    filter->process_noise      = initial_process_noise;
    filter->measurement_noise  = initial_measurement_noise;
    filter->estimated_error    = initial_estimated_error;
    filter->state_estimate     = initial_value;
    filter->is_initialized     = false;
}

static inline float kalman_filter(kalman_t *filter, float measurement) {
    // Prediction step
    filter->estimated_error += filter->process_noise;
    // Kalman Gain
    float denominator = filter->estimated_error + filter->measurement_noise;
    float kalman_gain = (denominator != (float)0) ? (filter->estimated_error / denominator) : (float)0;
    // Correction step
    filter->state_estimate += kalman_gain * (measurement - filter->state_estimate);
    filter->estimated_error *= ((float)1 - kalman_gain);
    return filter->state_estimate;
}

static inline double kalman_double_filter(kalman_double_t *filter, double measurement) {
    // Prediction step
    filter->estimated_error += filter->process_noise;
    // Kalman Gain
    double denominator = filter->estimated_error + filter->measurement_noise;
    double kalman_gain = (denominator != (double)0) ? (filter->estimated_error / denominator) : (double)0;
    // Correction step
    filter->state_estimate += kalman_gain * (measurement - filter->state_estimate);
    filter->estimated_error *= ((double)1 - kalman_gain);
    return filter->state_estimate;
}

static inline long double kalman_long_double_filter(kalman_long_double_t *filter, long double measurement) {
    // Prediction step
    filter->estimated_error += filter->process_noise;
    // Kalman Gain
    long double denominator = filter->estimated_error + filter->measurement_noise;
    long double kalman_gain = (denominator != (long double)0) ? (filter->estimated_error / denominator) : (long double)0;
    // Correction step
    filter->state_estimate += kalman_gain * (measurement - filter->state_estimate);
    filter->estimated_error *= ((long double)1 - kalman_gain);
    return filter->state_estimate;
}

#endif
