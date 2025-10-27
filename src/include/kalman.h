#ifndef KALMAN_H
#define KALMAN_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "utilities.h"
#include "constants.h"
#include "log.h"

typedef struct {
    float process_noise;
    float measurement_noise;
    float estimated_error;
    float state_estimate;
    uint8_t is_initialized;
} kalman_t;

typedef struct {
    double process_noise;
    double measurement_noise;
    double estimated_error;
    double state_estimate;
    uint8_t is_initialized;
} kalman_double_t;

typedef struct {
    long double process_noise;
    long double measurement_noise;
    long double estimated_error;
    long double state_estimate;
    uint8_t is_initialized;
} kalman_long_double_t;

typedef struct {
    uint8_t first_check;
    kalman_t kalman_filter;
    uint8_t kalman_initialized_count;
    float *kalman_calibration_samples; 
    float initial_value;
    float temp_ewma_value;
    float value_prediction;
} oricle_t;

typedef struct {
    uint8_t first_check;
    kalman_double_t kalman_filter;
    uint8_t kalman_initialized_count;
    double *kalman_calibration_samples; 
    double initial_value;
    double temp_ewma_value;
    double value_prediction;
} oricle_double_t;

typedef struct {
    uint8_t first_check;
    kalman_long_double_t kalman_filter;
    uint8_t kalman_initialized_count;
    long double *kalman_calibration_samples; 
    long double initial_value;
    long double temp_ewma_value;
    long double value_prediction;
} oricle_long_double_t;

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

static inline void setup_oricle_long_double(oricle_long_double_t *o, long double initial_value) {
    o->first_check = true;
    o->kalman_calibration_samples = NULL;
    o->kalman_initialized_count = 0;
    o->initial_value = initial_value;
    o->temp_ewma_value = initial_value;
    o->value_prediction = initial_value;
}

static inline void setup_oricle_double(oricle_double_t *o, double initial_value) {
    o->first_check = true;
    o->kalman_calibration_samples = NULL;
    o->kalman_initialized_count = 0;
    o->initial_value = initial_value;
    o->temp_ewma_value = initial_value;
    o->value_prediction = initial_value;
}

static inline void cleanup_oricle_long_double(oricle_long_double_t *o) {
    if (o->kalman_calibration_samples) free(o->kalman_calibration_samples);
    o->kalman_calibration_samples = NULL;
}

static inline void cleanup_oricle_double(oricle_double_t *o) {
    if (o->kalman_calibration_samples) free(o->kalman_calibration_samples);
    o->kalman_calibration_samples = NULL;
}

static inline void calculate_oricle_double(const char *label, const char *desc, oricle_double_t *o, double value, double max_value) {
    if (o->first_check) {
        o->first_check = false;
        o->kalman_calibration_samples = (double *)calloc(1, KALMAN_CALIBRATION_SAMPLES * sizeof(double));
        o->temp_ewma_value = o->initial_value;
        o->value_prediction = o->initial_value;
        o->kalman_filter.is_initialized = false;
        o->kalman_initialized_count = 0;
        LOG_DEBUG("%s[%s]First-time setup.", label, desc);
        if (o->initial_value != (double)0) value = o->initial_value;
    }
    if (value < (double)0) value = (double)0;
    if (max_value != (double)0) {
        if (value > max_value) value = max_value;
    }
    if (!o->kalman_filter.is_initialized) {
        if (o->kalman_initialized_count == 0) {
            o->temp_ewma_value = value;
        }
        if (o->kalman_initialized_count < KALMAN_CALIBRATION_SAMPLES) {
            o->kalman_calibration_samples[o->kalman_initialized_count] = (double)value;
            o->kalman_initialized_count++;
            if (o->kalman_initialized_count > 1) {
                o->temp_ewma_value = (double)KALMAN_ALPHA_EWMA * value + ((double)1 - (double)KALMAN_ALPHA_EWMA) * o->temp_ewma_value;
            }
            if (o->kalman_initialized_count == KALMAN_CALIBRATION_SAMPLES) {
                double avg_value = calculate_double_average(o->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES);
                double var_value = calculate_double_variance(o->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES, avg_value);
                free(o->kalman_calibration_samples);
                o->kalman_calibration_samples = NULL;
                if (var_value < (double)0.1) var_value = (double)0.1;
                double kalman_q_avg_task = (double)1;
                double kalman_r_avg_task = var_value;
                double kalman_p0_avg_task = var_value * (double)2;
                kalman_double_init(&o->kalman_filter, kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task, avg_value);
                o->kalman_filter.is_initialized = true;                                
                o->value_prediction = (double)o->kalman_filter.state_estimate;
                LOG_DEBUG("%s[%s]Kalman Filter fully initialized. Avg: %.2f, Var: %.2f (Q:%.2f, R:%.2f, P0:%.2f)",
                                label, desc, avg_value, var_value, kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task);
            } else {
                o->value_prediction = o->temp_ewma_value;
                LOG_DEBUG("%s[%s]Calibrating... (%d/%d) -> Meas: %.2f -> EWMA: %.2f", label, desc, o->kalman_initialized_count, KALMAN_CALIBRATION_SAMPLES, value, o->temp_ewma_value);
            }
        }
        LOG_DEBUG("%s[%s]Meas: %.2f -> Est: %.2f", label, desc, value, o->value_prediction);
        return;
    }
    o->value_prediction = kalman_double_filter(&o->kalman_filter, (double)value);
    if (o->value_prediction < (double)0) o->value_prediction = (double)0;
    if (max_value != (double)0) {
        if (o->value_prediction > max_value) o->value_prediction = max_value;
    }
    LOG_DEBUG("%s[%s]Meas: %.2f -> Est: %.2f", label, desc, value, o->value_prediction);
}

static inline void calculate_oricle_long_double(const char *label, const char *desc, oricle_long_double_t *o, long double value, long double max_value) {
    if (o->first_check) {
        o->first_check = false;
        o->kalman_calibration_samples = (long double *)calloc(1, KALMAN_CALIBRATION_SAMPLES * sizeof(long double));
        o->temp_ewma_value = o->initial_value;
        o->value_prediction = o->initial_value;
        o->kalman_filter.is_initialized = false;
        o->kalman_initialized_count = 0;
        LOG_DEBUG("%s[%s]First-time setup.", label, desc);
        if (o->initial_value != (long double)0) value = o->initial_value;
    }
    if (value < (long double)0) value = (long double)0;
    if (max_value != (long double)0) {
        if (value > max_value) value = max_value;
    }
    if (!o->kalman_filter.is_initialized) {
        if (o->kalman_initialized_count == 0) {
            o->temp_ewma_value = value;
        }
        if (o->kalman_initialized_count < KALMAN_CALIBRATION_SAMPLES) {
            o->kalman_calibration_samples[o->kalman_initialized_count] = (long double)value;
            o->kalman_initialized_count++;
            if (o->kalman_initialized_count > 1) {
                o->temp_ewma_value = (long double)KALMAN_ALPHA_EWMA * value + ((long double)1 - (long double)KALMAN_ALPHA_EWMA) * o->temp_ewma_value;
            }
            if (o->kalman_initialized_count == KALMAN_CALIBRATION_SAMPLES) {
                long double avg_value = calculate_long_double_average(o->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES);
                long double var_value = calculate_long_double_variance(o->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES, avg_value);
                free(o->kalman_calibration_samples);
                o->kalman_calibration_samples = NULL;
                if (var_value < (long double)0.1) var_value = (long double)0.1;
                long double kalman_q_avg_task = (long double)1;
                long double kalman_r_avg_task = var_value;
                long double kalman_p0_avg_task = var_value * (long double)2;
                kalman_long_double_init(&o->kalman_filter, kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task, avg_value);
                o->kalman_filter.is_initialized = true;                                
                o->value_prediction = (long double)o->kalman_filter.state_estimate;
                LOG_DEBUG("%s[%s]Kalman Filter fully initialized. Avg: %.2Lf, Var: %.2Lf (Q:%.2Lf, R:%.2Lf, P0:%.2Lf)",
                                label, desc, avg_value, var_value, kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task);
            } else {
                o->value_prediction = o->temp_ewma_value;
                LOG_DEBUG("%s[%s]Calibrating... (%d/%d) -> Meas: %.2Lf -> EWMA: %.2Lf", label, desc, o->kalman_initialized_count, KALMAN_CALIBRATION_SAMPLES, value, o->temp_ewma_value);
            }
        }
        LOG_DEBUG("%s[%s]Meas: %.2Lf -> Est: %.2Lf", label, desc, value, o->value_prediction);
        return;
    }
    o->value_prediction = kalman_long_double_filter(&o->kalman_filter, (long double)value);
    if (o->value_prediction < (long double)0) o->value_prediction = (long double)0;
    if (max_value != (long double)0) {
        if (o->value_prediction > max_value) o->value_prediction = max_value;
    }
    LOG_DEBUG("%s[%s]Meas: %.2Lf -> Est: %.2Lf", label, desc, value, o->value_prediction);
}

#endif
