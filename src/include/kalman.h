#ifndef KALMAN_H
#define KALMAN_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#include "utilities.h"
#include "constants.h"
#include "log.h"
#include "types.h"

typedef struct {
    float state_estimate;
    float value_velocity;
    float process_noise;
    float measurement_noise;
    float process_noise_vel;
    float estimated_error;
    float P_vel_vel;
    float P_pos_vel;
    uint64_t last_timestamp_us;    
    uint8_t is_initialized;
} kalman_t;

typedef struct {
    double state_estimate;
    double value_velocity;
    double process_noise;
    double measurement_noise;
    double process_noise_vel;
    double estimated_error;
    double P_vel_vel;
    double P_pos_vel;
    uint64_t last_timestamp_us;    
    uint8_t is_initialized;
} kalman_double_t;

typedef struct {
    long double state_estimate;
    long double value_velocity;
    long double process_noise;
    long double measurement_noise;
    long double process_noise_vel;
    long double estimated_error;
    long double P_vel_vel;
    long double P_pos_vel;
    uint64_t last_timestamp_us;    
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
    filter->process_noise           = initial_process_noise;
    filter->measurement_noise       = initial_measurement_noise;
    filter->estimated_error         = initial_estimated_error;
    filter->state_estimate          = initial_value;
    filter->process_noise_vel       = initial_process_noise / 10.0f;
    filter->value_velocity          = 0.0f;
    filter->P_vel_vel               = initial_estimated_error;
    filter->P_pos_vel               = 0.0f;
    filter->last_timestamp_us       = (uint64_t)0;
    filter->is_initialized          = false;
}

static inline void kalman_double_init(
    kalman_double_t *filter,
    double initial_process_noise,
    double initial_measurement_noise,
    double initial_estimated_error,
    double initial_value
) {
    filter->process_noise           = initial_process_noise;
    filter->measurement_noise       = initial_measurement_noise;
    filter->estimated_error         = initial_estimated_error;
    filter->state_estimate          = initial_value;
    filter->process_noise_vel       = initial_process_noise / 10.0;
    filter->value_velocity          = 0.0;
    filter->P_vel_vel               = initial_estimated_error;
    filter->P_pos_vel               = 0.0;
    filter->last_timestamp_us       = (uint64_t)0;
    filter->is_initialized          = false;
}

static inline void kalman_long_double_init(
    kalman_long_double_t *filter,
    long double initial_process_noise,
    long double initial_measurement_noise,
    long double initial_estimated_error,
    long double initial_value
) {
    filter->process_noise           = initial_process_noise;
    filter->measurement_noise       = initial_measurement_noise;
    filter->estimated_error         = initial_estimated_error;
    filter->state_estimate          = initial_value;
    filter->process_noise_vel       = initial_process_noise / 10.0L;
    filter->value_velocity          = 0.0L;
    filter->P_vel_vel               = initial_estimated_error;
    filter->P_pos_vel               = 0.0L;
    filter->last_timestamp_us       = (uint64_t)0;
    filter->is_initialized          = false;
}

static inline float kalman_filter(kalman_t *filter, float measurement, uint64_t current_timestamp_us) {
    float delta_t = 0.0f;
    if (filter->last_timestamp_us != (uint64_t)0) {
        delta_t = (float)(current_timestamp_us - filter->last_timestamp_us) / (float)1e9;
    }
    filter->last_timestamp_us = current_timestamp_us;
    if (delta_t < 1e-6f) {
        return filter->state_estimate;
    }
    float predicted_value = filter->state_estimate + filter->value_velocity * delta_t;
    float FP_pos_pos = filter->estimated_error + filter->P_pos_vel * delta_t;
    float FP_pos_vel = filter->P_pos_vel + filter->P_vel_vel * delta_t;
    float P_pos_pos_temp = FP_pos_pos + FP_pos_vel * delta_t;
    filter->P_pos_vel = FP_pos_vel;
    filter->estimated_error = P_pos_pos_temp + filter->process_noise;
    filter->P_vel_vel = filter->P_vel_vel + filter->process_noise_vel;
    float innovation = measurement - predicted_value;
    float innovation_covariance = filter->estimated_error + filter->measurement_noise;
    if (fabsf(innovation_covariance) < 1e-9f) {
        return predicted_value;
    }
    float kalman_gain_pos = filter->estimated_error / innovation_covariance;
    float kalman_gain_vel = filter->P_pos_vel / innovation_covariance;
    filter->state_estimate = predicted_value + kalman_gain_pos * innovation;
    filter->value_velocity = filter->value_velocity + kalman_gain_vel * innovation;
    filter->estimated_error -= kalman_gain_pos * filter->estimated_error;
    filter->P_pos_vel -= kalman_gain_pos * filter->P_pos_vel;
    filter->P_vel_vel -= kalman_gain_vel * filter->P_pos_vel;
    return filter->state_estimate;
}

static inline double kalman_double_filter(kalman_double_t *filter, double measurement, uint64_t current_timestamp_us) {
    double delta_t = 0.0;
    if (filter->last_timestamp_us != (uint64_t)0) {
        delta_t = (double)(current_timestamp_us - filter->last_timestamp_us) / (double)1e9;
    }
    filter->last_timestamp_us = current_timestamp_us;
    if (delta_t < 1e-6) {
        return filter->state_estimate;
    }
    double predicted_value = filter->state_estimate + filter->value_velocity * delta_t;
    double FP_pos_pos = filter->estimated_error + filter->P_pos_vel * delta_t;
    double FP_pos_vel = filter->P_pos_vel + filter->P_vel_vel * delta_t;
    double P_pos_pos_temp = FP_pos_pos + FP_pos_vel * delta_t;
    filter->P_pos_vel = FP_pos_vel;
    filter->estimated_error = P_pos_pos_temp + filter->process_noise;
    filter->P_vel_vel = filter->P_vel_vel + filter->process_noise_vel;
    double innovation = measurement - predicted_value;
    double innovation_covariance = filter->estimated_error + filter->measurement_noise;
    if (fabs(innovation_covariance) < 1e-9) {
        return predicted_value;
    }
    double kalman_gain_pos = filter->estimated_error / innovation_covariance;
    double kalman_gain_vel = filter->P_pos_vel / innovation_covariance;
    filter->state_estimate = predicted_value + kalman_gain_pos * innovation;
    filter->value_velocity = filter->value_velocity + kalman_gain_vel * innovation;
    filter->estimated_error -= kalman_gain_pos * filter->estimated_error;
    filter->P_pos_vel -= kalman_gain_pos * filter->P_pos_vel;
    filter->P_vel_vel -= kalman_gain_vel * filter->P_pos_vel;
    return filter->state_estimate;
}

static inline long double kalman_long_double_filter(kalman_long_double_t *filter, long double measurement, uint64_t current_timestamp_us) {
    long double delta_t = 0.0L;
    if (filter->last_timestamp_us != (uint64_t)0) {
        delta_t = (long double)(current_timestamp_us - filter->last_timestamp_us) / (long double)1e9;
    }
    filter->last_timestamp_us = current_timestamp_us;
    if (delta_t < 1e-6L) {
        return filter->state_estimate;
    }
    long double predicted_value = filter->state_estimate + filter->value_velocity * delta_t;
    long double FP_pos_pos = filter->estimated_error + filter->P_pos_vel * delta_t;
    long double FP_pos_vel = filter->P_pos_vel + filter->P_vel_vel * delta_t;
    long double P_pos_pos_temp = FP_pos_pos + FP_pos_vel * delta_t;
    filter->P_pos_vel = FP_pos_vel;
    filter->estimated_error = P_pos_pos_temp + filter->process_noise;
    filter->P_vel_vel = filter->P_vel_vel + filter->process_noise_vel;
    long double innovation = measurement - predicted_value;
    long double innovation_covariance = filter->estimated_error + filter->measurement_noise;
    if (fabsl(innovation_covariance) < 1e-9L) {
        return predicted_value;
    }
    long double kalman_gain_pos = filter->estimated_error / innovation_covariance;
    long double kalman_gain_vel = filter->P_pos_vel / innovation_covariance;
    filter->state_estimate = predicted_value + kalman_gain_pos * innovation;
    filter->value_velocity = filter->value_velocity + kalman_gain_vel * innovation;
    filter->estimated_error -= kalman_gain_pos * filter->estimated_error;
    filter->P_pos_vel -= kalman_gain_pos * filter->P_pos_vel;
    filter->P_vel_vel -= kalman_gain_vel * filter->P_pos_vel;
    return filter->state_estimate;
}

static inline void setup_oricle(oricle_t *o, float initial_value) {
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

static inline void setup_oricle_long_double(oricle_long_double_t *o, long double initial_value) {
    o->first_check = true;
    o->kalman_calibration_samples = NULL;
    o->kalman_initialized_count = 0;
    o->initial_value = initial_value;
    o->temp_ewma_value = initial_value;
    o->value_prediction = initial_value;
}

static inline void cleanup_oricle(oricle_t *o) {
    if (o->kalman_calibration_samples) free(o->kalman_calibration_samples);
    o->kalman_calibration_samples = NULL;
}

static inline void cleanup_oricle_double(oricle_double_t *o) {
    if (o->kalman_calibration_samples) free(o->kalman_calibration_samples);
    o->kalman_calibration_samples = NULL;
}

static inline void cleanup_oricle_long_double(oricle_long_double_t *o) {
    if (o->kalman_calibration_samples) free(o->kalman_calibration_samples);
    o->kalman_calibration_samples = NULL;
}

static inline void calculate_oricle(const char *label, const char *desc, oricle_t *o, float value, float max_value) {
    uint64_t_status_t current_time = get_monotonic_time_ns(label);
    if (current_time.status != SUCCESS) {
        return;
    }
    if (o->first_check) {
        o->first_check = false;
        o->kalman_calibration_samples = (float *)calloc(KALMAN_CALIBRATION_SAMPLES, sizeof(float));
        o->temp_ewma_value = o->initial_value;
        o->value_prediction = o->initial_value;
        o->kalman_filter.is_initialized = false;
        o->kalman_initialized_count = 0;
        LOG_DEBUG("%s[%s]First-time setup.", label, desc);
        if (o->initial_value != 0.0f) value = o->initial_value;
    }
    if (value < 0.0f) value = 0.0f;
    if (max_value != 0.0f) {
        if (value > max_value) value = max_value;
    }    
    if (!o->kalman_filter.is_initialized) {
        if (o->kalman_initialized_count == 0) {
            o->temp_ewma_value = value;
            o->kalman_filter.last_timestamp_us = current_time.r_uint64_t;
        }
        if (o->kalman_calibration_samples && o->kalman_initialized_count < KALMAN_CALIBRATION_SAMPLES) {
            o->kalman_calibration_samples[o->kalman_initialized_count] = value;
            o->kalman_initialized_count++;
            if (o->kalman_initialized_count > 1) {
                o->temp_ewma_value = KALMAN_ALPHA_EWMA * value + (1.0f - KALMAN_ALPHA_EWMA) * o->temp_ewma_value;
            }
            if (o->kalman_initialized_count == KALMAN_CALIBRATION_SAMPLES) {
                float avg_value = calculate_average(o->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES);
                float var_value = calculate_variance(o->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES, avg_value);
                free(o->kalman_calibration_samples);
                o->kalman_calibration_samples = NULL;               
                if (var_value < 0.1f) var_value = 0.1f;
                float kalman_q_avg_task = 1.0f;
                float kalman_r_avg_task = var_value;
                float kalman_p0_avg_task = var_value * 2.0f;
                kalman_init(&o->kalman_filter, kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task, avg_value);
                o->kalman_filter.is_initialized = true;              
                o->value_prediction = o->kalman_filter.state_estimate;
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
    o->value_prediction = kalman_filter(&o->kalman_filter, value, current_time.r_uint64_t);
    if (o->value_prediction < 0.0f) o->value_prediction = 0.0f;
    if (max_value != 0.0f) {
        if (o->value_prediction > max_value) o->value_prediction = max_value;
    }
    LOG_DEBUG("%s[%s]Meas: %.2f -> Est: %.2f (Vel: %.2f)", label, desc, value, o->value_prediction, o->kalman_filter.value_velocity);
}

static inline void calculate_oricle_double(const char *label, const char *desc, oricle_double_t *o, double value, double max_value) {
    uint64_t_status_t current_time = get_monotonic_time_ns(label);
    if (current_time.status != SUCCESS) {
        return;
    }
    if (o->first_check) {
        o->first_check = false;
        o->kalman_calibration_samples = (double *)calloc(KALMAN_CALIBRATION_SAMPLES, sizeof(double));
        o->temp_ewma_value = o->initial_value;
        o->value_prediction = o->initial_value;
        o->kalman_filter.is_initialized = false;
        o->kalman_initialized_count = 0;
        LOG_DEBUG("%s[%s]First-time setup.", label, desc);
        if (o->initial_value != 0.0) value = o->initial_value;
    }
    if (value < 0.0) value = 0.0;
    if (max_value != 0.0) {
        if (value > max_value) value = max_value;
    }    
    if (!o->kalman_filter.is_initialized) {
        if (o->kalman_initialized_count == 0) {
            o->temp_ewma_value = value;
            o->kalman_filter.last_timestamp_us = current_time.r_uint64_t;
        }
        if (o->kalman_calibration_samples && o->kalman_initialized_count < KALMAN_CALIBRATION_SAMPLES) {
            o->kalman_calibration_samples[o->kalman_initialized_count] = value;
            o->kalman_initialized_count++;
            if (o->kalman_initialized_count > 1) {
                o->temp_ewma_value = KALMAN_ALPHA_EWMA * value + (1.0 - KALMAN_ALPHA_EWMA) * o->temp_ewma_value;
            }
            if (o->kalman_initialized_count == KALMAN_CALIBRATION_SAMPLES) {
                double avg_value = calculate_double_average(o->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES);
                double var_value = calculate_double_variance(o->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES, avg_value);
                free(o->kalman_calibration_samples);
                o->kalman_calibration_samples = NULL;
                if (var_value < 0.1) var_value = 0.1;                
                double kalman_q_avg_task = 1.0;
                double kalman_r_avg_task = var_value;
                double kalman_p0_avg_task = var_value * 2.0;
                kalman_double_init(&o->kalman_filter, kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task, avg_value);
                o->kalman_filter.is_initialized = true;              
                o->value_prediction = o->kalman_filter.state_estimate;
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
    o->value_prediction = kalman_double_filter(&o->kalman_filter, value, current_time.r_uint64_t);
    if (o->value_prediction < 0.0) o->value_prediction = 0.0;
    if (max_value != 0.0) {
        if (o->value_prediction > max_value) o->value_prediction = max_value;
    }
    LOG_DEBUG("%s[%s]Meas: %.2f -> Est: %.2f (Vel: %.2f)", label, desc, value, o->value_prediction, o->kalman_filter.value_velocity);
}

#if defined(LONGINTV_TEST)
static inline void calculate_oricle_doubleX(const char *label, const char *desc, oricle_double_t *o, double value, double max_value) {
    uint64_t_status_t current_time = get_monotonic_time_ns(label);
    if (current_time.status != SUCCESS) {
        return;
    }
    if (o->first_check) {
        o->first_check = false;
        o->kalman_calibration_samples = (double *)calloc(KALMAN_CALIBRATION_SAMPLES, sizeof(double));
        o->temp_ewma_value = o->initial_value;
        o->value_prediction = o->initial_value;
        o->kalman_filter.is_initialized = false;
        o->kalman_initialized_count = 0;
        LOG_DEVEL_DEBUG("%s[%s]First-time setup.", label, desc);
        if (o->initial_value != 0.0) value = o->initial_value;
    }
    if (value < 0.0) value = 0.0;
    if (max_value != 0.0) {
        if (value > max_value) value = max_value;
    }    
    if (!o->kalman_filter.is_initialized) {
        if (o->kalman_initialized_count == 0) {
            o->temp_ewma_value = value;
            o->kalman_filter.last_timestamp_us = current_time.r_uint64_t;
        }
        if (o->kalman_calibration_samples && o->kalman_initialized_count < KALMAN_CALIBRATION_SAMPLES) {
            o->kalman_calibration_samples[o->kalman_initialized_count] = value;
            o->kalman_initialized_count++;
            if (o->kalman_initialized_count > 1) {
                o->temp_ewma_value = KALMAN_ALPHA_EWMA * value + (1.0 - KALMAN_ALPHA_EWMA) * o->temp_ewma_value;
            }
            if (o->kalman_initialized_count == KALMAN_CALIBRATION_SAMPLES) {
                double avg_value = calculate_double_average(o->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES);
                double var_value = calculate_double_variance(o->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES, avg_value);
                free(o->kalman_calibration_samples);
                o->kalman_calibration_samples = NULL;
                if (var_value < 0.1) var_value = 0.1;                
                double kalman_q_avg_task = 1.0;
                double kalman_r_avg_task = var_value;
                double kalman_p0_avg_task = var_value * 2.0;
                kalman_double_init(&o->kalman_filter, kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task, avg_value);
                o->kalman_filter.is_initialized = true;              
                o->value_prediction = o->kalman_filter.state_estimate;
                LOG_DEVEL_DEBUG("%s[%s]Kalman Filter fully initialized. Avg: %.2f, Var: %.2f (Q:%.2f, R:%.2f, P0:%.2f)",
                                label, desc, avg_value, var_value, kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task);
            } else {
                o->value_prediction = o->temp_ewma_value;
                LOG_DEVEL_DEBUG("%s[%s]Calibrating... (%d/%d) -> Meas: %.2f -> EWMA: %.2f", label, desc, o->kalman_initialized_count, KALMAN_CALIBRATION_SAMPLES, value, o->temp_ewma_value);
            }
        }
        LOG_DEVEL_DEBUG("%s[%s]Meas: %.2f -> Est: %.2f", label, desc, value, o->value_prediction);
        return;
    }    
    o->value_prediction = kalman_double_filter(&o->kalman_filter, value, current_time.r_uint64_t);
    if (o->value_prediction < 0.0) o->value_prediction = 0.0;
    if (max_value != 0.0) {
        if (o->value_prediction > max_value) o->value_prediction = max_value;
    }
    LOG_DEVEL_DEBUG("%s[%s]Meas: %.2f -> Est: %.2f (Vel: %.2f)", label, desc, value, o->value_prediction, o->kalman_filter.value_velocity);
}
#endif

static inline void calculate_oricle_long_double(const char *label, const char *desc, oricle_long_double_t *o, long double value, long double max_value) {
    uint64_t_status_t current_time = get_monotonic_time_ns(label);
    if (current_time.status != SUCCESS) {
        return;
    }
    if (o->first_check) {
        o->first_check = false;
        o->kalman_calibration_samples = (long double *)calloc(KALMAN_CALIBRATION_SAMPLES, sizeof(long double));
        o->temp_ewma_value = o->initial_value;
        o->value_prediction = o->initial_value;
        o->kalman_filter.is_initialized = false;
        o->kalman_initialized_count = 0;
        LOG_DEBUG("%s[%s]First-time setup.", label, desc);
        if (o->initial_value != 0.0L) value = o->initial_value;
    }
    if (value < 0.0L) value = 0.0L;
    if (max_value != 0.0L) {
        if (value > max_value) value = max_value;
    }    
    if (!o->kalman_filter.is_initialized) {
        if (o->kalman_initialized_count == 0) {
            o->temp_ewma_value = value;
            o->kalman_filter.last_timestamp_us = current_time.r_uint64_t;
        }
        if (o->kalman_calibration_samples && o->kalman_initialized_count < KALMAN_CALIBRATION_SAMPLES) {
            o->kalman_calibration_samples[o->kalman_initialized_count] = value;
            o->kalman_initialized_count++;
            if (o->kalman_initialized_count > 1) {
                o->temp_ewma_value = KALMAN_ALPHA_EWMA * value + (1.0L - KALMAN_ALPHA_EWMA) * o->temp_ewma_value;
            }
            if (o->kalman_initialized_count == KALMAN_CALIBRATION_SAMPLES) {
                long double avg_value = calculate_long_double_average(o->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES);
                long double var_value = calculate_long_double_variance(o->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES, avg_value);
                free(o->kalman_calibration_samples);
                o->kalman_calibration_samples = NULL;                
                if (var_value < 0.1L) var_value = 0.1L;
                long double kalman_q_avg_task = 1.0L;
                long double kalman_r_avg_task = var_value;
                long double kalman_p0_avg_task = var_value * 2.0L;
                kalman_long_double_init(&o->kalman_filter, kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task, avg_value);
                o->kalman_filter.is_initialized = true;              
                o->value_prediction = o->kalman_filter.state_estimate;
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
    o->value_prediction = kalman_long_double_filter(&o->kalman_filter, value, current_time.r_uint64_t);
    if (o->value_prediction < 0.0L) o->value_prediction = 0.0L;
    if (max_value != 0.0L) {
        if (o->value_prediction > max_value) o->value_prediction = max_value;
    }
    LOG_DEBUG("%s[%s]Meas: %.2Lf -> Est: %.2Lf (Vel: %.2Lf)", label, desc, value, o->value_prediction, o->kalman_filter.value_velocity);
}

#endif
