#include "kalman.h"
#include "log.h"
#include "utilities.h"
#include "constants.h"
#include "stdbool.h"

void setup_oricle_long_double(oricle_long_double_t *o, long double initial_value) {
    o->first_check = true;
    o->kalman_initialized_count = 0;
    o->initial_value = initial_value;
    o->temp_ewma_value = initial_value;
    o->value_prediction = initial_value;
}

void setup_oricle_double(oricle_double_t *o, double initial_value) {
    o->first_check = true;
    o->kalman_initialized_count = 0;
    o->initial_value = initial_value;
    o->temp_ewma_value = initial_value;
    o->value_prediction = initial_value;
}

void cleanup_oricle_long_double(oricle_long_double_t *o) {
    
}

void cleanup_oricle_double(oricle_double_t *o) {
    
}

void calculate_oricle_double(const char *label, const char *desc, oricle_double_t *o, double value, double max_value) {
    if (o->first_check) {
        o->first_check = false;
        o->temp_ewma_value = o->initial_value;
        o->value_prediction = o->initial_value;
        o->kalman_filter.is_initialized = false;
        o->kalman_initialized_count = 0;
        LOG_DEVEL_DEBUG("%s[%s]First-time setup.", label, desc);
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
                if (var_value < (double)0.1) var_value = (double)0.1;
                double kalman_q_avg_task = (double)1;
                double kalman_r_avg_task = var_value;
                double kalman_p0_avg_task = var_value * (double)2;
                kalman_double_init(&o->kalman_filter, kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task, avg_value);
                o->kalman_filter.is_initialized = true;                                
                o->value_prediction = (double)o->kalman_filter.state_estimate;
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
    o->value_prediction = kalman_double_filter(&o->kalman_filter, (double)value);
    if (o->value_prediction < (double)0) o->value_prediction = (double)0;
    if (max_value != (double)0) {
        if (o->value_prediction > max_value) o->value_prediction = max_value;
    }
    LOG_DEVEL_DEBUG("%s[%s]Meas: %.2f -> Est: %.2f", label, desc, value, o->value_prediction);
}

void calculate_oricle_long_double(const char *label, const char *desc, oricle_long_double_t *o, long double value, long double max_value) {
    if (o->first_check) {
        o->first_check = false;
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
