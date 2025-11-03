#ifndef TIMER_H
#define TIMER_H

#include <stdint.h>

#include "constants.h"

typedef struct TimerEvent {
    struct TimerEvent *next;  
    struct TimerEvent *prev;  
    uint64_t expiration_tick;
    uint64_t timer_id;
} TimerEvent;

typedef struct TimerBucket {
    TimerEvent *head;  
    TimerEvent *tail;  
} TimerBucket;

typedef struct TimerWheelLevel {
    TimerBucket buckets[WHEEL_SIZE];  
    uint16_t current_index;  
    uint64_t tick_factor; 
    uint64_t current_tick_count;
} TimerWheelLevel;

typedef struct HierarchicalTimerWheel {
    TimerWheelLevel levels[MAX_TIMER_LEVELS]; 
    int tick_event_fd; 
    int add_event_fd;
    int timeout_event_fd;
    TimerEvent *new_event_queue_head;
    TimerEvent *new_event_queue_tail;
    TimerEvent *ready_queue_head;
    TimerEvent *ready_queue_tail;
    uint64_t global_current_tick; 
} HierarchicalTimerWheel;

#endif
