#include <Arduino.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <esp_task_wdt.h>
#include <nvs_flash.h>
#include <nvs.h>
#include "ShaTests/nerdSHA256plus.h"
#include "stratum.h"
#include "mining.h"
#include "utils.h"
#include "monitor.h"
#include "timeconst.h"
#include "drivers/displays/display.h"
#include "drivers/storage/storage.h"
#include "drivers/nerd-nos/nerdnos.h"
#include "mining_nerdnos.h"
#include <esp_system.h>

extern WiFiClient client;
extern mining_subscribe mWorker;
extern mining_job mJob;
extern miner_data mMiner;
extern monitor_data mMonitor;

extern pthread_mutex_t job_mutex;
extern double best_diff;
extern unsigned long mLastTXtoPool;

#define ASIC_JOB_COUNT 32
#define ASIC_HISTORY_SIZE 128

typedef struct {
  uint32_t diffs[ASIC_HISTORY_SIZE];
  uint32_t timestamps[ASIC_HISTORY_SIZE];
  uint32_t newest;
  uint32_t oldest;
  uint64_t sum;
  double avg_gh;
  double duration;
  int shares;
} history_t;

static bm_job_t asic_jobs[ASIC_JOB_COUNT] = {0};
static history_t history = {0};
static pthread_mutex_t job_interval_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t job_interval_cond = PTHREAD_COND_INITIALIZER;

double nerdnos_get_avg_hashrate() {
  return history.avg_gh;
}

static void safe_free_job(bm_job_t *job) {
  if (job && job->ntime) {
    nerdnos_free_bm_job(job);
    job->ntime = NULL;  // Only clear the ntime pointer
    // Do not use memset here, as it might interfere with other memory
  }
}

static void calculate_hashrate(history_t *history, uint32_t diff) {
  if (history->newest + 1 >= ASIC_HISTORY_SIZE) {
    history->sum -= history->diffs[history->oldest % ASIC_HISTORY_SIZE];
    history->oldest++;
  }
  history->sum += diff;
  history->diffs[history->newest % ASIC_HISTORY_SIZE] = diff;
  history->timestamps[history->newest % ASIC_HISTORY_SIZE] = esp_timer_get_time();

  uint64_t oldest_timestamp = history->timestamps[history->oldest % ASIC_HISTORY_SIZE];
  uint64_t newest_timestamp = history->timestamps[history->newest % ASIC_HISTORY_SIZE];

  history->duration = (double)(newest_timestamp - oldest_timestamp) / 1.0e6;
  history->shares = (int)history->newest - (int)history->oldest + 1;

  if (history->duration > 0) {
    double avg = (double)(history->sum << 32llu) / history->duration;
    history->avg_gh = avg / 1.0e9;
  }

  history->newest++;
}

static void create_job_timer(TimerHandle_t xTimer) {
  pthread_mutex_lock(&job_interval_mutex);
  pthread_cond_signal(&job_interval_cond);
  pthread_mutex_unlock(&job_interval_mutex);
}

void check_memory() {
  static unsigned long last_check = 0;
  unsigned long now = millis();
  if (now - last_check > 60000) { // Check every minute
    Serial.printf("Free heap: %u bytes\n", ESP.getFreeHeap());
    last_check = now;
  }
}

void runASIC(void * task_id) {
  Serial.printf("[MINER] Started runASIC Task!\n");

  TimerHandle_t job_timer = xTimerCreate("NERDNOS_Job_Timer", NERDNOS_JOB_INTERVAL_MS / portTICK_PERIOD_MS, pdTRUE, NULL, create_job_timer);
  if (job_timer == NULL) {
    Serial.println("Failed to create NERDNOS timer");
    return;
  }

  if (xTimerStart(job_timer, 0) != pdPASS) {
    Serial.println("Failed to start NERDNOS timer");
    return;
  }

  uint32_t extranonce_2 = 0;
  while(1) {
    while(!mMiner.newJob) {
      vTaskDelay(100 / portTICK_PERIOD_MS);
    }

    mMiner.newJob = false;
    mMiner.inRun = true;

    Serial.println(">>> STARTING TO HASH NONCES");
    uint32_t startT = micros();

    // Safely clear all jobs
    for (int i = 0; i < ASIC_JOB_COUNT; i++) {
      safe_free_job(&asic_jobs[i]);
    }

    uint32_t version = strtoul(mJob.version.c_str(), NULL, 16);
    mMonitor.NerdStatus = NM_hashing;
    uint32_t current_difficulty = 0;

    while (mMiner.inRun) {
      check_memory();  // Periodic memory check

      pthread_mutex_lock(&job_interval_mutex);
      pthread_cond_wait(&job_interval_cond, &job_interval_mutex);
      pthread_mutex_unlock(&job_interval_mutex);

      extranonce_2++;
      uint8_t asic_job_id = (uint8_t)(extranonce_2 % ASIC_JOB_COUNT);

      safe_free_job(&asic_jobs[asic_job_id]);

      pthread_mutex_lock(&job_mutex);
      if (current_difficulty != mMiner.poolDifficulty) {
        current_difficulty = mMiner.poolDifficulty;
        nerdnos_set_asic_difficulty(current_difficulty);
        Serial.printf("Set difficulty to %u\n", current_difficulty);
      }

      nerdnos_create_job(&mWorker, &mJob, &asic_jobs[asic_job_id], extranonce_2, current_difficulty);
      
      if (!asic_jobs[asic_job_id].ntime) {
        Serial.println("Failed to create job");
        pthread_mutex_unlock(&job_mutex);
        continue;
      }
      pthread_mutex_unlock(&job_mutex);

      nerdnos_send_work(&asic_jobs[asic_job_id], asic_job_id);

      task_result *result = NULL;
      while ((result = nerdnos_proccess_work(version, 1)) != NULL) {
        if (result->job_id >= ASIC_JOB_COUNT || !asic_jobs[result->job_id].ntime) {
          Serial.printf("Invalid job ID or no job found for ID %02x\n", result->job_id);
          // Do not free result here, as we're not sure if it's heap-allocated
          continue;
        }

        uint8_t hash[32];
        double diff_hash = nerdnos_test_nonce_value(&asic_jobs[result->job_id], result->nonce, result->rolled_version, hash);

        if (diff_hash > best_diff) {
          best_diff = diff_hash;
        }

        if (diff_hash >= asic_jobs[result->job_id].pool_diff) {
          calculate_hashrate(&history, asic_jobs[result->job_id].pool_diff);
          Serial.printf("avg hashrate: %.2fGH/s (history spans %.2fs, %d shares)\n", history.avg_gh, history.duration, history.shares);
        }

        if (diff_hash > mMiner.poolDifficulty) {
          tx_mining_submit_asic(client, mWorker, &asic_jobs[result->job_id], result);
          Serial.println("valid share!");
          Serial.printf("   - Current diff share: %.12f\n", diff_hash);
          Serial.printf("   - Current pool diff : %.12f\n", mMiner.poolDifficulty);
          Serial.printf("Free heap after share: %u bytes\n", ESP.getFreeHeap());
          Serial.print("   - TX SHARE: ");
          for (size_t i = 0; i < 32; i++) {
            Serial.printf("%02x", hash[i]);
          }
          Serial.println();
          mLastTXtoPool = millis();
        }

        // Do not free result here, as we're not sure if it's heap-allocated
      }
    }

    Serial.println("MINER WORK ABORTED >> waiting new job");
    mMiner.inRun = false;
    uint32_t duration = micros() - startT;
    Serial.printf("Mining session duration: %u microseconds\n", duration);

    // Safely clear all jobs
    for (int i = 0; i < ASIC_JOB_COUNT; i++) {
      safe_free_job(&asic_jobs[i]);
    }
  }
}