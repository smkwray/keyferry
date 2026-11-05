// Microphone (ADR 0018 rule 14). The ES8311 codec runs in recording mode only (its DAC off and the
// speaker amplifier driven off); a capture task reads it over I2S in 2 ms blocks and applies the
// computer's volume and both mutes. Blocks reach TinyUSB's UAC2 FIFO only on the TinyUSB task,
// which also opens, closes and resets the stream, and each block carries the stream generation it
// was captured in, so a block only ever lands in that recording. Nothing is stored or sent
// anywhere else.
#include "mic.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cstdlib>

#include "bsp/esp-bsp.h"
#include "driver/i2s_std.h"
#include "esp_codec_dev.h"
#include "esp_codec_dev_defaults.h"
#include "esp_log.h"
#include "device/usbd_pvt.h"  // usbd_defer_func: run on the TinyUSB task (pinned TinyUSB 0.21)
#include "freertos/FreeRTOS.h"
#include "freertos/message_buffer.h"
#include "freertos/task.h"
#include "tusb.h"
#include "usb_device.h"

namespace keyferry::handheld {
namespace {

constexpr char kTag[] = "mic";
constexpr std::uint32_t kSampleRate = 48000;
constexpr int kBlockSamples = 96;  // 2 ms
constexpr int kFaultReads = 3;     // consecutive failed reads: the chip counts as failed for this boot
constexpr int kReadyBlocks = 100;  // startup: 200 ms to see a non-silent block

// Entity IDs of TUD_AUDIO20_MIC_ONE_CH_DESCRIPTOR, and its streaming interface (usb_device.cpp
// puts the control interface at 0).
constexpr std::uint8_t kInputTerminal = 0x01;
constexpr std::uint8_t kFeatureUnit = 0x02;
constexpr std::uint8_t kClock = 0x04;
constexpr std::uint8_t kStreamingInterface = 1;

// The computer's volume control: -40 dB to 0 dB in 1 dB steps (UAC2 units are 1/256 dB). It only
// attenuates; Sensitivity on the board sets the codec's analog gain.
constexpr std::int16_t kVolumeMin = -40 * 256;
constexpr std::int16_t kVolumeMax = 0;
constexpr std::uint16_t kVolumeStep = 256;

esp_codec_dev_handle_t g_codec = nullptr;
i2s_chan_handle_t g_rx = nullptr;
std::atomic<bool> g_fault{false};
std::atomic<bool> g_stopped{false};          // leaving the function: no more samples this boot
MessageBufferHandle_t g_blocks = nullptr;    // capture task -> TinyUSB task, whole blocks only
std::atomic<bool> g_submit_pending{false};
std::atomic<bool> g_board_mute{false};
std::atomic<int> g_peak{0};
// TinyUSB task: the computer's controls (index 0 master, 1 the one channel) and the stream.
std::atomic<bool> g_host_mute[2] = {};
std::atomic<std::int16_t> g_host_volume[2] = {};
std::atomic<std::int32_t> g_gain_q16{1 << 16};
std::atomic<bool> g_streaming{false};
std::atomic<std::uint32_t> g_stream_session{0};
// Changes whenever the computer opens or closes the stream: a block is sent only into the
// recording it was captured for, never into the next one.
std::atomic<std::uint32_t> g_stream_generation{0};

struct Block {
  std::uint32_t generation;  // g_stream_generation before the samples were read
  std::int16_t samples[kBlockSamples];
};

// Open by the computer in the current USB session (a bus reset or re-enumeration starts a new one).
bool Streaming() {
  return g_streaming.load() && g_stream_session.load() == UsbDeviceSession() && tud_mounted() &&
         !tud_suspended();
}

void UpdateGain() {
  const float db = static_cast<float>(g_host_volume[0].load() + g_host_volume[1].load()) / 256.0f;
  g_gain_q16.store(static_cast<std::int32_t>(std::pow(10.0f, std::max(db, -80.0f) / 20.0f) * 65536.0f));
}

bool StartCodec(int gain_db) {
  if (bsp_i2c_init() != ESP_OK) return false;
  i2s_chan_config_t channel = I2S_CHANNEL_DEFAULT_CONFIG(CONFIG_BSP_I2S_NUM, I2S_ROLE_MASTER);
  channel.dma_desc_num = 6;
  channel.dma_frame_num = kBlockSamples;
  if (i2s_new_channel(&channel, nullptr, &g_rx) != ESP_OK) return false;
  i2s_std_config_t std_config{};
  std_config.clk_cfg = I2S_STD_CLK_DEFAULT_CONFIG(kSampleRate);
  std_config.slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO);
  std_config.gpio_cfg.mclk = BSP_I2S_MCLK;
  std_config.gpio_cfg.bclk = BSP_I2S_SCLK;
  std_config.gpio_cfg.ws = BSP_I2S_LCLK;
  std_config.gpio_cfg.dout = I2S_GPIO_UNUSED;
  std_config.gpio_cfg.din = BSP_I2S_DSIN;
  if (i2s_channel_init_std_mode(g_rx, &std_config) != ESP_OK || i2s_channel_enable(g_rx) != ESP_OK) {
    return false;
  }

  audio_codec_i2s_cfg_t i2s{};
  i2s.port = CONFIG_BSP_I2S_NUM;
  i2s.rx_handle = g_rx;
  audio_codec_i2c_cfg_t i2c{};
  i2c.port = BSP_I2C_NUM;
  i2c.addr = ES8311_CODEC_DEFAULT_ADDR;
  i2c.bus_handle = bsp_i2c_get_handle();
  const audio_codec_data_if_t* data = audio_codec_new_i2s_data(&i2s);
  const audio_codec_ctrl_if_t* control = audio_codec_new_i2c_ctrl(&i2c);
  const audio_codec_gpio_if_t* gpio = audio_codec_new_gpio();
  if (data == nullptr || control == nullptr || gpio == nullptr) return false;

  es8311_codec_cfg_t es8311{};
  es8311.ctrl_if = control;
  es8311.gpio_if = gpio;
  es8311.codec_mode = ESP_CODEC_DEV_WORK_MODE_ADC;  // no DAC, so the speaker amplifier stays off
  es8311.pa_pin = BSP_POWER_AMP_IO;  // ADC mode drives it off at open and never turns it on
  es8311.use_mclk = true;
  const audio_codec_if_t* codec = es8311_codec_new(&es8311);
  if (codec == nullptr) return false;
  esp_codec_dev_cfg_t device{};
  device.dev_type = ESP_CODEC_DEV_TYPE_IN;
  device.codec_if = codec;
  device.data_if = data;
  g_codec = esp_codec_dev_new(&device);
  if (g_codec == nullptr) return false;
  esp_codec_dev_sample_info_t format{};
  format.sample_rate = kSampleRate;
  format.channel = 1;
  format.bits_per_sample = 16;
  if (esp_codec_dev_open(g_codec, &format) != ESP_CODEC_DEV_OK) return false;
  return esp_codec_dev_set_in_gain(g_codec, static_cast<float>(gain_db)) == ESP_CODEC_DEV_OK;
}

// TinyUSB task: queued blocks into the driver's FIFO, in order with stream open/close and bus
// resets (all on this task), so the stream decision and the write are one step. A block that
// would overwrite unread audio is dropped instead.
void Submit(void*) {
  g_submit_pending.store(false);
  Block block;
  while (xMessageBufferReceive(g_blocks, &block, sizeof(block), 0) == sizeof(block)) {
    if (g_stopped.load() || g_fault.load() || !Streaming() ||
        block.generation != g_stream_generation.load()) {
      continue;
    }
    tu_fifo_t* fifo = tud_audio_get_ep_in_ff();
    if (fifo == nullptr || tu_fifo_remaining(fifo) < sizeof(block.samples)) continue;
    tud_audio_write(block.samples, sizeof(block.samples));
  }
}

// Reads one block; false on an error.
bool ReadBlock(std::int16_t* block) {
  return esp_codec_dev_read(g_codec, block, kBlockSamples * sizeof(std::int16_t)) == ESP_CODEC_DEV_OK;
}

void CaptureTask(void*) {
  Block captured;
  std::int16_t* const block = captured.samples;
  int failures = 0;
  bool was_streaming = false;
  for (;;) {
    captured.generation = g_stream_generation.load();
    if (!ReadBlock(block)) {
      if (++failures < kFaultReads) {
        vTaskDelay(pdMS_TO_TICKS(10));
        continue;
      }
      // Terminal for this boot: no further samples, and the screen says so until Microphone is
      // opened again.
      g_fault.store(true);
      ESP_LOGE(kTag, "no samples from the codec; microphone stopped");
      vTaskDelete(nullptr);
    }
    failures = 0;
    int peak = 0;
    for (const std::int16_t sample : captured.samples) peak = std::max(peak, std::abs(static_cast<int>(sample)));
    int seen = g_peak.load();
    while (peak > seen && !g_peak.compare_exchange_weak(seen, peak)) {
    }
    const bool streaming = Streaming();  // a hint; Submit() decides on the TinyUSB task
    if (streaming != was_streaming) {
      ESP_LOGI(kTag, "computer %s the stream (stack free %u B)", streaming ? "opened" : "closed",
               static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)));
      was_streaming = streaming;
    }
    if (!streaming || g_stopped.load()) continue;
    if (g_board_mute.load() || g_host_mute[0].load() || g_host_mute[1].load()) {
      std::memset(captured.samples, 0, sizeof(captured.samples));
    } else {
      const std::int32_t gain = g_gain_q16.load();
      if (gain < (1 << 16)) {
        for (std::int16_t& sample : captured.samples) sample = static_cast<std::int16_t>((sample * gain) >> 16);
      }
    }
    xMessageBufferSend(g_blocks, &captured, sizeof(captured), 0);  // full: this block is dropped
    if (!g_submit_pending.exchange(true)) usbd_defer_func(Submit, nullptr, false);
  }
}

// Startup: the codec answers over I2C with the gain just written, and I2S delivers sound (a live
// microphone is never exactly silent). Only then is a microphone presented to the computer.
bool CaptureReady(int gain_db) {
  int gain_register = -1;
  if (esp_codec_dev_read_reg(g_codec, 0x16, &gain_register) != ESP_CODEC_DEV_OK ||  // ADC PGA gain
      gain_register != std::clamp(gain_db / 6, 0, 7)) {
    ESP_LOGE(kTag, "codec gain did not read back (%d)", gain_register);
    return false;
  }
  std::int16_t block[kBlockSamples];
  for (int i = 0; i < kReadyBlocks; ++i) {
    if (!ReadBlock(block)) return false;
    for (const std::int16_t sample : block) {
      if (sample != 0) return true;
    }
  }
  ESP_LOGE(kTag, "codec delivered only silence");
  return false;
}

}  // namespace

bool MicStart(int gain_db) {
  UpdateGain();
  g_blocks = xMessageBufferCreate(4 * (sizeof(Block) + sizeof(std::size_t)));
  if (g_blocks == nullptr || !StartCodec(gain_db) || !CaptureReady(gain_db) ||
      xTaskCreate(CaptureTask, "kf_mic", 3072, nullptr, 6, nullptr) != pdPASS) {
    ESP_LOGE(kTag, "audio chip did not start");
    g_fault.store(true);
    return true;  // the screen says so; no microphone is presented to the computer
  }
  return UsbDeviceStart(UsbPersonality::kMic);
}

void MicStop() { g_stopped.store(true); }

bool MicLive() { return !g_stopped.load() && !g_fault.load() && Streaming(); }

void MicSetMuted(bool muted) { g_board_mute.store(muted); }

void MicSetGain(int gain_db) {
  if (g_codec != nullptr) esp_codec_dev_set_in_gain(g_codec, static_cast<float>(gain_db));
}

MicStatus MicStatusNow() {
  MicStatus status;
  status.usb = tud_mounted() && !tud_suspended();
  status.live = MicLive();
  status.muted = g_board_mute.load();
  status.host_muted = g_host_mute[0].load() || g_host_mute[1].load();
  status.fault = g_fault.load();
  const int peak = g_peak.exchange(0);
  if (peak > 0) {
    const float db = 20.0f * std::log10(static_cast<float>(peak) / 32768.0f);
    status.level = std::clamp(static_cast<int>((db + 60.0f) * 100.0f / 60.0f), 0, 100);
  }
  return status;
}

}  // namespace keyferry::handheld

// --- TinyUSB UAC2 callbacks (TinyUSB task) ------------------------------------------------------

namespace kh = keyferry::handheld;

extern "C" bool tud_audio_set_itf_cb(std::uint8_t, tusb_control_request_t const* request) {
  if (TU_U16_LOW(request->wIndex) == kh::kStreamingInterface) {
    kh::g_stream_session.store(kh::UsbDeviceSession());
    kh::g_streaming.store(TU_U16_LOW(request->wValue) != 0);
    kh::g_stream_generation.fetch_add(1);
  }
  return true;
}

extern "C" bool tud_audio_set_itf_close_ep_cb(std::uint8_t, tusb_control_request_t const* request) {
  if (TU_U16_LOW(request->wIndex) == kh::kStreamingInterface) {
    kh::g_streaming.store(false);
    kh::g_stream_generation.fetch_add(1);
  }
  return true;
}

extern "C" bool tud_audio_get_req_entity_cb(std::uint8_t rhport, tusb_control_request_t const* request) {
  const std::uint8_t channel = TU_U16_LOW(request->wValue);
  const std::uint8_t control = TU_U16_HIGH(request->wValue);
  const std::uint8_t entity = TU_U16_HIGH(request->wIndex);
  const bool current = request->bRequest == AUDIO20_CS_REQ_CUR;
  const bool range = request->bRequest == AUDIO20_CS_REQ_RANGE;
  const auto send = [&](void* data, std::uint16_t length) {
    return tud_audio_buffer_and_schedule_control_xfer(rhport, request, data, length);
  };
  if (entity == kh::kInputTerminal && control == AUDIO20_TE_CTRL_CONNECTOR && current) {
    audio20_desc_channel_cluster_t cluster{};
    cluster.bNrChannels = 1;
    return send(&cluster, sizeof(cluster));
  }
  if (entity == kh::kFeatureUnit && channel <= 1) {
    if (control == AUDIO20_FU_CTRL_MUTE && current) {
      audio20_control_cur_1_t mute{};
      mute.bCur = kh::g_host_mute[channel].load() ? 1 : 0;
      return send(&mute, sizeof(mute));
    }
    if (control == AUDIO20_FU_CTRL_VOLUME && current) {
      audio20_control_cur_2_t volume{};
      volume.bCur = kh::g_host_volume[channel].load();
      return send(&volume, sizeof(volume));
    }
    if (control == AUDIO20_FU_CTRL_VOLUME && range) {
      audio20_control_range_2_n_t(1) volumes{};
      volumes.wNumSubRanges = 1;
      volumes.subrange[0].bMin = kh::kVolumeMin;
      volumes.subrange[0].bMax = kh::kVolumeMax;
      volumes.subrange[0].bRes = kh::kVolumeStep;
      return send(&volumes, sizeof(volumes));
    }
  }
  if (entity == kh::kClock) {
    // TinyUSB reads the rate from this reply to size the stream's packets.
    if (control == AUDIO20_CS_CTRL_SAM_FREQ && current) {
      audio20_control_cur_4_t rate{};
      rate.bCur = static_cast<std::int32_t>(kh::kSampleRate);
      return send(&rate, sizeof(rate));
    }
    if (control == AUDIO20_CS_CTRL_SAM_FREQ && range) {
      audio20_control_range_4_n_t(1) rates{};
      rates.wNumSubRanges = 1;
      rates.subrange[0].bMin = static_cast<std::int32_t>(kh::kSampleRate);
      rates.subrange[0].bMax = static_cast<std::int32_t>(kh::kSampleRate);
      rates.subrange[0].bRes = 0;
      return send(&rates, sizeof(rates));
    }
    if (control == AUDIO20_CS_CTRL_CLK_VALID && current) {
      audio20_control_cur_1_t valid{};
      valid.bCur = 1;
      return send(&valid, sizeof(valid));
    }
  }
  return false;  // stall: not a control this microphone has
}

extern "C" bool tud_audio_set_req_entity_cb(std::uint8_t, tusb_control_request_t const* request,
                                            std::uint8_t* buffer) {
  const std::uint8_t channel = TU_U16_LOW(request->wValue);
  const std::uint8_t control = TU_U16_HIGH(request->wValue);
  const std::uint8_t entity = TU_U16_HIGH(request->wIndex);
  if (request->bRequest != AUDIO20_CS_REQ_CUR || entity != kh::kFeatureUnit || channel > 1) return false;
  if (control == AUDIO20_FU_CTRL_MUTE && request->wLength == sizeof(audio20_control_cur_1_t)) {
    kh::g_host_mute[channel].store(buffer[0] != 0);
    return true;
  }
  if (control == AUDIO20_FU_CTRL_VOLUME && request->wLength == sizeof(audio20_control_cur_2_t)) {
    std::int16_t volume = 0;
    std::memcpy(&volume, buffer, sizeof(volume));
    kh::g_host_volume[channel].store(std::clamp(volume, kh::kVolumeMin, kh::kVolumeMax));
    kh::UpdateGain();
    return true;
  }
  return false;
}
