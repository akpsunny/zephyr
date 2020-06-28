/*
 * Copyright (c) 2020 Siddharth Chandrasekaran <siddharth@embedjournal.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _OSDP_H_
#define _OSDP_H_

#include <zephyr.h>
#include <stddef.h>
#include <stdint.h>

#define OSDP_PD_ERR_RETRY_SEC			(300 * 1000)
#define OSDP_PD_POLL_TIMEOUT_MS			(50)
#define OSDP_RESP_TOUT_MS			(400)
#define OSDP_CP_RETRY_WAIT_MS			(500)

#define OSDP_PD_CMD_QUEUE_SIZE			(128)
#define OSDP_PD_CAP_SENTINEL			{ -1, 0, 0 } /* struct pd_cap[] end */

enum osdp_card_formats_e {
	OSDP_CARD_FMT_RAW_UNSPECIFIED,
	OSDP_CARD_FMT_RAW_WIEGAND,
	OSDP_CARD_FMT_ASCII,
	OSDP_CARD_FMT_SENTINEL
};

/* struct pd_cap::function_code */
enum osdp_pd_cap_function_code_e {
	CAP_UNUSED,
	CAP_CONTACT_STATUS_MONITORING,
	CAP_OUTPUT_CONTROL,
	CAP_CARD_DATA_FORMAT,
	CAP_READER_LED_CONTROL,
	CAP_READER_AUDIBLE_OUTPUT,
	CAP_READER_TEXT_OUTPUT,
	CAP_TIME_KEEPING,
	CAP_CHECK_CHARACTER_SUPPORT,
	CAP_COMMUNICATION_SECURITY,
	CAP_RECEIVE_BUFFERSIZE,
	CAP_LARGEST_COMBINED_MESSAGE_SIZE,
	CAP_SMART_CARD_SUPPORT,
	CAP_READERS,
	CAP_BIOMETRICS,
	CAP_SENTINEL
};

/* CMD_OUT */
struct osdp_cmd_output {
	uint8_t output_no;
	uint8_t control_code;
	uint16_t tmr_count;
};

/* CMD_LED */
enum osdp_led_color_e {
	OSDP_LED_COLOR_NONE,
	OSDP_LED_COLOR_RED,
	OSDP_LED_COLOR_GREEN,
	OSDP_LED_COLOR_AMBER,
	OSDP_LED_COLOR_BLUE,
	OSDP_LED_COLOR_SENTINEL
};

struct __osdp_cmd_led_params {
	uint8_t control_code;
	uint8_t on_count;
	uint8_t off_count;
	uint8_t on_color;	/* enum osdp_led_color_e */
	uint8_t off_color;	/* enum osdp_led_color_e */
	uint16_t timer;
};

struct osdp_cmd_led {
	uint8_t reader;
	uint8_t led_number;
	struct __osdp_cmd_led_params temporary;
	struct __osdp_cmd_led_params permanent;
};

/* CMD_BUZ */
struct osdp_cmd_buzzer {
	uint8_t reader;
	uint8_t tone_code;
	uint8_t on_count;
	uint8_t off_count;
	uint8_t rep_count;
};

/* CMD_TEXT */
struct osdp_cmd_text {
	uint8_t reader;
	uint8_t cmd;
	uint8_t temp_time;
	uint8_t offset_row;
	uint8_t offset_col;
	uint8_t length;
	uint8_t data[32];
};

/* CMD_COMSET */
struct osdp_cmd_comset {
	uint8_t addr;
	uint32_t baud;
};

/* CMD_KEYSET */
struct osdp_cmd_keyset {
	uint8_t key_type;
	uint8_t len;
	uint8_t data[32];
};

/* generic OSDP command structure */
enum osdp_cmd_e {
	OSDP_CMD_OUTPUT = 1,
	OSDP_CMD_LED,
	OSDP_CMD_BUZZER,
	OSDP_CMD_TEXT,
	OSDP_CMD_KEYSET,
	OSDP_CMD_COMSET,
	OSDP_CMD_SENTINEL
};

struct osdp_cmd {
	void *__next;
	int id;
	union {
		uint8_t cmd_bytes[32];
		struct osdp_cmd_led    led;
		struct osdp_cmd_buzzer buzzer;
		struct osdp_cmd_text   text;
		struct osdp_cmd_output output;
		struct osdp_cmd_comset comset;
		struct osdp_cmd_keyset keyset;
	};
};

struct pd_cap {
	uint8_t function_code;	/* enum osdp_pd_cap_function_code_e */
	uint8_t compliance_level;
	uint8_t num_items;
};

struct pd_id {
	int version;
	int model;
	uint32_t vendor_code;
	uint32_t serial_number;
	uint32_t firmware_version;
};

struct osdp_channel {
	/**
	 * pointer to a block of memory that will be passed to the send/receive
	 * method. This is optional and can be left empty.
	 */
        void *data;

	/**
	 * recv: function pointer; Copies received bytes into buffer
	 * @data - for use by underlying layers. channel_s::data is passed
	 * @buf  - byte array copy incoming data
	 * @len  - sizeof `buf`. Can copy utmost `len` number of bytes into `buf`
	 *
	 * Returns:
	 *  +ve: number of bytes copied on to `bug`. Must be <= `len`
	 */
	int (*recv)(void *data, uint8_t *buf, int maxlen);

	/**
	 * send: function pointer; Sends byte array into some channel
	 * @data - for use by underlying layers. channel_s::data is passed
	 * @buf  - byte array to be sent
	 * @len  - number of bytes in `buf`
	 *
	 * Returns:
	 *  +ve: number of bytes sent. must be <= `len` (TODO: handle partials)
	 */
	int (*send)(void *data, uint8_t *buf, int len);

	/**
	 * flush: function pointer; drop all bytes in queue to be read
	 * @data - for use by underlying layers. channel_s::data is passed
	 */
	void (*flush)(void *data);
};

typedef struct {
	/**
	 * Can be one of 9600/38400/115200.
	 */
	int baud_rate;

	/**
	 * 7 bit PD address. the rest of the bits are ignored. The special address
	 * 0x7F is used for broadcast. So there can be 2^7-1 devices on a multi-
	 * drop channel.
	 */
	int address;

	/**
	 * Used to modify the way the context is setup.
	 */
	int flags;

	/**
	 * Static info that the PD reports to the CP when it received a `CMD_ID`.
	 * This is used only in PD mode of operation.
	 */
	struct pd_id id;

	/**
	 * This is a pointer to an array of structures containing the PD's
	 * capabilities. Use macro `OSDP_PD_CAP_SENTINEL` to terminate the array.
	 * This is used only PD mode of operation.
	 */
	struct pd_cap *cap;

	/**
	 * Communication channel ops structure, containing send/recv function
	 * pointers.
	 */
	struct osdp_channel channel;
} osdp_pd_info_t;

void osdp_pd_refresh();
int osdp_pd_get_cmd(struct osdp_cmd *cmd);

#endif	/* _OSDP_H_ */
