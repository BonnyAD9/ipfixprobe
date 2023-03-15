/**
 * \file flexprobe-encryption-processing.h
 * \brief Traffic feature processing for encryption analysis for Flexprobe -- HW accelerated network
 * probe \author Roman Vrana <ivrana@fit.vutbr.cz> \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#ifndef IPFIXPROBE_FLEXPROBE_ENCRYPTION_PROCESSING_H
#define IPFIXPROBE_FLEXPROBE_ENCRYPTION_PROCESSING_H

#include <cmath>
#include <limits>

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/process.hpp>

#include "flexprobe-data.h"

namespace ipxp {

template<typename T>
class RtStats {
protected:
	// helper variables for variance calculation
	//    T prev_average_;
	T delta_sq_sum_;

	T mean_;
	T variance_;
	T deviation_;

	T minimum_;
	T maximum_;

public:
	T mean() const { return mean_; }

	T variance() const { return variance_; }

	T deviation() const { return deviation_; }

	T minimum() const { return minimum_; }

	T maximum() const { return maximum_; }

protected:
	// running average
	T running_average_(T next_value, std::uint64_t packets)
	{
		//        prev_average_ = mean_;
		auto p_delta = next_value - mean_;
		mean_ = packets
			? (next_value + static_cast<T>((packets - 1)) * mean_) / static_cast<T>(packets)
			: T();
		auto delta = next_value - mean_;
		delta_sq_sum_ += p_delta * delta;
		return mean_;
	}

	// running variance calculated using Welford's algorithm
	T running_variance_(std::uint64_t packets)
	{
		return (variance_ = packets ? delta_sq_sum_ / static_cast<T>(packets) : T()), variance_;
	}

	// running deviation
	T comp_deviation_() { return deviation_ = std::sqrt(variance_), deviation_; }

	T comp_minimum_(T next_val) { return minimum_ = std::min(minimum_, next_val), minimum_; }

	T comp_maximum_(T next_val) { return maximum_ = std::max(maximum_, next_val), maximum_; }

public:
	explicit RtStats(
		T init_min = std::numeric_limits<T>::max(),
		T init_max = std::numeric_limits<T>::min())
		: delta_sq_sum_(0)
		, mean_(0)
		, variance_(0)
		, deviation_(0)
		, minimum_(init_min)
		, maximum_(init_max)
	{
	}

	void update(T next_val, const size_t count)
	{
		running_average_(next_val, count);
		running_variance_(count);
		comp_deviation_();
		comp_minimum_(next_val);
		comp_maximum_(next_val);
	}
};

struct FlexprobeEncryptionData : public RecordExt {
	static int REGISTERED_ID;

	std::uint64_t mpe8_valid_count;
	std::uint64_t mpe4_valid_count;
	RtStats<float> time_interpacket;
	RtStats<std::uint16_t> payload_size;
	RtStats<float> mpe_8bit;
	RtStats<float> mpe_4bit;

	FlexprobeEncryptionData()
		: RecordExt(REGISTERED_ID)
		, mpe8_valid_count()
		, mpe4_valid_count()
	{
	}

	virtual int fill_ipfix(uint8_t* buffer, int size)
	{
		// TODO: fill fields in correct order
		return 0;
	}

	const char** get_ipfix_tmplt() const
	{
		static const char* ipfix_template[]
			= {IPFIX_FLEXPROBE_ENCR_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};
		return ipfix_template;
	}
};

class FlexprobeEncryptionProcessing : public ProcessPlugin {
public:
	FlexprobeEncryptionProcessing() = default;

	void init(const char* params) {} // TODO
	void close() {} // TODO
	RecordExt* get_ext() const { return new FlexprobeEncryptionData(); }
	OptionsParser* get_parser() const
	{
		return new OptionsParser("flexprobe-encrypt", "Parse flexprobe data");
	}
	std::string get_name() const { return "flexprobe-encrypt"; }
	FlexprobeEncryptionProcessing* copy() override
	{
		return new FlexprobeEncryptionProcessing(*this);
	}

	int post_create(Flow& rec, const Packet& pkt) override;

	int post_update(Flow& rec, const Packet& pkt) override;
};

} // namespace ipxp
#endif // IPFIXPROBE_FLEXPROBE_ENCRYPTION_PROCESSING_H
