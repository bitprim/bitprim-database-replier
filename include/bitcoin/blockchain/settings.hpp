/**
 * Copyright (c) 2011-2015 libbitcoin developers (see AUTHORS)
 *
 * This file is part of libbitcoin-blockchain.
 *
 * libbitcoin-blockchain is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef LIBBITCOIN_BLOCKCHAIN_SETTINGS_HPP
#define LIBBITCOIN_BLOCKCHAIN_SETTINGS_HPP

#include <cstdint>
#include <boost/filesystem.hpp>
#include <bitcoin/bitcoin.hpp>
#include <bitcoin/blockchain/define.hpp>

namespace libbitcoin {
namespace blockchain {

/// Common blockchain configuration settings, thread safe.
struct BCB_API settings
{
    /// Default instances.
    static const settings mainnet;
    static const settings testnet;

    /// Properties.
    uint32_t threads;
    uint32_t history_start_height;
    uint32_t stealth_start_height;
    uint32_t block_pool_capacity;
    uint32_t transaction_pool_capacity;
    bool transaction_pool_consistency;
    bool use_testnet_rules;
    boost::filesystem::path database_path;
    config::checkpoint::list checkpoints;
};

} // namespace chain
} // namespace libbitcoin

#endif