/**
 * Copyright (c) 2016 Bitprim developers (see AUTHORS)
 *
 * This file is part of Bitprim.
 *
 * Bitprim is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef LIBBITCOIN_DATABASE_CONFIGURATION_HPP
#define LIBBITCOIN_DATABASE_CONFIGURATION_HPP

#include <boost/filesystem.hpp>

#include <bitcoin/database/define.hpp>
#include <bitcoin/database/settings_replier.hpp>
#include <bitcoin/network.hpp>


namespace libbitcoin { namespace database {

// Not localizable.
#define BB_HELP_VARIABLE "help"
#define BB_SETTINGS_VARIABLE "settings"
#define BB_VERSION_VARIABLE "version"

// This must be lower case but the env var part can be any case.
#define BB_CONFIG_VARIABLE "config"

// This must match the case of the env var.
#define BB_ENVIRONMENT_VARIABLE_PREFIX "BD_"

/// Full node configuration, thread safe.
class BCD_API configuration {
public:
    configuration(config::settings context);
    configuration(configuration const& other);

    /// Options.
    bool help;
    bool initchain;
    bool settings;
    bool version;

    /// Options and environment vars.
    boost::filesystem::path file;

    /// Settings.
    database::settings_replier database;
    network::settings network;
};

}} // namespace libbitcoin::database

#endif /*LIBBITCOIN_DATABASE_CONFIGURATION_HPP*/