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

#include <bitcoin/database/configuration.hpp>
// #include "configuration.hpp"

#include <cstddef>

namespace libbitcoin { namespace database {

// Construct with defaults derived from given context.
configuration::configuration(config::settings context)
  : help(false),
    initchain(false),
    settings(false),
    version(false),
    database(context),
    network(context)
{}

// Copy constructor.
configuration::configuration(configuration const& other)
  : help(other.help),
    initchain(other.initchain),
    settings(other.settings),
    version(other.version),
    file(other.file),
    database(other.database),
    network(other.network)
{}

}} // namespace libbitcoin::database
